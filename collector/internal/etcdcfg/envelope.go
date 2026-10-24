// Package etcdcfg —— etcd 配置值信封解码与版本守卫（docs/09 §5 2026-10-25 裁定）。
//
// 四个配置键（shared.EtcdKeyZones / EtcdKeyForwardRules / EtcdKeyConfigAnalytics /
// EtcdKeyConfigCollector+{node}）的值统一为 JSON 信封：
//
//	{"version": <uint64 单调递增>, "updated_at": <RFC3339>, "data": <业务负载 JSON>}
//
// 写侧 = Master（master/internal/config，线格式权威）；本包为消费侧实现：
//   - Decode 严格解信封：裸 payload（缺信封字段）一律报错，业务负载解析只发生在
//     信封解包之后（调用方拿 Envelope.Data 再解析）；
//   - Guard 按 key 记录已应用版本，乱序回放（≤ 已应用版本）忽略；
//   - updated_at 仅记录（日志/打点），不参与应用判定。
//
// shared.EtcdKeyAssignFlow（分配表）与 /lucid/leader（选主）不适用信封，勿经本包。
package etcdcfg

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// 信封解码错误哨兵（调用方 errors.Is 判定）。
var (
	// ErrNotEnvelope —— 值不是 JSON 对象（裸数组 payload 等）。
	ErrNotEnvelope = errors.New("etcd config value is not an envelope json object")
	// ErrEnvelopeIncomplete —— 信封缺字段（version / updated_at / data）。
	ErrEnvelopeIncomplete = errors.New("etcd config envelope incomplete")
)

// Envelope —— 配置值信封（master/internal/config.Envelope 的消费侧镜像；
// 字段名即线格式：version / updated_at / data）。
type Envelope struct {
	// Version —— 单调递增版本（写侧 Master 保证 ≥1；应用判定唯一依据）。
	Version uint64
	// UpdatedAt —— 发布时刻（RFC3339；仅记录，不参与判定）。
	UpdatedAt time.Time
	// Data —— 业务负载原文（JSON；由调用方在信封解包后解析）。
	Data []byte
}

// envelopeFields —— 信封必需字段（只增不改：多余字段忽略，docs/09 §0）。
const (
	fieldVersion   = "version"
	fieldUpdatedAt = "updated_at"
	fieldData      = "data"
)

// Decode —— 严格解信封。
//
// 规则（与 Master 写侧约定对齐）：
//   - 值必须为 JSON 对象（裸 payload 数组直接 ErrNotEnvelope）；
//   - version / updated_at / data 三字段必须齐全，缺失报 ErrEnvelopeIncomplete；
//   - version 必须为 ≥1 的整数（Master 单调版本从 1 起；0 视为非法）；
//   - updated_at 必须为合法 RFC3339 时间（可为零时刻——仅记录）；
//   - data 键必须存在（值原文保留，null 由调用方负载解析器裁定）；
//   - 未知字段忽略（proto/JSON 演进只增不改，docs/09 §0）。
func Decode(data []byte) (Envelope, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return Envelope{}, fmt.Errorf("decode etcd config envelope (bare payload forbidden): %w", ErrNotEnvelope)
	}
	var env Envelope

	vRaw, ok := raw[fieldVersion]
	if !ok || len(vRaw) == 0 {
		return Envelope{}, fmt.Errorf("envelope field %q: %w", fieldVersion, ErrEnvelopeIncomplete)
	}
	if err := json.Unmarshal(vRaw, &env.Version); err != nil {
		return Envelope{}, fmt.Errorf("envelope field %q must be an integer: %w", fieldVersion, err)
	}
	if env.Version == 0 {
		return Envelope{}, fmt.Errorf("envelope field %q must be >= 1: %w", fieldVersion, ErrNotEnvelope)
	}

	uaRaw, ok := raw[fieldUpdatedAt]
	if !ok || len(uaRaw) == 0 {
		return Envelope{}, fmt.Errorf("envelope field %q: %w", fieldUpdatedAt, ErrEnvelopeIncomplete)
	}
	if err := json.Unmarshal(uaRaw, &env.UpdatedAt); err != nil {
		return Envelope{}, fmt.Errorf("envelope field %q must be RFC3339: %w", fieldUpdatedAt, err)
	}

	dRaw, ok := raw[fieldData]
	if !ok {
		return Envelope{}, fmt.Errorf("envelope field %q: %w", fieldData, ErrEnvelopeIncomplete)
	}
	env.Data = append([]byte(nil), dRaw...) // 脱离入参缓冲

	return env, nil
}
