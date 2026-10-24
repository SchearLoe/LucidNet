// Package codec —— gateway.ws 消费侧负载解码（线格式 = proto+lz4，docs/09 §2）。
// 与 storage/internal/inserter 同口径：gen/go 代码生成未落地前返回
// ErrCodecUnavailable；JSONCodec 为本地联调/E2E 通道（JSON 信封，非线格式契约）。
package codec

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/SchearLoe/lucidnet/shared"
)

// ErrCodecUnavailable —— proto+lz4 解码桩占位错误（gen/ 代码生成就绪后替换）。
var ErrCodecUnavailable = errors.New("proto codec unavailable: gen/lucidnet/v1 codegen not landed yet (docs/09 §0)")

// Codec —— 主题负载解码接口（gateway.ws 消费 alarms / bgp.mitigations）。
type Codec interface {
	// DecodeAlarmEnvelope 解码 alarms topic 信封（oneof: Alarm / AttackEvent）。
	DecodeAlarmEnvelope([]byte) (*shared.AlarmEnvelope, error)
	// DecodeMitigationEvent 解码 bgp.mitigations 事件（R9 回执）。
	DecodeMitigationEvent([]byte) (*shared.MitigationEvent, error)
}

// ProtoCodec —— proto+lz4 解码桩（docs/09 §10 联调桩建议，与 storage 口径一致）。
type ProtoCodec struct{}

// DecodeAlarmEnvelope 解码 alarms 信封（桩）。
func (ProtoCodec) DecodeAlarmEnvelope([]byte) (*shared.AlarmEnvelope, error) {
	return nil, ErrCodecUnavailable
}

// DecodeMitigationEvent 解码 bgp.mitigations 事件（桩）。
func (ProtoCodec) DecodeMitigationEvent([]byte) (*shared.MitigationEvent, error) {
	return nil, ErrCodecUnavailable
}

// JSONCodec —— JSON 直通解码（本地联调/单测/E2E 用；字段名 = proto JSON snake_case，
// docs/11 §8。生产线格式仍为 proto+lz4，此类型不构成契约变更）。
type JSONCodec struct{}

// DecodeAlarmEnvelope 解码 JSON 信封：{"alarm":{…}} 或 {"attack":{…}}（恰一非空）。
func (JSONCodec) DecodeAlarmEnvelope(b []byte) (*shared.AlarmEnvelope, error) {
	var wire struct {
		Alarm  *alarmJSON  `json:"alarm"`
		Attack *attackJSON `json:"attack"`
	}
	if err := json.Unmarshal(trim(b), &wire); err != nil {
		return nil, fmt.Errorf("decode alarm envelope json: %w", err)
	}
	env := &shared.AlarmEnvelope{}
	switch {
	case wire.Alarm != nil:
		env.Alarm = wire.Alarm.toShared()
	case wire.Attack != nil:
		env.Attack = wire.Attack.toShared()
	default:
		return nil, fmt.Errorf("decode alarm envelope json: empty payload (oneof alarm|attack)")
	}
	return env, nil
}

// DecodeMitigationEvent 解码 JSON 处置回执。
func (JSONCodec) DecodeMitigationEvent(b []byte) (*shared.MitigationEvent, error) {
	var wire mitigationJSON
	if err := json.Unmarshal(trim(b), &wire); err != nil {
		return nil, fmt.Errorf("decode mitigation event json: %w", err)
	}
	return wire.toShared(), nil
}

func trim(b []byte) []byte { return bytes.TrimSpace(b) }

// —— proto JSON snake_case 镜像（仅 JSONCodec 线上格式） ——

type alarmJSON struct {
	AlarmID    string `json:"alarm_id"`
	Source     string `json:"source"`
	Severity   uint32 `json:"severity"`
	Category   uint32 `json:"category"`
	RaiseMs    int64  `json:"raise_ms"`
	ClearMs    int64  `json:"clear_ms"`
	Subject    string `json:"subject"`
	DetailJSON string `json:"detail_json"`
	ZoneID     int32  `json:"zone_id"`
	AttackID   string `json:"attack_id"`
}

func (a *alarmJSON) toShared() *shared.Alarm {
	return &shared.Alarm{
		AlarmID:    a.AlarmID,
		Source:     a.Source,
		Severity:   shared.AlarmSeverity(a.Severity),
		Category:   shared.AlarmCategory(a.Category),
		RaiseMs:    a.RaiseMs,
		ClearMs:    a.ClearMs,
		Subject:    a.Subject,
		DetailJSON: a.DetailJSON,
		ZoneID:     a.ZoneID,
		AttackID:   a.AttackID,
	}
}

type attackJSON struct {
	AttackID     string   `json:"attack_id"`
	ZoneID       int32    `json:"zone_id"`
	ZoneName     string   `json:"zone_name"`
	AttackType   uint32   `json:"attack_type"`
	TargetPrefix string   `json:"target_prefix"`
	StartMs      int64    `json:"start_ms"`
	EndMs        int64    `json:"end_ms"`
	PeakBps      int64    `json:"peak_bps"`
	PeakPps      int64    `json:"peak_pps"`
	Confidence   float32  `json:"confidence"`
	TopSources   []string `json:"top_sources"`
	EvidenceJSON string   `json:"evidence_json"`
	Status       uint32   `json:"status"`
	MitigationID string   `json:"mitigation_id"`
}

func (a *attackJSON) toShared() *shared.AttackEvent {
	return &shared.AttackEvent{
		AttackID:     a.AttackID,
		ZoneID:       a.ZoneID,
		ZoneName:     a.ZoneName,
		AttackType:   shared.AttackType(a.AttackType),
		TargetPrefix: a.TargetPrefix,
		StartMs:      a.StartMs,
		EndMs:        a.EndMs,
		PeakBps:      a.PeakBps,
		PeakPps:      a.PeakPps,
		Confidence:   a.Confidence,
		TopSources:   a.TopSources,
		EvidenceJSON: a.EvidenceJSON,
		Status:       shared.AttackStatus(a.Status),
		MitigationID: a.MitigationID,
	}
}

type mitigationJSON struct {
	MitigationID string `json:"mitigation_id"`
	Action       string `json:"action"`
	Prefix       string `json:"prefix"`
	ExpireAtMs   int64  `json:"expire_at_ms"`
	Result       string `json:"result"`
	AttackID     string `json:"attack_id"`
	TsMs         int64  `json:"ts_ms"`
}

func (m *mitigationJSON) toShared() *shared.MitigationEvent {
	return &shared.MitigationEvent{
		MitigationID: m.MitigationID,
		Action:       m.Action,
		Prefix:       m.Prefix,
		ExpireAtMs:   m.ExpireAtMs,
		Result:       m.Result,
		AttackID:     m.AttackID,
		TsMs:         m.TsMs,
	}
}
