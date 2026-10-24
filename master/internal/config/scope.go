package config

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// etcd 配置键空间（docs/09 §5 唯一权威；Master 写，各模块只读 watch）。
// 值结构 = JSON + 单调 version（Envelope）。
const (
	ScopeZones        = "/lucid/zones"             // Zone 配置快照（Collector zone 树 / Analytics）
	ScopeForwardRules = "/lucid/forward/rules"     // R1 转发规则快照（Broker）
	ScopeAnalytics    = "/lucid/config/analytics"  // 检测开关/阈值覆盖/internal_exclude
	ScopeAssignFlow   = "/lucid/assign/flow"       // 分配表（assigner 内部写，不在此管理）
	collectorPrefix   = "/lucid/config/collector/" // + {node}
)

// Envelope —— etcd 配置值信封：单调 version + 快照数据（docs/09 §5）。
type Envelope struct {
	Version   uint64          `json:"version"`
	UpdatedAt time.Time       `json:"updated_at"`
	Data      json.RawMessage `json:"data"`
}

// CollectorScope 生成 collector 节点配置键。
func CollectorScope(nodeID string) string { return collectorPrefix + nodeID }

// IsCollectorScope 判断是否 collector 节点配置键，返回节点 ID。
func IsCollectorScope(scope string) (string, bool) {
	if strings.HasPrefix(scope, collectorPrefix) {
		return strings.TrimPrefix(scope, collectorPrefix), true
	}
	return "", false
}

// ValidScope 发布作用域校验（/lucid/assign/flow 由分配器内部维护，拒绝外部发布）。
func ValidScope(scope string) bool {
	switch scope {
	case ScopeZones, ScopeForwardRules, ScopeAnalytics:
		return true
	}
	if _, ok := IsCollectorScope(scope); ok {
		return scope != CollectorScope("") // 空节点 ID 无效
	}
	return false
}

// ScopeTargets —— 作用域影响的组件角色（reload 命令下发与 ACK 统计口径）。
// broker/collector 经 etcd watch 拿数据（docs/09 §9-⑤），ACK 仅确认"已应用"。
func ScopeTargets(scope string) []string {
	if node, ok := IsCollectorScope(scope); ok {
		return []string{node}
	}
	switch scope {
	case ScopeZones:
		return []string{"collector"}
	case ScopeForwardRules:
		return []string{"broker"}
	case ScopeAnalytics:
		return []string{"analytics"}
	}
	return nil
}

// ZoneSpec —— /lucid/zones 快照条目（JSON 镜像 proto ZoneSpec，docs/00 §2.2；
// 与 collector internal/zone 的 ParseSpecsJSON 消费形状对齐）。
type ZoneSpec struct {
	ID          int32          `json:"id"`
	Name        string         `json:"name"`
	Tenant      string         `json:"tenant"`
	IPs         []ZoneIPEntry  `json:"ips"`
	BoundaryIFs []ZoneDeviceIf `json:"boundary_ifs,omitempty"`
	PolicyID    int32          `json:"policy_id"`
	ZoneMatch   string         `json:"zone_match,omitempty"` // dst|src（默认 dst；契约缺口见模块 TODO）
}

// ZoneIPEntry —— CIDR 条目；单 IP 用 /32（v4）或 /128（v6）。
type ZoneIPEntry struct {
	Prefix string `json:"prefix"`
}

// ZoneDeviceIf —— 边界接口绑定（设备ID + ifIndex）。
type ZoneDeviceIf struct {
	DeviceID uint32 `json:"device_id"`
	IfIndex  uint32 `json:"if_index"`
}

// ForwardRule —— /lucid/forward/rules 快照条目（docs/dd/01 §3.1）。
type ForwardRule struct {
	ID           int64         `json:"id"`
	Name         string        `json:"name"`
	Priority     int           `json:"priority"`
	Enabled      bool          `json:"enabled"`
	Match        ForwardMatch  `json:"match"`
	Destinations []ForwardDest `json:"destinations"`
}

// ForwardMatch —— 匹配条件（AND；exporters 与 exporter_groups 取并集）。
type ForwardMatch struct {
	Exporters      []string `json:"exporters,omitempty"`
	ExporterGroups []string `json:"exporter_groups,omitempty"`
}

// ForwardDest —— 目的地（passthrough 不支持 resample，docs/dd/01 §3.2-3 / R1 裁定）。
type ForwardDest struct {
	Addr       string          `json:"addr"`
	Protocol   string          `json:"protocol"` // passthrough|netflow5|ipfix
	Resample   *Resample       `json:"resample,omitempty"`
	FlowFilter json.RawMessage `json:"flow_filter,omitempty"` // 代理模式可选内容过滤（dd/01 §3.2-4）
}

// Resample —— 再采样（deterministic|random）。
type Resample struct {
	Mode string `json:"mode"`
	Rate uint32 `json:"rate"`
}

// SnapshotJSON —— 解析快照为通用 JSON 数组（校验入口共用）。
func parseSnapshot(data []byte) ([]json.RawMessage, error) {
	var arr []json.RawMessage
	if err := json.Unmarshal(data, &arr); err != nil {
		return nil, fmt.Errorf("snapshot must be a json array: %w", err)
	}
	return arr, nil
}

func jsonUnmarshal(data []byte, v any) error {
	if err := json.Unmarshal(data, v); err != nil {
		return err
	}
	return nil
}
