package registry

import (
	"encoding/json"
	"fmt"
	"time"
)

// 节点模型与生命周期状态（docs/dd/07 §2 / hld/07 §4）。
//
// 生命周期：注册（自报角色/容量）→ 心跳保活（etcd lease，10s 间隔）→
//   失联 30s 标 degraded → 失联 90s 判 offline 并触发再平衡；
// 排水：online → draining（分配表摘除）→ 迁移完成 → maintenance（人工确认）。

// State —— 节点状态（PG nodes.state 契约值域：online|draining|maintenance|offline）。
type State string

const (
	StateOnline      State = "online"
	StateDraining    State = "draining"
	StateMaintenance State = "maintenance"
	StateOffline     State = "offline"
)

// ValidState 状态值域校验。
func ValidState(s State) bool {
	switch s {
	case StateOnline, StateDraining, StateMaintenance, StateOffline:
		return true
	}
	return false
}

// Role —— 组件角色（docs/dd/07 §2 注释）。
type Role string

const (
	RoleBroker    Role = "broker"
	RoleCollector Role = "collector"
	RoleAnalytics Role = "analytics"
	RoleStorage   Role = "storage"
	RoleMaster    Role = "master"
	RoleBGP       Role = "bgp"
)

// ValidRole 角色值域校验。
func ValidRole(r Role) bool {
	switch r {
	case RoleBroker, RoleCollector, RoleAnalytics, RoleStorage, RoleMaster, RoleBGP:
		return true
	}
	return false
}

// NIC —— 网卡档案（容量权重输入；NodeInfo gRPC 未携带，注册后经 admin API 补录）。
type NIC struct {
	Name      string `json:"name"`
	SpeedGbps uint32 `json:"speed_gbps"`
}

// Node —— 节点档案。
type Node struct {
	ID             string
	Role           Role
	Host           string
	Cores          uint32
	MemGB          uint32
	NICs           []NIC
	State          State
	Degraded       bool // 失联超 degradedAfter（30s）的运行时标记（hld/07 §4）
	Version        string
	WeightOverride float64 // >0 时覆盖自动权重
	JoinedAt       time.Time
	LastHB         time.Time
}

// Weight —— 容量权重（docs/dd/07 §2）：weight = cores/24 × nic_speed/25G。
// 权重下限 0.05（保证哈希环至少 1 个 vnode）；WeightOverride > 0 时优先。
func (n Node) Weight() float64 {
	if n.WeightOverride > 0 {
		return n.WeightOverride
	}
	nicFactor := 1.0 // 未登记网卡按 25G 基准（NodeInfo 契约无 nic 字段，见模块 TODO）
	var speed uint32
	for _, nic := range n.NICs {
		if nic.SpeedGbps > speed {
			speed = nic.SpeedGbps
		}
	}
	if speed > 0 {
		nicFactor = float64(speed) / 25.0
	}
	cores := float64(n.Cores)
	if cores <= 0 {
		cores = 1
	}
	w := cores / 24.0 * nicFactor
	if w < 0.05 {
		w = 0.05
	}
	return w
}

// NodeEvent —— 生命周期事件（供审计/告警/再平衡触发）。
type NodeEvent struct {
	Type EventType
	Node Node
	At   time.Time
}

// EventType —— 事件类型。
type EventType string

const (
	EventRegistered EventType = "registered"
	EventOnline     EventType = "online"
	EventDegraded   EventType = "degraded"
	EventOffline    EventType = "offline"
	EventDrain      EventType = "drain"
	EventStateSet   EventType = "state_set"
)

// Exporter —— exporter 台账（分配算法输入，docs/dd/07 §3）。
type Exporter struct {
	IP        string
	DeviceID  uint32
	LastSeen  time.Time
	RateFPS   float64 // 最近观测速率（心跳 metrics_json 上报）
	PinnedTo  string  // 手工 pin 的 collector 节点 ID（空=自动分配）
	ActiveSet bool    // 管理侧启停标记（false 时即使心跳活跃也不参与分配）
}

// ---------- 心跳 metrics_json 载荷（NodeStat.metrics_json 契约） ----------
//
// {
//   "version": "v1.0.0",
//   "exporters": [{"ip":"10.0.0.1","fps":12345.6}],
//   "ack": {"cmd_id":"...","scope":"/lucid/zones","version":7}
// }

// NodeMetrics —— NodeStat.metrics_json 解析结果。
type NodeMetrics struct {
	Version   string
	Exporters []ExporterObs
	Ack       *CmdAck
}

// ExporterObs —— 节点观测到的活跃 exporter 及速率。
type ExporterObs struct {
	IP  string  `json:"ip"`
	FPS float64 `json:"fps"`
}

// CmdAck —— 命令/配置回执（配置下发的节点 ACK 走心跳通道，docs/dd/07 §5）。
type CmdAck struct {
	CmdID   string `json:"cmd_id"`
	Scope   string `json:"scope"`
	Version uint64 `json:"version"`
	OK      bool   `json:"ok"`
	ErrMsg  string `json:"err_msg,omitempty"`
}

// ParseMetricsJSON 解析心跳摘要载荷（gRPC Heartbeat 与 Kafka cluster.heartbeat 共用）。
func ParseMetricsJSON(b []byte) (NodeMetrics, error) {
	if len(b) == 0 {
		return NodeMetrics{}, nil
	}
	var raw struct {
		Version   string        `json:"version"`
		Exporters []ExporterObs `json:"exporters"`
		Ack       *CmdAck       `json:"ack"`
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		return NodeMetrics{}, fmt.Errorf("parse node metrics json: %w", err)
	}
	return NodeMetrics{Version: raw.Version, Exporters: raw.Exporters, Ack: raw.Ack}, nil
}
