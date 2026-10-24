package snmp

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/SchearLoe/lucidnet/collector/internal/enrich"
)

// RoleSource —— 判定依据（role_source 记录，dd/02 §5.2 优先级表；PG interfaces 列）。
type RoleSource string

const (
	RoleSourceManual   RoleSource = "manual"   // 优先级 1：PG 人工标记（运维在 Console 修正）
	RoleSourceLoopback RoleSource = "loopback" // 环回/管理口 → internal（不参与业务计量）
	RoleSourceLLDP     RoleSource = "lldp"     // 优先级 2：LLDP 邻居 sysName ∈ 纳管设备清单
	RoleSourceIGP      RoleSource = "igp"      // 优先级 3：OSPF/ISIS 邻接存在
	RoleSourceNaming   RoleSource = "naming"   // 优先级 4：ifDescr/ifAlias 命中命名规则
	RoleSourceDefault  RoleSource = "default"  // 优先级 5：默认 boundary + unknown 标记
)

// RoleEvidence —— 单接口识别输入（dd/02 §5.2 walk 周期 6h / 变更触发即时重算）。
//
// TODO(gosnmp-walk)：证据收集（本结构由 walk 结果填充）：
//   - ifTable/ifXTable：IfDescr/IfAlias/IfType/IfSpeed/IfOperStatus；
//   - IP-MIB ipAddrTable：接口 ↔ IP（HasIP，L3 判据之一）；
//   - LLDP-MIB：lldpRemSysName + lldpRemPortId（邻居发现）；
//   - OSPF-MIB ospfIfTable / ISIS-MIB（IGP 邻接，IGPAdjacency）。
type RoleEvidence struct {
	DeviceID uint32
	IfIndex  uint32

	IfDescr      string
	IfAlias      string
	IfType       int // IANA ifType；softwareLoopback = 24
	IfSpeed      uint64
	IfOperStatus int
	HasIP        bool // ipAddrTable 命中

	LLDPNeighborSysName string // 空 = 无 LLDP 邻居
	LLDPNeighborPortID  string
	IGPAdjacency        bool // OSPF/ISIS 邻接存在

	// ManualRole —— PG 人工标记（nil = 无标记；优先级 1）。
	ManualRole *enrich.IfRole
}

// ianaIfTypeSoftwareLoopback —— IANA ifType：softwareLoopback(24)（环回 → internal）。
const ianaIfTypeSoftwareLoopback = 24

// RoleDecision —— 识别输出 → PG interfaces(role, role_source, evidence_json)（dd/02 §5.2）。
type RoleDecision struct {
	DeviceID uint32
	IfIndex  uint32
	Role     enrich.IfRole
	Source   RoleSource
	// Evidence —— evidence_json 内容（命中依据 + 输入快照）。
	Evidence string
	// Unknown —— default 判定 → UI 黄色提示人工确认（dd/02 §5.2 优先级 5）。
	Unknown bool
}

// RoleEngine —— 接口角色识别引擎（首中即定，role_source 记录依据）。
type RoleEngine interface {
	Identify(ctx context.Context, ev RoleEvidence) (RoleDecision, error)
}

// NamingRule —— 命名正则表条目（PG 下发，dd/02 §5.2；命中 ifDescr/ifAlias）。
type NamingRule struct {
	Pattern string        // 正则（(?i) 大小写不敏感由规则自身携带）
	Role    enrich.IfRole // 命中判定角色
}

// DefaultNamingRules —— dd/02 §5.2 预置命名规则。
func DefaultNamingRules() []NamingRule {
	return []NamingRule{
		{Pattern: `(?i)(to-|Z_|ge.*core|-agg-|LAG)`, Role: enrich.IfRoleInternal},
		{Pattern: `(?i)(cust|client|eth-trunk.*c[0-9]+)`, Role: enrich.IfRoleBoundary},
	}
}

// RuleEngine —— 基于规则优先级表的识别实现（dd/02 §5.2）。
//
// 判定优先级（首中即定）：
//  1. PG 人工标记 manual；
//  2. 环回/管理口（ifType=softwareLoopback / ifDescr 含 Mgmt）→ internal
//     （dd/02 §5.2 将其列于优先级表之后，此处置于 manual 之后、LLDP 之前：
//     硬性端口属性应压过邻居/命名推断）；
//  3. LLDP 邻居 sysName ∈ 纳管设备清单 → internal；
//  4. OSPF/ISIS 邻接 → internal；
//  5. ifDescr/ifAlias 命中命名规则 → 对应角色；
//  6. 默认 → boundary + unknown 标记。
//
// TODO(role-pipeline)（dd/02 §5.2 收尾）：
//   - 识别结果批量写 PG interfaces(role, role_source, evidence_json)；
//   - 快照推送 Collector/Analytics（etcd /lucid/config/collector/* 与 Analytics 侧）；
//   - 对账校验（防 ifIndex 漂移）：每日 Top 流量 ifIndex 的 flow 聚合速率 vs
//     SNMP 同 ifIndex 速率，皮尔逊相关 <0.5 或接口名比对失败 → 告警
//     lucid_collector_ifindex_mismatch{device} → 人工映射表 manual_if_map。
type RuleEngine struct {
	managed     map[string]bool // 纳管设备清单（LLDP 判据）
	namingRules []NamingRule
	compiled    []*regexp.Regexp
}

// NewRuleEngine —— 构造（managedDevices 纳管设备名清单；rules 命名正则表，nil 取预置）。
func NewRuleEngine(managedDevices []string, rules []NamingRule) (*RuleEngine, error) {
	if rules == nil {
		rules = DefaultNamingRules()
	}
	e := &RuleEngine{
		managed:     make(map[string]bool, len(managedDevices)),
		namingRules: rules,
	}
	for _, m := range managedDevices {
		e.managed[m] = true
	}
	for i, r := range rules {
		re, err := regexp.Compile(r.Pattern)
		if err != nil {
			return nil, fmt.Errorf("compile naming rule %d %q: %w", i, r.Pattern, err)
		}
		e.compiled = append(e.compiled, re)
	}
	return e, nil
}

// evidenceJSON —— evidence_json 内容（dd/02 §5.2：命中依据 + 输入快照）。
type evidenceJSON struct {
	Source       RoleSource `json:"source"`
	IfDescr      string     `json:"if_descr,omitempty"`
	IfAlias      string     `json:"if_alias,omitempty"`
	IfType       int        `json:"if_type,omitempty"`
	LLDPNeighbor string     `json:"lldp_neighbor,omitempty"`
	IGPAdjacency bool       `json:"igp_adjacency,omitempty"`
	NamingRule   string     `json:"naming_rule,omitempty"`
	ManualRole   string     `json:"manual_role,omitempty"`
}

func (e *RuleEngine) decide(ev RoleEvidence) RoleDecision {
	dec := RoleDecision{DeviceID: ev.DeviceID, IfIndex: ev.IfIndex}

	// 1. manual（人工标记优先，运维修正入口）
	if ev.ManualRole != nil {
		dec.Role, dec.Source = *ev.ManualRole, RoleSourceManual
		dec.Evidence = e.marshalEvidence(evidenceJSON{
			Source: dec.Source, IfDescr: ev.IfDescr, IfAlias: ev.IfAlias,
			ManualRole: ev.ManualRole.String(),
		})
		return dec
	}
	// 2. 环回/管理口 → internal（不参与业务计量）
	if ev.IfType == ianaIfTypeSoftwareLoopback || strings.Contains(ev.IfDescr, "Mgmt") {
		dec.Role, dec.Source = enrich.IfRoleInternal, RoleSourceLoopback
		dec.Evidence = e.marshalEvidence(evidenceJSON{
			Source: dec.Source, IfDescr: ev.IfDescr, IfAlias: ev.IfAlias, IfType: ev.IfType,
		})
		return dec
	}
	// 3. LLDP 邻居 sysName ∈ 纳管设备清单 → internal
	if ev.LLDPNeighborSysName != "" && e.managed[ev.LLDPNeighborSysName] {
		dec.Role, dec.Source = enrich.IfRoleInternal, RoleSourceLLDP
		dec.Evidence = e.marshalEvidence(evidenceJSON{
			Source: dec.Source, IfDescr: ev.IfDescr, IfAlias: ev.IfAlias,
			LLDPNeighbor: ev.LLDPNeighborSysName,
		})
		return dec
	}
	// 4. OSPF/ISIS 邻接 → internal
	if ev.IGPAdjacency {
		dec.Role, dec.Source = enrich.IfRoleInternal, RoleSourceIGP
		dec.Evidence = e.marshalEvidence(evidenceJSON{
			Source: dec.Source, IfDescr: ev.IfDescr, IfAlias: ev.IfAlias, IGPAdjacency: true,
		})
		return dec
	}
	// 5. 命名规则（ifDescr/ifAlias，首中即定）
	for i, re := range e.compiled {
		if re.MatchString(ev.IfDescr) || re.MatchString(ev.IfAlias) {
			dec.Role, dec.Source = e.namingRules[i].Role, RoleSourceNaming
			dec.Evidence = e.marshalEvidence(evidenceJSON{
				Source: dec.Source, IfDescr: ev.IfDescr, IfAlias: ev.IfAlias,
				NamingRule: e.namingRules[i].Pattern,
			})
			return dec
		}
	}
	// 6. 默认 → boundary + unknown（UI 黄色提示人工确认）
	dec.Role, dec.Source, dec.Unknown = enrich.IfRoleBoundary, RoleSourceDefault, true
	dec.Evidence = e.marshalEvidence(evidenceJSON{
		Source: dec.Source, IfDescr: ev.IfDescr, IfAlias: ev.IfAlias, IfType: ev.IfType,
	})
	return dec
}

// Identify —— 接口 RoleEngine。
func (e *RuleEngine) Identify(ctx context.Context, ev RoleEvidence) (RoleDecision, error) {
	return e.decide(ev), nil
}

// marshalEvidence —— evidence_json 序列化（错误以空串兜底，不阻断识别）。
func (e *RuleEngine) marshalEvidence(ev evidenceJSON) string {
	b, err := json.Marshal(ev)
	if err != nil {
		return ""
	}
	return string(b)
}
