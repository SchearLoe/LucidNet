package forwarder

import (
	"sort"
	"sync/atomic"
)

// RuleSet —— 不可变规则集快照（版本化热更新：整表原子替换，dd/01 §1/§3.2 #5）。
type RuleSet struct {
	Version uint64
	rules   []compiledRule
	// byExporter —— 展开缓存 map[exporter]→[ruleIDs]（dd/01 §3.3），命中 O(1)。
	byExporter map[string][]*compiledRule
}

// compiledRule —— 校验/展开后的运行时规则。
type compiledRule struct {
	src    Rule
	dests  []*Destination
	filter *Filter
}

// Empty —— 空表判断（未配置规则时零额外开销，dd/01 §1）。
func (s *RuleSet) Empty() bool { return s == nil || len(s.byExporter) == 0 }

// RuleCount —— 当前规则数（自监控）。
func (s *RuleSet) RuleCount() int {
	if s == nil {
		return 0
	}
	return len(s.rules)
}

// RulesFor —— 源 IP（exporter）命中的规则（按 priority 升序，命中即复制）。
func (s *RuleSet) RulesFor(exporter string) []*compiledRule {
	if s.Empty() {
		return nil
	}
	return s.byExporter[exporter]
}

// Destinations 返回规则的运行时目的地列表（透传/代理混排，priority 无关）。
func (r *compiledRule) Rule() *Rule { return &r.src }

// SnapshotPtr —— 原子规则集指针（atomic.Pointer 包装，切换 O(1)）。
type SnapshotPtr struct {
	p atomic.Pointer[RuleSet]
}

// Load 读取当前快照（恒非 nil：空表用共享零值）。
func (sp *SnapshotPtr) Load() *RuleSet {
	if s := sp.p.Load(); s != nil {
		return s
	}
	return emptyRuleSet
}

// Store 原子替换（调用方保证 version 单调，见 admin watch 单调闸）。
func (sp *SnapshotPtr) Store(s *RuleSet) { sp.p.Store(s) }

var emptyRuleSet = &RuleSet{byExporter: map[string][]*compiledRule{}}

// Compile —— 快照 → RuleSet（展开分组、构建索引；非法规则由 Validate 前置剔除）。
// destinations 的运行时对象（socket/会话）由 Engine 复用或重建（ReuseOrRebuild）。
func Compile(snap *RulesSnapshot) (*RuleSet, []error) {
	valid, verrs := snap.Validate()
	sort.SliceStable(valid, func(i, j int) bool { // 匹配顺序：priority 升序（dd/01 §3.2 #1）
		return valid[i].Priority < valid[j].Priority
	})
	rs := &RuleSet{
		Version:    snap.Version,
		byExporter: make(map[string][]*compiledRule, len(valid)),
	}
	if len(valid) > 0 {
		rs.rules = make([]compiledRule, len(valid))
	}
	for i := range valid {
		r := valid[i]
		cr := &rs.rules[i]
		cr.src = r
		cr.dests = make([]*Destination, len(r.Destinations))
		for j := range r.Destinations {
			cr.dests[j] = &cr.src.Destinations[j]
		}
		if r.FlowFilter != nil {
			cr.filter = CompileFilter(r.FlowFilter)
		}
		// 展开缓存：exporters ∪ groups → ruleIDs（dd/01 §3.3）
		seen := make(map[string]struct{})
		add := func(exp string) {
			if exp == "" {
				return
			}
			if _, dup := seen[exp]; dup {
				return
			}
			seen[exp] = struct{}{}
			rs.byExporter[exp] = append(rs.byExporter[exp], cr)
		}
		for _, e := range r.Match.Exporters {
			add(e)
		}
		for _, g := range r.Match.ExporterGroups {
			for _, e := range snap.ExporterGroups[g] {
				add(e)
			}
		}
	}
	return rs, verrs
}
