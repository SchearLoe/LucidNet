// Package flb —— 流量负载均衡（dd/01 §2）：exporter→collector 查表分发、
// 探活兜底与未知 exporter 哈希落点。Broker 只执行查表（分配权威是 Master，dd/01 §2.2）。
package flb

import (
	"sync/atomic"
)

// AssignSnapshot —— /lucid/assign/flow etcd 快照（docs/09 §5；结构 = JSON + 单调 version，
// 字段名与 proto/lucidnet/v1 AssignTable/AssignEntry 对齐）。
type AssignSnapshot struct {
	Version uint64        `json:"version"`
	Entries []AssignEntry `json:"entries"`
}

// AssignEntry —— exporter→collector 单条分配。
type AssignEntry struct {
	Exporter  string `json:"exporter"`
	Collector string `json:"collector"`
}

// Table —— 不可变分配表快照（本地全量缓存，切换原子替换，dd/01 §2.1）。
type Table struct {
	Version    uint64
	byExporter map[string]string
	collectors []string // 去重
}

// CompileAssign —— 快照 → 表。
func CompileAssign(snap *AssignSnapshot) *Table {
	t := &Table{Version: snap.Version, byExporter: make(map[string]string, len(snap.Entries))}
	seen := make(map[string]struct{})
	for _, e := range snap.Entries {
		if e.Exporter == "" || e.Collector == "" {
			continue
		}
		t.byExporter[e.Exporter] = e.Collector
		if _, dup := seen[e.Collector]; !dup {
			seen[e.Collector] = struct{}{}
			t.collectors = append(t.collectors, e.Collector)
		}
	}
	return t
}

// Assigned 查 exporter 固定分配。
func (t *Table) Assigned(exporter string) (string, bool) {
	c, ok := t.byExporter[exporter]
	return c, ok
}

// Collectors 去重 collector 列表。
func (t *Table) Collectors() []string { return t.collectors }

// Len 表内 exporter 数（自监控）。
func (t *Table) Len() int { return len(t.byExporter) }

// TablePtr —— 原子表指针。
type TablePtr struct{ p atomic.Pointer[Table] }

// Load 当前表（恒非 nil）。
func (tp *TablePtr) Load() *Table {
	if t := tp.p.Load(); t != nil {
		return t
	}
	return &Table{}
}

// Store 原子替换。
func (tp *TablePtr) Store(t *Table) { tp.p.Store(t) }
