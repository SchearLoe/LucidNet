package registry

import (
	"context"
	"errors"
	"sort"
	"sync"
	"time"
)

// ErrNotFound —— 节点/exporter 不存在。
var ErrNotFound = errors.New("registry: not found")

// Store —— 节点/exporter 台账存储抽象（内存桩 + PG 权威）。
//
// 并发约定：实现需保证并发安全；Registry 的故障扫描与心跳写入均经此层。
type Store interface {
	UpsertNode(ctx context.Context, n Node) (created bool, err error)
	GetNode(ctx context.Context, id string) (Node, error)
	ListNodes(ctx context.Context) ([]Node, error)
	SetNodeState(ctx context.Context, id string, st State) error
	SetNodeHB(ctx context.Context, id string, ts time.Time, degraded bool, version string) error
	SetNodeWeightOverride(ctx context.Context, id string, w float64) error
	UpsertExporter(ctx context.Context, e Exporter) error
	GetExporter(ctx context.Context, ip string) (Exporter, error)
	ListExporters(ctx context.Context) ([]Exporter, error)
	MarkExporterSeen(ctx context.Context, ip string, ts time.Time, fps float64) error
	SetExporterPin(ctx context.Context, ip, collectorNodeID string) error
	Close() error
}

// ---------- 内存实现 ----------

// MemStore —— 内存台账（开发模式 / 单测桩）。
type MemStore struct {
	mu        sync.Mutex
	nodes     map[string]Node
	exporters map[string]Exporter
}

// NewMemStore 构造内存台账。
func NewMemStore() *MemStore {
	return &MemStore{nodes: map[string]Node{}, exporters: map[string]Exporter{}}
}

// UpsertNode 写入节点档案。
func (m *MemStore) UpsertNode(_ context.Context, n Node) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, created := m.nodes[n.ID]
	m.nodes[n.ID] = n
	return !created, nil
}

// GetNode 读取节点。
func (m *MemStore) GetNode(_ context.Context, id string) (Node, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n, ok := m.nodes[id]
	if !ok {
		return Node{}, ErrNotFound
	}
	return n, nil
}

// ListNodes 列出节点（按 ID 排序）。
func (m *MemStore) ListNodes(_ context.Context) ([]Node, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Node, 0, len(m.nodes))
	for _, n := range m.nodes {
		out = append(out, n)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// SetNodeState 状态迁移。
func (m *MemStore) SetNodeState(_ context.Context, id string, st State) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	n, ok := m.nodes[id]
	if !ok {
		return ErrNotFound
	}
	n.State = st
	m.nodes[id] = n
	return nil
}

// SetNodeHB 心跳落账。
func (m *MemStore) SetNodeHB(_ context.Context, id string, ts time.Time, degraded bool, version string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	n, ok := m.nodes[id]
	if !ok {
		return ErrNotFound
	}
	n.LastHB = ts
	n.Degraded = degraded
	if version != "" {
		n.Version = version
	}
	m.nodes[id] = n
	return nil
}

// SetNodeWeightOverride 设置权重覆盖。
func (m *MemStore) SetNodeWeightOverride(_ context.Context, id string, w float64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	n, ok := m.nodes[id]
	if !ok {
		return ErrNotFound
	}
	n.WeightOverride = w
	m.nodes[id] = n
	return nil
}

// UpsertExporter 写入 exporter 档案。
func (m *MemStore) UpsertExporter(_ context.Context, e Exporter) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.exporters[e.IP] = e
	return nil
}

// GetExporter 读取 exporter。
func (m *MemStore) GetExporter(_ context.Context, ip string) (Exporter, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.exporters[ip]
	if !ok {
		return Exporter{}, ErrNotFound
	}
	return e, nil
}

// ListExporters 列出全部 exporter。
func (m *MemStore) ListExporters(_ context.Context) ([]Exporter, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Exporter, 0, len(m.exporters))
	for _, e := range m.exporters {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].IP < out[j].IP })
	return out, nil
}

// MarkExporterSeen 观测更新（保留 pin 与 ActiveSet；新记录默认参与分配）。
func (m *MemStore) MarkExporterSeen(_ context.Context, ip string, ts time.Time, fps float64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.exporters[ip]
	if !ok {
		e = Exporter{IP: ip, ActiveSet: true}
	}
	e.LastSeen = ts
	e.RateFPS = fps
	m.exporters[ip] = e
	return nil
}

// SetExporterPin 设置/清除 pin。
func (m *MemStore) SetExporterPin(_ context.Context, ip, collectorNodeID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.exporters[ip]
	if !ok {
		return ErrNotFound
	}
	e.PinnedTo = collectorNodeID
	m.exporters[ip] = e
	return nil
}

// Close 关闭（内存实现为空）。
func (m *MemStore) Close() error { return nil }

// CompileAssert 内存实现满足接口。
var _ Store = (*MemStore)(nil)
