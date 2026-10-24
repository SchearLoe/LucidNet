package registry

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"
)

// NodeMirror —— /lucid/nodes/{id} etcd 镜像（节点档案 + 心跳 lease，docs/hld/07 §3）。
// etcd 不可用时由装配层注入 NopMirror。
type NodeMirror interface {
	Put(ctx context.Context, id string, profileJSON []byte) error
	Delete(ctx context.Context, id string) error
	KeepAlive(ctx context.Context, id string) error
}

// NopMirror —— 无 etcd 开发模式下的空实现。
type NopMirror struct{}

// Put 实现 NodeMirror。
func (NopMirror) Put(context.Context, string, []byte) error { return nil }

// Delete 实现 NodeMirror。
func (NopMirror) Delete(context.Context, string) error { return nil }

// KeepAlive 实现 NodeMirror。
func (NopMirror) KeepAlive(context.Context, string) error { return nil }

// Options —— Registry 装配项。
type Options struct {
	DegradedAfter time.Duration // 失联标 degraded（hld/07 §4：30s）
	OfflineAfter  time.Duration // 失联判 offline + 再平衡（hld/07 §4：90s）
	ScanEvery     time.Duration // 故障扫描周期（默认 5s）
	Mirror        NodeMirror
	Now           func() time.Time // 测试时钟注入
	// OnEvent 生命周期事件回调（审计/告警/分配表触发）；不得阻塞，Registry 内部同步调用
	OnEvent func(NodeEvent)
	// OnChange 节点集合/权重变化回调（触发分配表重算）；不得阻塞
	OnChange func()
}

func (o *Options) fill() {
	if o.DegradedAfter <= 0 {
		o.DegradedAfter = 30 * time.Second
	}
	if o.OfflineAfter <= 0 {
		o.OfflineAfter = 90 * time.Second
	}
	if o.ScanEvery <= 0 {
		o.ScanEvery = 5 * time.Second
	}
	if o.Mirror == nil {
		o.Mirror = NopMirror{}
	}
	if o.Now == nil {
		o.Now = time.Now
	}
}

// Registry —— 节点生命周期管理：注册 / 心跳保活 / 故障判定 / 排水。
type Registry struct {
	store Store
	opts  Options

	drainMu sync.Mutex
	pending map[string]time.Time // nodeID → drain 发起时间（迁移完成判定，见 TODO）
}

// NewRegistry 构造。
func NewRegistry(store Store, opts Options) *Registry {
	opts.fill()
	return &Registry{store: store, opts: opts, pending: map[string]time.Time{}}
}

// emit 事件回调（防 panic 扩散）。
func (r *Registry) emit(ev NodeEvent) {
	if r.opts.OnEvent != nil {
		func() {
			defer func() { _ = recover() }()
			r.opts.OnEvent(ev)
		}()
	}
}

// changed 集合变化回调。
func (r *Registry) changed() {
	if r.opts.OnChange != nil {
		func() {
			defer func() { _ = recover() }()
			r.opts.OnChange()
		}()
	}
}

// Register 注册节点（gRPC RegisterNode；docs/dd/07 §1）。
// 已在线节点重复注册为幂等更新；offline/maintenance 节点重新注册恢复 online。
func (r *Registry) Register(ctx context.Context, n Node) (Node, error) {
	now := r.opts.Now()
	n.LastHB = now
	if !ValidRole(n.Role) {
		return Node{}, errf("invalid role %q", n.Role)
	}
	prev, err := r.store.GetNode(ctx, n.ID)
	wasNew := errors.Is(err, ErrNotFound)
	switch {
	case err == nil:
		if n.JoinedAt.IsZero() {
			n.JoinedAt = prev.JoinedAt
		}
	case wasNew:
		n.JoinedAt = now
	default:
		return Node{}, errf("get node %s: %w", n.ID, err)
	}
	n.State = StateOnline
	n.Degraded = false
	if _, err := r.store.UpsertNode(ctx, n); err != nil {
		return Node{}, errf("upsert node %s: %w", n.ID, err)
	}
	if err := r.mirrorPut(ctx, n); err != nil {
		return Node{}, errf("mirror node %s: %w", n.ID, err)
	}
	if wasNew {
		r.emit(NodeEvent{Type: EventRegistered, Node: n, At: now})
	} else if prev.State != StateOnline {
		r.emit(NodeEvent{Type: EventOnline, Node: n, At: now})
	}
	r.changed()
	return n, nil
}

// Heartbeat 心跳保活（gRPC Heartbeat 流或 Kafka cluster.heartbeat；10s 间隔）。
// offline 节点恢复心跳视为重新上线并触发再平衡。
func (r *Registry) Heartbeat(ctx context.Context, id string, ts time.Time, version string) error {
	now := r.opts.Now()
	if ts.IsZero() {
		ts = now
	}
	prev, err := r.store.GetNode(ctx, id)
	if err != nil {
		return errf("get node %s for hb: %w", id, err)
	}
	// 收到心跳即存活证据：清除 degraded 标记（30s 失联标记由扫描循环重新评估）
	if err := r.store.SetNodeHB(ctx, id, ts, false, version); err != nil {
		return errf("record hb for %s: %w", id, err)
	}
	if prev.State == StateOffline {
		if err := r.store.SetNodeState(ctx, id, StateOnline); err != nil {
			return errf("recover node %s: %w", id, err)
		}
		prev.State = StateOnline
		r.emit(NodeEvent{Type: EventOnline, Node: prev, At: now})
		r.changed()
	}
	_ = r.opts.Mirror.KeepAlive(ctx, id) // lease 续约失败不阻断心跳路径（lease 到期自然摘除）
	return nil
}

// Drain 排水（Console 一键 → 分配表摘除该 collector，docs/dd/07 §2）。
//
// TODO(M2)：迁移完成自动判定（该 collector Kafka lag 归零）→ 允许维护；
// MVP 需人工确认迁移完成后经 SetState(maintenance) 收尾。
func (r *Registry) Drain(ctx context.Context, id string) error {
	n, err := r.store.GetNode(ctx, id)
	if err != nil {
		return errf("get node %s for drain: %w", id, err)
	}
	if n.State == StateMaintenance {
		return nil
	}
	if err := r.store.SetNodeState(ctx, id, StateDraining); err != nil {
		return errf("set draining %s: %w", id, err)
	}
	r.drainMu.Lock()
	r.pending[id] = r.opts.Now()
	r.drainMu.Unlock()
	n.State = StateDraining
	if err := r.mirrorPut(ctx, n); err != nil {
		return errf("mirror node %s: %w", id, err)
	}
	r.emit(NodeEvent{Type: EventDrain, Node: n, At: r.opts.Now()})
	r.changed()
	return nil
}

// ErrInvalidState —— 非法状态值。
var ErrInvalidState = errors.New("registry: invalid state")

// SetState 人工状态设置（维护窗口开始/结束等）。
func (r *Registry) SetState(ctx context.Context, id string, st State) error {
	if !ValidState(st) {
		return fmt.Errorf("%w: %q", ErrInvalidState, st)
	}
	n, err := r.store.GetNode(ctx, id)
	if err != nil {
		return errf("get node %s: %w", id, err)
	}
	if err := r.store.SetNodeState(ctx, id, st); err != nil {
		return errf("set state %s: %w", id, err)
	}
	n.State = st
	if err := r.mirrorPut(ctx, n); err != nil {
		return errf("mirror node %s: %w", id, err)
	}
	r.emit(NodeEvent{Type: EventStateSet, Node: n, At: r.opts.Now()})
	if st == StateMaintenance || st == StateOffline {
		r.changed()
	}
	return nil
}

// SetWeightOverride 设置权重覆盖（容量权重输入，docs/dd/07 §2）。
func (r *Registry) SetWeightOverride(ctx context.Context, id string, w float64) error {
	if err := r.store.SetNodeWeightOverride(ctx, id, w); err != nil {
		return errf("set weight %s: %w", id, err)
	}
	r.changed()
	return nil
}

// Get 读取节点。
func (r *Registry) Get(ctx context.Context, id string) (Node, error) {
	return r.store.GetNode(ctx, id)
}

// List 列出全部节点。
func (r *Registry) List(ctx context.Context) ([]Node, error) {
	return r.store.ListNodes(ctx)
}

// AssignCandidates —— 分配算法的 collector 输入（在线 collector + 权重，docs/dd/07 §3）。
// draining/maintenance/offline 均不参与承载新分配。
func (r *Registry) AssignCandidates(ctx context.Context) ([]Node, error) {
	nodes, err := r.store.ListNodes(ctx)
	if err != nil {
		return nil, err
	}
	var out []Node
	for _, n := range nodes {
		if n.Role == RoleCollector && n.State == StateOnline {
			out = append(out, n)
		}
	}
	return out, nil
}

// ActiveExporters —— 活跃 exporter 输入（观测窗口内见过心跳上报，docs/dd/07 §3）。
func (r *Registry) ActiveExporters(ctx context.Context, window time.Duration) ([]Exporter, error) {
	all, err := r.store.ListExporters(ctx)
	if err != nil {
		return nil, err
	}
	now := r.opts.Now()
	var out []Exporter
	for _, e := range all {
		if !e.ActiveSet {
			continue
		}
		if window > 0 && now.Sub(e.LastSeen) > window {
			continue
		}
		out = append(out, e)
	}
	return out, nil
}

// ObserveExporters 记录心跳上报的 exporter 观测。
func (r *Registry) ObserveExporters(ctx context.Context, nodeID string, obs []ExporterObs) error {
	if len(obs) == 0 {
		return nil
	}
	now := r.opts.Now()
	for _, o := range obs {
		if o.IP == "" {
			continue
		}
		if err := r.store.MarkExporterSeen(ctx, o.IP, now, o.FPS); err != nil {
			return errf("observe exporter %s: %w", o.IP, err)
		}
	}
	return nil
}

// PinExporter 手工 pin（docs/dd/07 §3 触发条件之一）。
func (r *Registry) PinExporter(ctx context.Context, ip, collectorNodeID string) error {
	if err := r.store.SetExporterPin(ctx, ip, collectorNodeID); err != nil {
		return errf("pin exporter %s: %w", ip, err)
	}
	r.changed()
	return nil
}

// Exporters 全量台账（admin 查询）。
func (r *Registry) Exporters(ctx context.Context) ([]Exporter, error) {
	return r.store.ListExporters(ctx)
}

// RecordExporter 管理侧登记/更新 exporter（ActiveSet 参与分配开关）。
func (r *Registry) RecordExporter(ctx context.Context, e Exporter) error {
	if err := r.store.UpsertExporter(ctx, e); err != nil {
		return errf("record exporter %s: %w", e.IP, err)
	}
	r.changed()
	return nil
}

// ScanLoop 故障扫描（失联 30s degraded、90s offline + 再平衡，docs/hld/07 §4）。
func (r *Registry) ScanLoop(ctx context.Context) {
	t := time.NewTicker(r.opts.ScanEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			r.scanOnce(ctx)
		}
	}
}

func (r *Registry) scanOnce(ctx context.Context) {
	nodes, err := r.store.ListNodes(ctx)
	if err != nil {
		log.Printf(`{"level":"error","module":"master.registry","msg":"scan list nodes","err":%q}`, err.Error())
		return
	}
	now := r.opts.Now()
	for _, n := range nodes {
		if n.State != StateOnline && n.State != StateDraining {
			continue
		}
		silence := now.Sub(n.LastHB)
		switch {
		case silence > r.opts.OfflineAfter:
			if err := r.store.SetNodeState(ctx, n.ID, StateOffline); err != nil {
				continue
			}
			if err := r.store.SetNodeHB(ctx, n.ID, n.LastHB, true, ""); err != nil {
				continue
			}
			_ = r.opts.Mirror.Delete(ctx, n.ID)
			n.State = StateOffline
			n.Degraded = true
			r.emit(NodeEvent{Type: EventOffline, Node: n, At: now})
			r.changed()
		case silence > r.opts.DegradedAfter && !n.Degraded:
			if err := r.store.SetNodeHB(ctx, n.ID, n.LastHB, true, ""); err != nil {
				continue
			}
			n.Degraded = true
			r.emit(NodeEvent{Type: EventDegraded, Node: n, At: now})
		}
	}
}

func (r *Registry) mirrorPut(ctx context.Context, n Node) error {
	profile, err := ProfileJSON(n)
	if err != nil {
		return err
	}
	return r.opts.Mirror.Put(ctx, n.ID, profile)
}

// Close 关闭底层存储。
func (r *Registry) Close() error { return r.store.Close() }
