package assign

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"
)

// Assigner —— 分配表计算编排：触发合并（防抖 30s）→ 计算 → 版本化发布 → 订阅广播。
type Assigner struct {
	opts Options

	// 输入源（由装配层注入：registry.AssignCandidates / ActiveExporters）
	Collectors func(ctx context.Context) ([]Collector, error)
	Exporters  func(ctx context.Context) ([]Exporter, error)

	// 发布与初始版本（etcd；由装配层注入）
	Publisher Publisher
	// SetInitialVersion 由装配层在启动时注入 etcd 现值版本号，保证重启后单调
	InitialVersion uint64

	mu      sync.RWMutex
	cur     Table
	version uint64

	dirty     chan struct{}
	subsMu    sync.Mutex
	subs      map[int]chan Table
	nextSubID int

	runOnce sync.Once
}

// Publisher —— 分配表发布抽象（etcd）。
type Publisher interface {
	PublishAssign(ctx context.Context, t Table) error
}

// NopPublisher —— 无 etcd 开发模式空实现。
type NopPublisher struct{}

// PublishAssign 实现 Publisher。
func (NopPublisher) PublishAssign(context.Context, Table) error { return nil }

// New 构造 Assigner。
func New(opts Options) *Assigner {
	opts.fill()
	return &Assigner{
		opts:  opts,
		dirty: make(chan struct{}, 1),
		subs:  map[int]chan Table{},
	}
}

// Trigger —— 触发重算（节点上下线/权重变化/新 exporter/手工 pin；非阻塞合并）。
func (a *Assigner) Trigger() {
	select {
	case a.dirty <- struct{}{}:
	default:
	}
}

// Subscribe 订阅分配表变更（WatchAssign 流）；返回订阅通道与取消函数。
// 订阅后立即收到当前表。
func (a *Assigner) Subscribe() (<-chan Table, func()) {
	ch := make(chan Table, 8)
	a.subsMu.Lock()
	a.nextSubID++
	id := a.nextSubID
	a.subs[id] = ch
	a.subsMu.Unlock()
	cur := a.Current()
	if cur.Version > 0 {
		select {
		case ch <- cur:
		default:
		}
	}
	return ch, func() {
		a.subsMu.Lock()
		if _, ok := a.subs[id]; ok {
			delete(a.subs, id)
			close(ch)
		}
		a.subsMu.Unlock()
	}
}

// Current 当前分配表快照。
func (a *Assigner) Current() Table {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.cur
}

// Run 主循环：dirty → 防抖窗口 → 计算 → 发布（单调 version）→ 广播。
func (a *Assigner) Run(ctx context.Context) {
	a.runOnce.Do(func() {
		a.mu.Lock()
		a.version = a.InitialVersion
		a.mu.Unlock()
	})
	for {
		select {
		case <-ctx.Done():
			return
		case <-a.dirty:
		}
		// 防抖：30s 内的多次触发合并为一次计算（docs/dd/07 §3）
		debounce := time.NewTimer(a.opts.Debounce)
	drain:
		for {
			select {
			case <-ctx.Done():
				debounce.Stop()
				return
			case <-a.dirty:
			case <-debounce.C:
				break drain
			}
		}
		if err := a.computeAndPublish(ctx); err != nil {
			log.Printf(`{"level":"error","module":"master.assign","msg":"compute/publish","err":%q}`, err.Error())
		}
	}
}

// ComputeOnce 立即计算并发布（启动引导/管理端强制刷新）。
func (a *Assigner) ComputeOnce(ctx context.Context) error {
	return a.computeAndPublish(ctx)
}

func (a *Assigner) computeAndPublish(ctx context.Context) error {
	collectors, err := a.Collectors(ctx)
	if err != nil {
		return fmt.Errorf("load collectors: %w", err)
	}
	exporters, err := a.Exporters(ctx)
	if err != nil {
		return fmt.Errorf("load exporters: %w", err)
	}
	plan, err := computePlan(collectors, exporters, a.opts)
	if err != nil {
		return fmt.Errorf("compute assign plan: %w", err)
	}
	a.mu.Lock()
	a.version++ // 单调 version（etcd 历史版本回看）
	v := a.version
	a.mu.Unlock()
	t := Table{Version: v, UpdatedAt: a.opts.Now(), Entries: make([]Entry, 0, len(plan))}
	for _, e := range plan {
		t.Entries = append(t.Entries, e)
	}
	SortEntries(&t)
	if err := a.Publisher.PublishAssign(ctx, t); err != nil {
		a.mu.Lock()
		a.version-- // 发布失败回退版本号，下轮重算重用
		a.mu.Unlock()
		return fmt.Errorf("publish assign table v%d: %w", v, err)
	}
	a.mu.Lock()
	a.cur = t
	a.mu.Unlock()
	a.broadcast(t)
	log.Printf(`{"level":"info","module":"master.assign","msg":"assign table published","version":%d,"exporters":%d,"collectors":%d}`,
		v, len(t.Entries), len(collectors))
	return nil
}

func (a *Assigner) broadcast(t Table) {
	a.subsMu.Lock()
	defer a.subsMu.Unlock()
	for id, ch := range a.subs {
		select {
		case ch <- t:
		default: // 慢消费者丢弃本轮（表有 version，重连后补发当前表）
			log.Printf(`{"level":"warn","module":"master.assign","msg":"slow watch subscriber dropped","sub":%d}`, id)
		}
	}
}

// ParseTable 解析 /lucid/assign/flow 值。
func ParseTable(b []byte) (Table, error) {
	var t Table
	if err := json.Unmarshal(b, &t); err != nil {
		return Table{}, fmt.Errorf("parse assign table: %w", err)
	}
	return t, nil
}
