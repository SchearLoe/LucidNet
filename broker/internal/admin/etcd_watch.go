// Package admin —— 控制面接入（dd/01 §1 admin 子模块）：
// etcd watch 配置下发（docs/09 §5 裁定⑤：Broker 配置唯一通道）+ Master gRPC 注册/心跳（docs/09 §4）。
package admin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"

	"github.com/SchearLoe/lucidnet/broker/internal/config"
	"github.com/SchearLoe/lucidnet/broker/internal/flb"
	"github.com/SchearLoe/lucidnet/broker/internal/forwarder"
)

// AssignSink —— 分配表应用回调（engine 注入：编译→原子换表→打点）。
type AssignSink func(*flb.AssignSnapshot)

// RulesSink —— 转发规则应用回调（engine 注入：编译→目的地重建→原子换表）。
type RulesSink func(*forwarder.RulesSnapshot) []error

// Watcher —— etcd watch（/lucid/assign/flow、/lucid/forward/rules；docs/09 §5）。
// 初始 get + 增量 watch；version 单调闸：旧版本/乱序快照直接忽略（dd/01 §2.1）。
type Watcher struct {
	cli       *clientv3.Client
	assignKey string
	rulesKey  string
	onAssign  AssignSink
	onRules   RulesSink
	log       *slog.Logger

	assignVersion uint64 // 单调游标（本地）
	rulesVersion  uint64

	applyMu sync.Mutex // 序列化快照应用（watch 重建期间防并发）
}

// NewWatcher 构造。
func NewWatcher(cfg config.Config, cli *clientv3.Client, onAssign AssignSink, onRules RulesSink, log *slog.Logger) *Watcher {
	if log == nil {
		log = slog.Default()
	}
	return &Watcher{
		cli:       cli,
		assignKey: cfg.AssignKey,
		rulesKey:  cfg.RulesKey,
		onAssign:  onAssign,
		onRules:   onRules,
		log:       log,
	}
}

// Run —— 阻塞 watch 主循环（ctx 取消退出；etcd 短暂不可达自动重试）。
func (w *Watcher) Run(ctx context.Context) error {
	if err := w.bootstrap(ctx); err != nil {
		return err
	}
	// 两条 watch 独立协程；任一通道意外关闭则整体退出（上层拉起重连，避免双写游标）
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	errCh := make(chan error, 2)
	go func() { errCh <- w.watchOne(runCtx, w.assignKey, w.applyAssign) }()
	go func() { errCh <- w.watchOne(runCtx, w.rulesKey, w.applyRules) }()
	select {
	case <-ctx.Done():
		return nil
	case <-runCtx.Done():
		return nil
	case err := <-errCh:
		return err
	}
}

// bootstrap —— 启动全量拉取（30s 内恢复语义，dd/01 §5）。
func (w *Watcher) bootstrap(ctx context.Context) error {
	for _, item := range []struct {
		key   string
		apply func([]byte) error
	}{
		{w.assignKey, w.applyAssign},
		{w.rulesKey, w.applyRules},
	} {
		resp, err := w.cli.Get(ctx, item.key)
		if err != nil {
			return fmt.Errorf("admin: etcd get %s: %w", item.key, err)
		}
		if len(resp.Kvs) == 0 {
			w.log.Info("admin: etcd key empty at bootstrap", "key", item.key)
			continue
		}
		if err := item.apply(resp.Kvs[0].Value); err != nil {
			w.log.Warn("admin: bootstrap snapshot rejected", "key", item.key, "err", err)
		}
	}
	return nil
}

// watchOne —— 单键 watch（通道关闭→返回错误，由进程拉起重连）。
func (w *Watcher) watchOne(ctx context.Context, key string, apply func([]byte) error) error {
	for {
		ch := w.cli.Watch(ctx, key)
		for resp := range ch {
			for _, ev := range resp.Events {
				var val []byte
				if ev.Type == clientv3.EventTypePut && ev.Kv != nil {
					val = ev.Kv.Value
				} else if ev.Type == clientv3.EventTypeDelete && ev.PrevKv != nil {
					w.log.Warn("admin: config key deleted", "key", key)
					continue
				} else {
					continue
				}
				if err := apply(val); err != nil {
					w.log.Warn("admin: snapshot rejected", "key", key, "err", err)
				}
			}
		}
		if ctx.Err() != nil {
			return nil
		}
		// watch 通道异常关闭：退避重建
		w.log.Warn("admin: watch channel closed, retrying", "key", key)
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(time.Second):
		}
	}
}

// versioned —— 单调版本闸通用结构。
type versioned struct {
	Version uint64 `json:"version"`
}

// checkVersion —— 解析 version 并做单调判断（< 当前版本拒绝；0 版本视为非法快照）。
func checkVersion(key string, current *uint64, data []byte) (uint64, error) {
	var v versioned
	if err := json.Unmarshal(data, &v); err != nil {
		return 0, fmt.Errorf("admin: decode %s snapshot: %w", key, err)
	}
	if v.Version == 0 {
		return 0, errors.New("admin: snapshot version must be positive (monotonic)")
	}
	if v.Version <= *current {
		return v.Version, fmt.Errorf("admin: stale snapshot version %d (current %d): ignored", v.Version, *current)
	}
	return v.Version, nil
}

// applyAssign —— 分配表快照（JSON，字段名对齐 proto AssignTable，docs/09 §5）。
func (w *Watcher) applyAssign(data []byte) error {
	w.applyMu.Lock()
	defer w.applyMu.Unlock()
	v, err := checkVersion(w.assignKey, &w.assignVersion, data)
	if err != nil {
		return err
	}
	var snap flb.AssignSnapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return fmt.Errorf("admin: decode assign snapshot: %w", err)
	}
	w.onAssign(&snap)
	w.assignVersion = v
	return nil
}

// applyRules —— 转发规则快照。
func (w *Watcher) applyRules(data []byte) error {
	w.applyMu.Lock()
	defer w.applyMu.Unlock()
	v, err := checkVersion(w.rulesKey, &w.rulesVersion, data)
	if err != nil {
		return err
	}
	var snap forwarder.RulesSnapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return fmt.Errorf("admin: decode rules snapshot: %w", err)
	}
	if errs := w.onRules(&snap); len(errs) > 0 {
		// 部分规则非法：合法部分已生效，错误回传日志（审计由 Master 负责，dd/01 §5）
		w.log.Warn("admin: rules snapshot partially applied", "errs", errs)
	}
	w.rulesVersion = v
	return nil
}
