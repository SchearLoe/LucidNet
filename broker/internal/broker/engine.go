// Package broker —— lucid-broker 引擎组装（dd/01 §1 进程结构）：
// ingest（UDP 收包）→ flb（查表分发 collector，必经）+ forwarder（R1 规则复制/重编码/Kafka）
// + admin（etcd watch 配置热更新 + Master 注册心跳）+ metrics（Prometheus）。
package broker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"

	"github.com/SchearLoe/lucidnet/broker/internal/admin"
	"github.com/SchearLoe/lucidnet/broker/internal/config"
	"github.com/SchearLoe/lucidnet/broker/internal/flb"
	"github.com/SchearLoe/lucidnet/broker/internal/forwarder"
	"github.com/SchearLoe/lucidnet/broker/internal/ingest"
	"github.com/SchearLoe/lucidnet/broker/internal/kafkaprod"
	"github.com/SchearLoe/lucidnet/broker/internal/metrics"
)

// Engine —— 进程级组装（Run 阻塞至 ctx 取消）。
type Engine struct {
	cfg config.Config
	log *slog.Logger
	m   *metrics.Metrics

	producer *kafkaprod.Producer
	fwd      *forwarder.Engine
	dispatch *flb.Dispatcher
	prober   *flb.Prober
	pool     *ingest.Pool
	watcher  *admin.Watcher
	agent    *admin.MasterAgent
	etcd     *clientv3.Client

	rulesVersion  atomic.Uint64
	assignVersion atomic.Uint64
	startedAt     time.Time

	wg      sync.WaitGroup
	stopped sync.Once
}

// New —— 组装全部子模块（不启动；启动经 Run/Start）。
func New(cfg config.Config, m *metrics.Metrics, log *slog.Logger) (*Engine, error) {
	if log == nil {
		log = slog.Default()
	}
	if m == nil {
		m = metrics.New(nil)
	}
	e := &Engine{cfg: cfg, log: log, m: m, startedAt: time.Now()}

	// —— Kafka 生产（flows.raw 等；kgo 惰性连接，失败不阻断 FLB 数据面） ——
	if len(cfg.KafkaBrokers) > 0 {
		p, err := kafkaprod.New(cfg.KafkaBrokers, func(topic string, n int, perr error) {
			if perr != nil {
				m.KafkaProduceError(topic, n)
			} else {
				m.KafkaProduce(topic, n)
			}
		})
		if err != nil {
			return nil, err
		}
		e.producer = p
	}

	// —— Forwarder（R1） ——
	var sink forwarder.KafkaSink
	if e.producer != nil {
		sink = e.producer
	}
	e.fwd = forwarder.NewEngine(sink, m)

	// —— FLB（查表分发 + 探活） ——
	health := flb.NewHealth(cfg.ProbeFailThreshold, cfg.ProbeRestoreAfter, func(addr string, down bool) {
		m.SetCollectorHealth(addr, !down)
		log.Warn("flb: collector health changed", "collector", addr, "down", down)
	})
	e.dispatch = flb.NewDispatcher(cfg.DefaultCollectors, health, m)
	e.prober = flb.NewProber(e.dispatch, cfg.ProbeInterval)

	// —— Ingest ——
	e.pool = ingest.NewPool(e.onPacket, cfg.WorkersPerPort, cfg.RcvBufBytes)
	return e, nil
}

// onPacket —— 收包路径（dd/01 §1：Forwarder 复制点在 FLB 之前）。
func (e *Engine) onPacket(datagram []byte, src netip.Addr) {
	e.fwd.Process(datagram, src)
	e.dispatch.Forward(datagram, src.String())
}

// Run —— 启动全部协程并阻塞至 ctx 取消，返回前完成优雅关停。
func (e *Engine) Run(ctx context.Context) error {
	if err := e.Start(ctx); err != nil {
		return err
	}
	<-ctx.Done()
	e.Stop()
	return nil
}

// Start —— 拉起数据面与控制面（错误时回收已启动部分）。
func (e *Engine) Start(ctx context.Context) error {
	etcd, err := clientv3.New(clientv3.Config{
		Endpoints:   e.cfg.EtcdEndpoints,
		Context:     ctx,
		DialTimeout: 5 * time.Second,
	})
	if err != nil {
		e.Stop()
		return fmt.Errorf("broker: etcd client: %w", err)
	}
	e.etcd = etcd
	e.watcher = admin.NewWatcher(e.cfg, etcd,
		func(snap *flb.AssignSnapshot) {
			tbl := flb.CompileAssign(snap)
			e.dispatch.Table().Store(tbl)
			e.assignVersion.Store(tbl.Version)
			e.m.SetAssignVersion(tbl.Version)
			e.m.SetAssignExporters(tbl.Len())
			e.log.Info("flb: assign table applied", "version", tbl.Version, "exporters", tbl.Len(), "collectors", len(tbl.Collectors()))
		},
		func(snap *forwarder.RulesSnapshot) []error {
			rs, verrs := e.fwd.ApplyRules(snap)
			e.rulesVersion.Store(rs.Version)
			e.m.SetRulesVersion(rs.Version)
			e.log.Info("forwarder: rules applied", "version", rs.Version, "rules", rs.RuleCount())
			return verrs
		},
		e.log)

	if err := e.pool.Start(ctx, e.cfg.ListenAddr, e.cfg.ListenPorts); err != nil {
		e.Stop()
		return err
	}

	e.spawn("flb.prober", func() { e.prober.Run(ctx) })
	e.spawn("admin.watch", func() {
		if err := e.watcher.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
			e.log.Error("admin: etcd watch exited", "err", err)
		}
	})
	if e.cfg.MasterAddr != "" {
		agent := admin.NewMasterAgent(e.cfg.MasterAddr, e.cfg.NodeID, "",
			uint32(runtime.NumCPU()), 0, e.heartbeatJSON, nil, e.log)
		e.agent = agent
		e.spawn("admin.master", func() { agent.Run(ctx, e.cfg.HeartbeatInterval) })
	}
	e.log.Info("broker: started",
		"node", e.cfg.NodeID,
		"listen", fmt.Sprintf("%s ports=%v", e.cfg.ListenAddr, e.cfg.ListenPorts),
		"workers_per_port", e.cfg.WorkersPerPort,
		"etcd", e.cfg.EtcdEndpoints,
		"kafka", e.cfg.KafkaBrokers)
	return nil
}

// Stop —— 优雅关停：停收包 → flush Kafka → 会话 flush 关闭 → 关资源（幂等）。
func (e *Engine) Stop() {
	e.stopped.Do(func() {
		e.log.Info("broker: shutting down")
		e.pool.Close() // 先停收包（不再产生新数据）
		if e.producer != nil {
			flushCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			e.producer.Close(flushCtx)
			cancel()
		}
		e.fwd.Close() // 会话 flush 后关闭（dd/01 §3.2 #5）
		e.dispatch.Close()
		if e.etcd != nil {
			_ = e.etcd.Close()
		}
		e.wg.Wait()
		e.log.Info("broker: stopped")
	})
}

// spawn —— 常驻协程包装（panic 隔离 + WaitGroup）。
func (e *Engine) spawn(name string, fn func()) {
	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		defer func() {
			if r := recover(); r != nil {
				e.log.Error("broker: goroutine panic", "component", name, "panic", r)
			}
		}()
		fn()
	}()
}

// heartbeatJSON —— 心跳摘要（Prometheus 为主通道，此为摘要，docs/09 §4）。
func (e *Engine) heartbeatJSON() string {
	summary := struct {
		Node          string `json:"node"`
		UptimeSeconds int64  `json:"uptime_seconds"`
		IngestPackets int64  `json:"ingest_packets_total"`
		RulesVersion  uint64 `json:"rules_version"`
		AssignVersion uint64 `json:"assign_version"`
	}{
		Node:          e.cfg.NodeID,
		UptimeSeconds: int64(time.Since(e.startedAt).Seconds()),
		IngestPackets: e.pool.Packets(),
		RulesVersion:  e.rulesVersion.Load(),
		AssignVersion: e.assignVersion.Load(),
	}
	b, err := json.Marshal(summary)
	if err != nil {
		return "{}"
	}
	return string(b)
}

// Producer —— 暴露 Kafka 生产者（测试/运维；可为 nil）。
func (e *Engine) Producer() *kafkaprod.Producer { return e.producer }

// Forwarder —— 暴露规则引擎（测试）。
func (e *Engine) Forwarder() *forwarder.Engine { return e.fwd }

// Dispatcher —— 暴露 FLB 分发器（测试）。
func (e *Engine) Dispatcher() *flb.Dispatcher { return e.dispatch }
