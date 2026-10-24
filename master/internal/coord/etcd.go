package coord

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sync/atomic"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"
	"go.etcd.io/etcd/client/v3/concurrency"

	"github.com/SchearLoe/lucidnet/master/internal/assign"
	"github.com/SchearLoe/lucidnet/master/internal/config"
	"github.com/SchearLoe/lucidnet/master/internal/registry"
)

// etcd 集成（docs/09 §5 键空间属主 Master；hld/07 §2 选主 /lucid/leader）。

// EtcdClient —— 连接构造（装配层统一持有生命周期）。
func EtcdClient(ctx context.Context, endpoints []string) (*clientv3.Client, error) {
	cli, err := clientv3.New(clientv3.Config{
		Endpoints:   endpoints,
		DialTimeout: 5 * time.Second,
		Context:     ctx,
	})
	if err != nil {
		return nil, fmt.Errorf("connect etcd %v: %w", endpoints, err)
	}
	return cli, nil
}

// ConfigPublisher —— config.Publisher 的 etcd 实现（值 = config.Envelope JSON）。
type ConfigPublisher struct{ cli *clientv3.Client }

// NewConfigPublisher 构造。
func NewConfigPublisher(cli *clientv3.Client) *ConfigPublisher { return &ConfigPublisher{cli: cli} }

// Publish 实现 config.Publisher。
func (p *ConfigPublisher) Publish(ctx context.Context, scope string, env config.Envelope) error {
	b, err := json.Marshal(env)
	if err != nil {
		return fmt.Errorf("marshal envelope for %s: %w", scope, err)
	}
	if _, err := p.cli.Put(ctx, scope, string(b)); err != nil {
		return fmt.Errorf("etcd put %s: %w", scope, err)
	}
	return nil
}

// AssignPublisher —— assign.Publisher 的 etcd 实现（值 = assign.Table JSON，
// 版本在表内，docs/09 §5 "版本化快照"）。
type AssignPublisher struct{ cli *clientv3.Client }

// NewAssignPublisher 构造。
func NewAssignPublisher(cli *clientv3.Client) *AssignPublisher { return &AssignPublisher{cli: cli} }

// PublishAssign 实现 assign.Publisher。
func (p *AssignPublisher) PublishAssign(ctx context.Context, t assign.Table) error {
	b, err := json.Marshal(t)
	if err != nil {
		return fmt.Errorf("marshal assign table v%d: %w", t.Version, err)
	}
	if _, err := p.cli.Put(ctx, KeyAssignFlow, string(b)); err != nil {
		return fmt.Errorf("etcd put %s: %w", KeyAssignFlow, err)
	}
	return nil
}

// LatestAssignVersion 读取当前分配表版本（Assigner 重启后 version 单调衔接）。
func LatestAssignVersion(ctx context.Context, cli *clientv3.Client) (uint64, error) {
	resp, err := cli.Get(ctx, KeyAssignFlow)
	if err != nil {
		return 0, fmt.Errorf("etcd get %s: %w", KeyAssignFlow, err)
	}
	if resp.Count == 0 {
		return 0, nil
	}
	t, err := assign.ParseTable(resp.Kvs[0].Value)
	if err != nil {
		return 0, fmt.Errorf("parse current assign table: %w", err)
	}
	return t.Version, nil
}

// etcd 键（docs/09 §5 / hld/07 §3；常量即接口，新增需登记 09）。
const (
	KeyLeader     = "/lucid/leader"
	KeyNodesRoot  = "/lucid/nodes/"
	KeyAssignFlow = "/lucid/assign/flow"
)

// NodeMirror —— registry.NodeMirror 的 etcd 实现：/lucid/nodes/{id} 档案 + 独立 lease
// （心跳 KeepAlive 续约；lease 到期节点档案自动摘除，docs/hld/07 §3）。
type NodeMirror struct {
	cli *clientv3.Client
	ttl int64
	mu  syncMap // nodeID → leaseID
}

type syncMap struct {
	v atomic.Value // map[string]clientv3.LeaseID
}

func (m *syncMap) load() map[string]clientv3.LeaseID {
	if v, ok := m.v.Load().(map[string]clientv3.LeaseID); ok {
		return v
	}
	return map[string]clientv3.LeaseID{}
}

func (m *syncMap) store(k string, id clientv3.LeaseID) {
	cur := m.load()
	next := make(map[string]clientv3.LeaseID, len(cur)+1)
	for k2, v2 := range cur {
		next[k2] = v2
	}
	next[k] = id
	m.v.Store(next)
}

func (m *syncMap) get(k string) (clientv3.LeaseID, bool) {
	id, ok := m.load()[k]
	return id, ok
}

func (m *syncMap) del(k string) {
	cur := m.load()
	next := make(map[string]clientv3.LeaseID, len(cur))
	for k2, v2 := range cur {
		if k2 != k {
			next[k2] = v2
		}
	}
	m.v.Store(next)
}

// NewNodeMirror 构造（ttl 秒为 lease 存活期，≥3×心跳间隔）。
func NewNodeMirror(cli *clientv3.Client, ttl time.Duration) *NodeMirror {
	if ttl <= 0 {
		ttl = 30 * time.Second
	}
	return &NodeMirror{cli: cli, ttl: int64(ttl.Seconds())}
}

// Put 写入节点档案（每次授予新 lease，替代旧 lease）。
func (m *NodeMirror) Put(ctx context.Context, id string, profileJSON []byte) error {
	lease, err := m.cli.Grant(ctx, m.ttl)
	if err != nil {
		return fmt.Errorf("grant lease for node %s: %w", id, err)
	}
	if _, err := m.cli.Put(ctx, KeyNodesRoot+id, string(profileJSON),
		clientv3.WithLease(lease.ID)); err != nil {
		return fmt.Errorf("etcd put node %s: %w", id, err)
	}
	m.mu.store(id, lease.ID)
	return nil
}

// Delete 摘除节点档案。
func (m *NodeMirror) Delete(ctx context.Context, id string) error {
	if leaseID, ok := m.mu.get(id); ok {
		_, _ = m.cli.Revoke(ctx, leaseID)
		m.mu.del(id)
	}
	_, err := m.cli.Delete(ctx, KeyNodesRoot+id)
	if err != nil {
		return fmt.Errorf("etcd delete node %s: %w", id, err)
	}
	return nil
}

// KeepAlive 心跳续约（lease 缺失时静默——档案由下次 Put 重建）。
func (m *NodeMirror) KeepAlive(ctx context.Context, id string) error {
	leaseID, ok := m.mu.get(id)
	if !ok {
		return nil
	}
	_, err := m.cli.KeepAliveOnce(ctx, leaseID)
	if err != nil {
		m.mu.del(id) // lease 已过期：档案由 etcd 自动删除，等下次注册重建
		return fmt.Errorf("keepalive lease for node %s: %w", id, err)
	}
	return nil
}

// CompileAssert 实现约束。
var _ registry.NodeMirror = (*NodeMirror)(nil)

// LeaderGate —— etcd 选主（docs/dd/07 §7：Master 宕机，备 15s 接管）。
// 非 leader 实例：数据面读接口可用，配置变更拒绝（只读保护）。
type LeaderGate struct {
	cli      *clientv3.Client
	name     string
	ttl      int
	isLeader atomic.Bool
	running  atomic.Bool
}

// NewLeaderGate 构造（ttl 秒 = 接管上限，默认 15s）。
func NewLeaderGate(cli *clientv3.Client, name string, ttl int) *LeaderGate {
	if ttl <= 0 {
		ttl = 15
	}
	return &LeaderGate{cli: cli, name: name, ttl: ttl}
}

// IsLeader 当前是否 leader。
func (g *LeaderGate) IsLeader() bool { return g.isLeader.Load() }

// Run 竞选循环（阻塞；ctx 取消后 Resign 返回）。
func (g *LeaderGate) Run(ctx context.Context) {
	if !g.running.CompareAndSwap(false, true) {
		return
	}
	for {
		if ctx.Err() != nil {
			return
		}
		session, err := concurrency.NewSession(g.cli,
			concurrency.WithContext(ctx), concurrency.WithTTL(g.ttl))
		if err != nil {
			log.Printf(`{"level":"warn","module":"master.coord","msg":"leader session","err":%q}`, err.Error())
			if !sleepCtx(ctx, 2*time.Second) {
				return
			}
			continue
		}
		election := concurrency.NewElection(session, KeyLeader)
		if err := election.Campaign(ctx, g.name); err != nil {
			_ = session.Close()
			if !sleepCtx(ctx, time.Second) {
				return
			}
			continue
		}
		g.isLeader.Store(true)
		log.Printf(`{"level":"info","module":"master.coord","msg":"leader acquired","name":%q}`, g.name)
		// 会话断开（网络分区/etcd 多数派丢失）→ 自动降级为只读并重选
		select {
		case <-ctx.Done():
			g.isLeader.Store(false)
			_ = election.Resign(context.WithoutCancel(ctx))
			_ = session.Close()
			return
		case <-session.Done():
			g.isLeader.Store(false)
			log.Printf(`{"level":"warn","module":"master.coord","msg":"leader session lost","name":%q}`, g.name)
		}
		_ = session.Close()
		if !sleepCtx(ctx, time.Second) {
			return
		}
	}
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	select {
	case <-ctx.Done():
		return false
	case <-time.After(d):
		return true
	}
}
