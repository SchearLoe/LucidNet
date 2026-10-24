package config

import (
	"context"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ---------- 内存补偿队列 ----------

// TestMemOutboxLifecycle —— 落队 → 到期可见 → 重试失败退避 → 成功关单 / 人工取消。
func TestMemOutboxLifecycle(t *testing.T) {
	ctx := context.Background()
	ob := NewMemOutbox()
	// 落队（1s 后到期）
	e := OutboxEntry{Scope: ScopeZones, Version: 7, Payload: zonesOK,
		Required: []string{"n1"}, NextRetry: time.Now().Add(time.Second)}
	if err := ob.Enqueue(ctx, &e); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	if e.ID == 0 || e.Status != OutboxPending {
		t.Fatalf("entry = %+v", e)
	}
	// 同 scope+version 重复落队拒绝
	if err := ob.Enqueue(ctx, &OutboxEntry{Scope: ScopeZones, Version: 7}); err == nil {
		t.Fatal("duplicate pending accepted")
	}
	// 未到期不可见
	due, _ := ob.PendingDue(ctx, time.Now(), 10)
	if len(due) != 0 {
		t.Fatalf("due before next_retry = %v", due)
	}
	// 到期可见
	due, _ = ob.PendingDue(ctx, time.Now().Add(2*time.Second), 10)
	if len(due) != 1 || due[0].Version != 7 || len(due[0].Required) != 1 {
		t.Fatalf("due = %+v", due)
	}
	// 重试失败：attempt++ 退避顺延
	if err := ob.MarkAttempt(ctx, e.ID, time.Now().Add(time.Hour), "etcd down"); err != nil {
		t.Fatalf("mark attempt: %v", err)
	}
	due, _ = ob.PendingDue(ctx, time.Now().Add(2*time.Second), 10)
	if len(due) != 0 {
		t.Fatal("entry still due after backoff push")
	}
	pending, _ := ob.ListPending(ctx)
	if len(pending) != 1 || pending[0].Attempt != 1 || pending[0].LastError != "etcd down" {
		t.Fatalf("pending after attempt = %+v", pending)
	}
	// 成功关单
	if err := ob.MarkDone(ctx, e.ID); err != nil {
		t.Fatalf("mark done: %v", err)
	}
	if n, _ := ob.PendingCount(ctx); n != 0 {
		t.Fatalf("pending count = %d after done", n)
	}
	// 关单后重复关单拒绝
	if err := ob.MarkDone(ctx, e.ID); !errors.Is(err, ErrOutboxNotFound) {
		t.Fatalf("double done err = %v", err)
	}
	// 取消路径
	e2 := OutboxEntry{Scope: ScopeZones, Version: 8, NextRetry: time.Now()}
	if err := ob.Enqueue(ctx, &e2); err != nil {
		t.Fatalf("enqueue v8: %v", err)
	}
	if err := ob.Cancel(ctx, ScopeZones, 8); err != nil {
		t.Fatalf("cancel: %v", err)
	}
	if err := ob.Cancel(ctx, ScopeZones, 8); !errors.Is(err, ErrOutboxNotFound) {
		t.Fatalf("double cancel err = %v", err)
	}
	if n, _ := ob.PendingCount(ctx); n != 0 {
		t.Fatalf("pending count = %d after cancel", n)
	}
}

// fakeObs —— 发布链路可观测钩子桩。
type fakeObs struct {
	mu       sync.Mutex
	attempts int
	lastErr  error
	partials int
}

func (f *fakeObs) PublishAttempt(_ string, err error, _ time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.attempts++
	f.lastErr = err
}

func (f *fakeObs) AckPartial(string, uint64, int, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.partials++
}

func (f *fakeObs) OutboxDepth(int) {}

// TestPublishFailurePersistsOutboxAndRecovers —— etcd 发布失败落 outbox（版本 failed），
// etcd 恢复后重投成功：版本转 published、单关 done、reload 下发恢复。
func TestPublishFailurePersistsOutboxAndRecovers(t *testing.T) {
	pub := &failingPub{fails: 1}
	s, sink := newTestStore(t, []string{"n1"}, pub)
	obs := &fakeObs{}
	s.opts.Obs = obs
	outbox := NewMemOutbox()
	s.outbox = outbox
	ctx := context.Background()
	go s.Run(ctx)
	defer s.Close()

	if _, err := s.Publish(ctx, ScopeZones, zonesOK, "tester"); err == nil {
		t.Fatal("publish should fail while etcd down")
	}
	// 版本 failed + 单据落队
	v, _ := s.GetVersion(ctx, ScopeZones, 1)
	if v.State != VersionFailed {
		t.Fatalf("state = %s, want failed", v.State)
	}
	pending, _ := outbox.ListPending(ctx)
	if len(pending) != 1 || pending[0].Version != 1 || string(pending[0].Payload) != string(zonesOK) {
		t.Fatalf("pending = %+v", pending)
	}
	obs.mu.Lock()
	attempts, lastErr := obs.attempts, obs.lastErr
	obs.mu.Unlock()
	if attempts != 1 || lastErr == nil {
		t.Fatalf("obs attempts = %d lastErr = %v", attempts, lastErr)
	}

	// etcd 恢复 → 补偿重投成功
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		v, _ = s.GetVersion(ctx, ScopeZones, 1)
		if v.State == VersionPublished {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if v.State != VersionPublished {
		t.Fatalf("state = %s, want published after outbox retry", v.State)
	}
	if n, _ := outbox.PendingCount(ctx); n != 0 {
		t.Fatalf("outbox not closed: %d pending", n)
	}
	if len(sink.sent) == 0 {
		t.Fatal("reload not dispatched after recovery")
	}
}

// TestOutboxStartupScanRecoversPending —— 重启扫描 pending（PG 权威续补语义）：
// 预置 failed 版本 + pending 单，新 Store 启动后重投成功关单。
func TestOutboxStartupScanRecoversPending(t *testing.T) {
	outbox := NewMemOutbox()
	versions := NewMemVersions()
	// 模拟上次运行遗留：版本 v1 failed + pending 单
	if err := versions.SaveVersion(context.Background(), Version{
		Scope: ScopeZones, Version: 1, State: VersionFailed,
		DataJSON: zonesOK, CreatedAt: time.Now(),
	}, AckSummary{Required: []string{"n1"}}); err != nil {
		t.Fatalf("seed version: %v", err)
	}
	if err := outbox.Enqueue(context.Background(), &OutboxEntry{
		Scope: ScopeZones, Version: 1, Payload: zonesOK, Required: []string{"n1"},
		NextRetry: time.Now().Add(-time.Minute),
	}); err != nil {
		t.Fatalf("seed outbox: %v", err)
	}

	s := NewStore(versions, Options{
		Publisher: &failingPub{}, // fails=0 → 重投成功
		Targets:   &fakeTarget{nodes: []string{"n1"}},
		Outbox:    outbox,
		PollEvery: 10 * time.Millisecond,
	})
	ctx := context.Background()
	go s.Run(ctx)
	defer s.Close()

	deadline := time.Now().Add(3 * time.Second)
	var v Version
	for time.Now().Before(deadline) {
		v, _ = s.GetVersion(ctx, ScopeZones, 1)
		if v.State == VersionActive || v.State == VersionPublished {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("state = %s, want recovered after startup scan", v.State)
}

// TestCancelPendingOutbox —— 人工取消后不再重投，版本保持 failed。
func TestCancelPendingOutbox(t *testing.T) {
	pub := &failingPub{fails: 1}
	s, _ := newTestStore(t, nil, pub)
	outbox := NewMemOutbox()
	s.outbox = outbox
	ctx := context.Background()
	if _, err := s.Publish(ctx, ScopeZones, zonesOK, "t"); err == nil {
		t.Fatal("publish should fail")
	}
	if err := s.CancelPending(ctx, ScopeZones, 1); err != nil {
		t.Fatalf("cancel: %v", err)
	}
	if err := s.CancelPending(ctx, ScopeZones, 1); !errors.Is(err, ErrOutboxNotFound) {
		t.Fatalf("double cancel err = %v", err)
	}
	if n, _ := outbox.PendingCount(ctx); n != 0 {
		t.Fatalf("pending = %d after cancel", n)
	}
	v, _ := s.GetVersion(ctx, ScopeZones, 1)
	if v.State != VersionFailed {
		t.Fatalf("state = %s, want failed after cancel", v.State)
	}
}

// TestBackoffSchedule —— 指数退避：base×2^(n-1)，封顶 RetryMax。
func TestBackoffSchedule(t *testing.T) {
	s := NewStore(NewMemVersions(), Options{RetryBase: time.Second, RetryMax: 5 * time.Minute})
	want := []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second,
		16 * time.Second, 32 * time.Second, 64 * time.Second, 128 * time.Second,
		256 * time.Second, 5 * time.Minute, 5 * time.Minute}
	for i, w := range want {
		if got := s.backoff(i + 1); got != w {
			t.Fatalf("backoff(%d) = %v, want %v", i+1, got, w)
		}
	}
}

// TestObservabilityAckPartial —— ACK 超时触发 partial 钩子。
func TestObservabilityAckPartial(t *testing.T) {
	s, _ := newTestStore(t, []string{"n1", "n2"}, &failingPub{})
	obs := &fakeObs{}
	s.opts.Obs = obs
	ctx := context.Background()
	v, err := s.Publish(ctx, ScopeZones, zonesOK, "t")
	if err != nil {
		t.Fatalf("publish: %v", err)
	}
	_ = s.Ack(ctx, "n1", ScopeZones, v, true, "")
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		obs.mu.Lock()
		n := obs.partials
		obs.mu.Unlock()
		if n == 1 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("AckPartial hook never fired")
}

// ---------- PG 补偿队列（PG 不可用时跳过，不挂 CI） ----------

const outboxTestDDL = `
CREATE TABLE IF NOT EXISTS config_outbox(
  id BIGSERIAL PRIMARY KEY,
  scope TEXT NOT NULL,
  version BIGINT NOT NULL,
  payload JSONB NOT NULL,
  required JSONB NOT NULL DEFAULT '[]',
  status TEXT NOT NULL DEFAULT 'pending',
  attempt INT NOT NULL DEFAULT 0,
  next_retry TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_error TEXT NOT NULL DEFAULT '',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_config_outbox_scope_version
  ON config_outbox(scope, version) WHERE status = 'pending';
CREATE INDEX IF NOT EXISTS idx_config_outbox_next_retry
  ON config_outbox(next_retry) WHERE status = 'pending';
`

// TestPGOutboxLifecycle —— PG outbox 落队/到期/退避/关单/取消全链路。
// 需 LUCID_TEST_PG_DSN；未配置或 PG 不可达时 Skip。
func TestPGOutboxLifecycle(t *testing.T) {
	dsn := os.Getenv("LUCID_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("LUCID_TEST_PG_DSN not set: skip PG outbox test")
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Skipf("bad LUCID_TEST_PG_DSN: %v", err)
	}
	cfg.ConnConfig.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Skipf("pg unavailable: %v", err)
	}
	defer pool.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := pool.Ping(ctx); err != nil {
		t.Skipf("pg unreachable: %v", err)
	}
	if _, err := pool.Exec(ctx, outboxTestDDL); err != nil {
		t.Skipf("apply outbox ddl: %v", err)
	}
	const testScope = "/lucid/test/outbox"
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM config_outbox WHERE scope=$1`, testScope)
	})

	ob := NewPGOutbox(pool)
	// ① 落队（已到期）
	e := OutboxEntry{Scope: testScope, Version: 1, Payload: []byte(`{"k":"v"}`),
		Required: []string{"n1"}, NextRetry: time.Now().Add(-time.Second)}
	if err := ob.Enqueue(ctx, &e); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	if e.ID == 0 || e.Status != OutboxPending || e.CreatedAt.IsZero() {
		t.Fatalf("entry = %+v", e)
	}
	// ② 到期扫描可见（payload/required 回读）
	due, err := ob.PendingDue(ctx, time.Now().Add(time.Minute), 10)
	if err != nil || len(due) != 1 {
		t.Fatalf("due = %+v err = %v", due, err)
	}
	if string(due[0].Payload) != `{"k":"v"}` || len(due[0].Required) != 1 || due[0].Required[0] != "n1" {
		t.Fatalf("due entry = %+v", due[0])
	}
	// ③ 重试失败：attempt 递增 + 退避顺延 + last_error 落库
	if err := ob.MarkAttempt(ctx, e.ID, time.Now().Add(time.Hour), "etcd down"); err != nil {
		t.Fatalf("mark attempt: %v", err)
	}
	due, _ = ob.PendingDue(ctx, time.Now().Add(time.Minute), 10)
	if len(due) != 0 {
		t.Fatal("entry due before backoff expiry")
	}
	pending, err := ob.ListPending(ctx)
	if err != nil || len(pending) != 1 || pending[0].Attempt != 1 || pending[0].LastError != "etcd down" {
		t.Fatalf("pending = %+v err = %v", pending, err)
	}
	// ④ 成功关单
	if err := ob.MarkDone(ctx, e.ID); err != nil {
		t.Fatalf("mark done: %v", err)
	}
	if n, _ := ob.PendingCount(ctx); n != 0 {
		t.Fatalf("pending count = %d after done", n)
	}
	// ⑤ 取消路径
	e2 := OutboxEntry{Scope: testScope, Version: 2, Payload: []byte(`{}`), NextRetry: time.Now()}
	if err := ob.Enqueue(ctx, &e2); err != nil {
		t.Fatalf("enqueue v2: %v", err)
	}
	if err := ob.Cancel(ctx, testScope, 2); err != nil {
		t.Fatalf("cancel: %v", err)
	}
	if err := ob.Cancel(ctx, testScope, 2); !errors.Is(err, ErrOutboxNotFound) {
		t.Fatalf("double cancel err = %v", err)
	}
	if n, _ := ob.PendingCount(ctx); n != 0 {
		t.Fatalf("pending count = %d after cancel", n)
	}
}
