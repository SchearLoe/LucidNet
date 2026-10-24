package config

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// fakeTarget / fakeSink / failingPub —— 发布链路测试桩。
type fakeTarget struct{ nodes []string }

func (f *fakeTarget) ResolveTargets(_ context.Context, _ string) ([]string, error) {
	return f.nodes, nil
}

type fakeSink struct {
	sent []string // nodeID
}

func (f *fakeSink) SendReload(_ context.Context, nodeID, _, _ string, _ uint64) error {
	f.sent = append(f.sent, nodeID)
	return nil
}

type failingPub struct{ fails int }

func (f *failingPub) Publish(context.Context, string, Envelope) error {
	if f.fails > 0 {
		f.fails--
		return errors.New("etcd down")
	}
	return nil
}

func newTestStore(t *testing.T, nodes []string, pub Publisher) (*Store, *fakeSink) {
	t.Helper()
	sink := &fakeSink{}
	opts := Options{
		Publisher:    pub,
		Targets:      &fakeTarget{nodes: nodes},
		CmdSink:      sink,
		AckTimeout:   50 * time.Millisecond,
		KeepVersions: 3,
	}
	return NewStore(NewMemVersions(), opts), sink
}

var zonesOK = []byte(`[{"id":1,"name":"a","tenant":"t1","ips":[{"prefix":"10.0.0.0/24"}]}]`)
var zonesOK2 = []byte(`[{"id":1,"name":"a","tenant":"t1","ips":[{"prefix":"10.0.2.0/24"}]}]`)

func TestPublishVersioningAndAck(t *testing.T) {
	s, sink := newTestStore(t, []string{"n1", "n2"}, &failingPub{})
	ctx := context.Background()
	v1, err := s.Publish(ctx, ScopeZones, zonesOK, "tester")
	if err != nil {
		t.Fatalf("publish: %v", err)
	}
	if v1 != 1 {
		t.Fatalf("v1 = %d", v1)
	}
	if len(sink.sent) != 2 {
		t.Fatalf("reload sent to %v", sink.sent)
	}
	// 全 ACK → active
	if err := s.Ack(ctx, "n1", ScopeZones, v1, true, ""); err != nil {
		t.Fatalf("ack n1: %v", err)
	}
	_ = s.Ack(ctx, "n2", ScopeZones, v1, true, "")
	v, _ := s.GetVersion(ctx, ScopeZones, v1)
	if v.State != VersionActive {
		t.Fatalf("state = %s, want active", v.State)
	}
	// 迟到 ACK 幂等忽略
	_ = s.Ack(ctx, "n1", ScopeZones, v1, true, "")
	// 第二次发布 version++
	v2, _ := s.Publish(ctx, ScopeZones, zonesOK2, "tester")
	if v2 != 2 {
		t.Fatalf("v2 = %d", v2)
	}
}

func TestPublishValidationRejected(t *testing.T) {
	s, _ := newTestStore(t, []string{"n1"}, &failingPub{})
	// R2 重叠拒绝
	bad := []byte(`[{"id":1,"name":"a","tenant":"t","ips":[{"prefix":"10.0.0.0/24"}]},
	                {"id":2,"name":"b","tenant":"t","ips":[{"prefix":"10.0.0.1/32"}]}]`)
	if _, err := s.Publish(context.Background(), ScopeZones, bad, "t"); err == nil {
		t.Fatal("overlapping zones published")
	}
	// 非法作用域
	if _, err := s.Publish(context.Background(), "/nope", zonesOK, "t"); err == nil {
		t.Fatal("invalid scope published")
	}
	// 分配表作用域拒绝外部发布
	if _, err := s.Publish(context.Background(), ScopeAssignFlow, zonesOK, "t"); err == nil {
		t.Fatal("assign flow published via config path")
	}
}

func TestPublishEtcdFailureReadOnlyAndRetry(t *testing.T) {
	pub := &failingPub{fails: 1}
	s, _ := newTestStore(t, []string{"n1"}, pub)
	go s.Run(context.Background())
	defer s.Close()
	_, err := s.Publish(context.Background(), ScopeZones, zonesOK, "t")
	if err == nil || !strings.Contains(err.Error(), "etcd down") {
		t.Fatalf("err = %v, want etcd down", err)
	}
	v, gerr := s.GetVersion(context.Background(), ScopeZones, 1)
	if gerr != nil {
		t.Fatalf("get version: %v", gerr)
	}
	if v.State != VersionFailed {
		t.Fatalf("state = %s, want failed", v.State)
	}
	// 补偿重试成功后转 published
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		v, _ = s.GetVersion(context.Background(), ScopeZones, 1)
		if v.State == VersionPublished {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("state = %s, want published after retry", v.State)
}

func TestAckTimeoutMarksPartial(t *testing.T) {
	s, _ := newTestStore(t, []string{"n1", "n2"}, &failingPub{})
	ctx := context.Background()
	v, err := s.Publish(ctx, ScopeZones, zonesOK, "t")
	if err != nil {
		t.Fatalf("publish: %v", err)
	}
	_ = s.Ack(ctx, "n1", ScopeZones, v, true, "")
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		ver, _ := s.GetVersion(ctx, ScopeZones, v)
		if ver.State == VersionPartial {
			return // 180s 未全 ACK → partial（测试窗口 50ms）
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("version never marked partial")
}

func TestRollbackCreatesNewVersion(t *testing.T) {
	s, _ := newTestStore(t, nil, &failingPub{})
	ctx := context.Background()
	s.Publish(ctx, ScopeZones, zonesOK, "t")
	s.Publish(ctx, ScopeZones, zonesOK2, "t")
	newV, err := s.Rollback(ctx, ScopeZones, 1, "tester")
	if err != nil {
		t.Fatalf("rollback: %v", err)
	}
	if newV != 3 {
		t.Fatalf("rollback version = %d, want 3 (monotonic)", newV)
	}
	v, _ := s.GetVersion(ctx, ScopeZones, 3)
	if string(v.DataJSON) != string(zonesOK) {
		t.Fatalf("rollback data mismatch: %s", v.DataJSON)
	}
	// 回滚到当前/未来版本拒绝
	if _, err := s.Rollback(ctx, ScopeZones, 3, "t"); err == nil {
		t.Fatal("rollback to latest accepted")
	}
}

func TestRetentionTrim(t *testing.T) {
	s, _ := newTestStore(t, nil, &failingPub{}) // KeepVersions=3
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		if _, err := s.Publish(ctx, ScopeZones, zonesOK, "t"); err != nil {
			t.Fatalf("publish %d: %v", i, err)
		}
	}
	versions, _ := s.ListVersions(ctx, ScopeZones, 0)
	if len(versions) != 3 {
		t.Fatalf("kept %d versions, want 3", len(versions))
	}
	if versions[0].Version != 5 {
		t.Fatalf("newest = v%d, want v5", versions[0].Version)
	}
}

func TestNoTargetsMeansReadOnly(t *testing.T) {
	s := NewStore(NewMemVersions(), Options{}) // 未装配 Targets → 只读保护
	if _, err := s.Publish(context.Background(), ScopeZones, zonesOK, "t"); !errors.Is(err, ErrReadOnly) {
		t.Fatalf("err = %v, want ErrReadOnly", err)
	}
}

func TestRoleConfigJSON(t *testing.T) {
	s, _ := newTestStore(t, nil, &failingPub{})
	ctx := context.Background()
	s.Publish(ctx, ScopeZones, zonesOK, "t")
	s.Publish(ctx, CollectorScope("c-1"), []byte(`{"ports":[9995]}`), "t")
	js, err := s.RoleConfigJSON(ctx, "collector", "c-1")
	if err != nil {
		t.Fatalf("role config: %v", err)
	}
	if !strings.Contains(js, ScopeZones) || !strings.Contains(js, CollectorScope("c-1")) {
		t.Fatalf("role config missing scopes: %s", js)
	}
	if !strings.Contains(js, "/lucid/assign/flow") {
		t.Fatalf("collector role config missing assign hint: %s", js)
	}
}
