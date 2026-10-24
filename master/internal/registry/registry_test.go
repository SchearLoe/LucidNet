package registry

import (
	"context"
	"errors"
	"testing"
	"time"
)

type fakeClock struct{ t time.Time }

func (c *fakeClock) Now() time.Time      { return c.t }
func (c *fakeClock) Add(d time.Duration) { c.t = c.t.Add(d) }

type recordingMirror struct{ deleted []string }

func (m *recordingMirror) Put(_ context.Context, _ string, _ []byte) error { return nil }
func (m *recordingMirror) Delete(_ context.Context, id string) error {
	m.deleted = append(m.deleted, id)
	return nil
}
func (m *recordingMirror) KeepAlive(context.Context, string) error { return nil }

// TestFailureDetection —— 失联 30s 标 degraded、90s 判 offline 并触发再平衡
// （docs/hld/07 §4）。
func TestFailureDetection(t *testing.T) {
	clock := &fakeClock{t: time.Unix(1_800_000_000, 0)}
	events := []EventType{}
	mirror := &recordingMirror{}
	reg := NewRegistry(NewMemStore(), Options{
		DegradedAfter: 30 * time.Second,
		OfflineAfter:  90 * time.Second,
		ScanEvery:     5 * time.Second,
		Now:           clock.Now,
		Mirror:        mirror,
		OnEvent:       func(ev NodeEvent) { events = append(events, ev.Type) },
	})
	ctx := context.Background()
	n, err := reg.Register(ctx, Node{ID: "c1", Role: RoleCollector, Host: "10.0.0.1", Cores: 24})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if n.State != StateOnline {
		t.Fatalf("state = %s", n.State)
	}

	clock.Add(31 * time.Second)
	reg.scanOnce(ctx)
	got, _ := reg.Get(ctx, "c1")
	if !got.Degraded {
		t.Fatal("31s silence: degraded not set")
	}

	clock.Add(60 * time.Second) // 累计 91s
	reg.scanOnce(ctx)
	got, _ = reg.Get(ctx, "c1")
	if got.State != StateOffline {
		t.Fatalf("90s silence: state = %s, want offline", got.State)
	}
	if len(mirror.deleted) != 1 || mirror.deleted[0] != "c1" {
		t.Fatalf("mirror deletes = %v", mirror.deleted)
	}

	// offline → 心跳恢复 → online
	clock.Add(1 * time.Second)
	if err := reg.Heartbeat(ctx, "c1", clock.Now(), "v1.2.3"); err != nil {
		t.Fatalf("hb after offline: %v", err)
	}
	got, _ = reg.Get(ctx, "c1")
	if got.State != StateOnline || got.Degraded {
		t.Fatalf("recovered node = %+v", got)
	}
	if got.Version != "v1.2.3" {
		t.Fatalf("version = %q", got.Version)
	}
	// 事件序列：degraded → offline → online
	want := []EventType{EventRegistered, EventDegraded, EventOffline, EventOnline}
	if len(events) != len(want) {
		t.Fatalf("events = %v, want %v", events, want)
	}
	for i := range want {
		if events[i] != want[i] {
			t.Fatalf("events = %v, want %v", events, want)
		}
	}
}

// TestDrainExcludesFromAssign —— draining collector 不参与分配（docs/dd/07 §2）。
func TestDrainExcludesFromAssign(t *testing.T) {
	reg := NewRegistry(NewMemStore(), Options{Now: (&fakeClock{t: time.Unix(1_800_000_000, 0)}).Now})
	ctx := context.Background()
	_, _ = reg.Register(ctx, Node{ID: "c1", Role: RoleCollector, Cores: 24})
	_, _ = reg.Register(ctx, Node{ID: "c2", Role: RoleCollector, Cores: 48})

	cands, _ := reg.AssignCandidates(ctx)
	if len(cands) != 2 {
		t.Fatalf("candidates = %d", len(cands))
	}
	if err := reg.Drain(ctx, "c1"); err != nil {
		t.Fatalf("drain: %v", err)
	}
	cands, _ = reg.AssignCandidates(ctx)
	if len(cands) != 1 || cands[0].ID != "c2" {
		t.Fatalf("candidates after drain = %v", cands)
	}
	// 排水完成后人工置维护
	if err := reg.SetState(ctx, "c1", StateMaintenance); err != nil {
		t.Fatalf("maintenance: %v", err)
	}
	// 非法状态拒绝
	if err := reg.SetState(ctx, "c1", "bogus"); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("invalid state err = %v", err)
	}
}

// TestWeight —— weight = cores/24 × nic/25G（docs/dd/07 §2）。
func TestWeight(t *testing.T) {
	cases := []struct {
		n    Node
		want float64
	}{
		{Node{Cores: 24}, 1.0},                               // 无网卡 → nic 因子 1
		{Node{Cores: 24, NICs: []NIC{{SpeedGbps: 50}}}, 2.0}, // 2×25G
		{Node{Cores: 12, NICs: []NIC{{SpeedGbps: 25}}}, 0.5}, //
		{Node{Cores: 0}, 0.05},                               // 下限
		{Node{Cores: 24, WeightOverride: 7}, 7.0},            // 覆盖优先
	}
	for _, c := range cases {
		if got := c.n.Weight(); got != c.want {
			t.Fatalf("weight(%+v) = %f, want %f", c.n, got, c.want)
		}
	}
}

// TestExporterLifecycle —— 观测窗口与 pin。
func TestExporterLifecycle(t *testing.T) {
	clock := &fakeClock{t: time.Unix(1_800_000_000, 0)}
	reg := NewRegistry(NewMemStore(), Options{Now: clock.Now})
	ctx := context.Background()
	_ = reg.ObserveExporters(ctx, "c1", []ExporterObs{{IP: "10.1.1.1", FPS: 1234}})
	clock.Add(2 * time.Minute)
	list, err := reg.ActiveExporters(ctx, 5*time.Minute)
	if err != nil || len(list) != 1 {
		t.Fatalf("active = %v err=%v", list, err)
	}
	clock.Add(4 * time.Minute) // 超出窗口
	list, _ = reg.ActiveExporters(ctx, 5*time.Minute)
	if len(list) != 0 {
		t.Fatalf("stale exporter still active: %v", list)
	}
	// pin
	_, _ = reg.Register(ctx, Node{ID: "c1", Role: RoleCollector})
	if err := reg.PinExporter(ctx, "10.1.1.1", "c1"); err != nil {
		t.Fatalf("pin: %v", err)
	}
	e, _ := reg.Exporters(ctx)
	if e[0].PinnedTo != "c1" {
		t.Fatalf("pin = %q", e[0].PinnedTo)
	}
}
