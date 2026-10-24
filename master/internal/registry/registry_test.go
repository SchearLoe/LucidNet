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

// TestNICFromMbps —— proto NicSpec（Mbps 口径）→ registry NIC（Gbps 口径）换算：
// 1 Gbps = 1000 Mbps，向下取整；不足 1 Gbps 记 0（权重计算忽略，docs/09 §3 NicSpec）。
func TestNICFromMbps(t *testing.T) {
	cases := []struct {
		mbps uint32
		want uint32
	}{
		{25000, 25},   // 25G 基准口
		{100000, 100}, // 100G
		{1000, 1},     // 1G
		{400, 0},      // 不足 1G → 0（权重忽略）
		{0, 0},        // 链路未协商
	}
	for _, c := range cases {
		nic := NICFromMbps("eth0", c.mbps)
		if nic.SpeedGbps != c.want {
			t.Fatalf("NICFromMbps(%d).SpeedGbps = %d, want %d", c.mbps, nic.SpeedGbps, c.want)
		}
		if nic.Name != "eth0" {
			t.Fatalf("name = %q", nic.Name)
		}
	}
}

// TestWeightNICsConsumeAndFallback —— 注册消费 NodeInfo.nics 进权重：
// Mbps 换算聚合（取最大上行口）与未上报 25G 基准兜底（向后兼容旧版 Broker）。
func TestWeightNICsConsumeAndFallback(t *testing.T) {
	cases := []struct {
		name string
		n    Node
		want float64
	}{
		{"25G 上报 = 基准", Node{Cores: 24, NICs: []NIC{NICFromMbps("eth0", 25000)}}, 1.0},
		{"100G 上报 = 4 倍", Node{Cores: 24, NICs: []NIC{NICFromMbps("eth0", 100000)}}, 4.0},
		{"2 口聚合取最大", Node{Cores: 24, NICs: []NIC{
			NICFromMbps("eth0", 25000), NICFromMbps("eth1", 50000)}}, 2.0},
		{"不足 1G 忽略 → 兜底", Node{Cores: 24, NICs: []NIC{NICFromMbps("mgmt0", 400)}}, 1.0},
		{"零速率口忽略", Node{Cores: 24, NICs: []NIC{
			{Name: "eth0", SpeedGbps: 0}, NICFromMbps("eth1", 25000)}}, 1.0},
		{"空 NIC 列表兜底", Node{Cores: 24, NICs: []NIC{}}, 1.0},
		{"未上报 nics 兜底（旧版 Broker）", Node{Cores: 24}, 1.0},
	}
	for _, c := range cases {
		if got := c.n.Weight(); got != c.want {
			t.Fatalf("%s: weight = %f, want %f", c.name, got, c.want)
		}
	}
}

// TestRegisterConsumesNICs —— 注册落 NIC 档案（PG nodes.nics 同构），心跳 nics 变化
// 顺带更新并触发权重重算；无变化幂等。
func TestRegisterConsumesNICs(t *testing.T) {
	clock := &fakeClock{t: time.Unix(1_800_000_000, 0)}
	changes := 0
	reg := NewRegistry(NewMemStore(), Options{
		Now:      clock.Now,
		OnChange: func() { changes++ },
	})
	ctx := context.Background()
	n, err := reg.Register(ctx, Node{
		ID: "c1", Role: RoleCollector, Cores: 24,
		NICs: []NIC{NICFromMbps("eth0", 50000)}, // 50G → weight = 2.0
	})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if got := n.Weight(); got != 2.0 {
		t.Fatalf("weight after register = %f, want 2.0", got)
	}
	stored, _ := reg.Get(ctx, "c1")
	if len(stored.NICs) != 1 || stored.NICs[0].Name != "eth0" || stored.NICs[0].SpeedGbps != 50 {
		t.Fatalf("stored nics = %+v", stored.NICs)
	}
	if changes != 1 {
		t.Fatalf("changes = %d, want 1 (register)", changes)
	}
	// 心跳上报相同网卡 → 幂等（不触发重算）
	if err := reg.UpdateNICs(ctx, "c1", []NIC{{Name: "eth0", SpeedGbps: 50}}); err != nil {
		t.Fatalf("update nics same: %v", err)
	}
	if changes != 1 {
		t.Fatalf("changes after idempotent update = %d, want 1", changes)
	}
	// 心跳上报网卡升级 → 档案更新 + 权重重算
	if err := reg.UpdateNICs(ctx, "c1", []NIC{NICFromMbps("eth0", 100000)}); err != nil {
		t.Fatalf("update nics: %v", err)
	}
	stored, _ = reg.Get(ctx, "c1")
	if got := stored.Weight(); got != 4.0 {
		t.Fatalf("weight after nic upgrade = %f, want 4.0", got)
	}
	if changes != 2 {
		t.Fatalf("changes = %d, want 2", changes)
	}
	// 空上报忽略（保留档案，25G 兜底语义不被清空）
	if err := reg.UpdateNICs(ctx, "c1", nil); err != nil {
		t.Fatalf("update nics empty: %v", err)
	}
	stored, _ = reg.Get(ctx, "c1")
	if len(stored.NICs) != 1 || stored.Weight() != 4.0 {
		t.Fatalf("empty update must not clear nics: %+v", stored)
	}
	// 未注册节点报错
	if err := reg.UpdateNICs(ctx, "ghost", []NIC{{Name: "eth0", SpeedGbps: 25}}); err == nil {
		t.Fatal("update nics for unknown node accepted")
	}
}

// TestParseMetricsJSONNICs —— metrics_json.nics 解析（心跳网卡变化上报契约）。
func TestParseMetricsJSONNICs(t *testing.T) {
	m, err := ParseMetricsJSON([]byte(`{"version":"v1","nics":[{"name":"eth0","speed_gbps":25}]}`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(m.NICs) != 1 || m.NICs[0].Name != "eth0" || m.NICs[0].SpeedGbps != 25 {
		t.Fatalf("nics = %+v", m.NICs)
	}
	// 空/旧版载荷无 nics 键 → 空切片（不触发档案更新）
	m, err = ParseMetricsJSON([]byte(`{"version":"v0"}`))
	if err != nil || len(m.NICs) != 0 {
		t.Fatalf("legacy payload nics = %+v err = %v", m.NICs, err)
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
