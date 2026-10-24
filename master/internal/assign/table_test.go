package assign

import (
	"context"
	"fmt"
	"testing"
	"time"
)

var testOpts = func() Options {
	o := Options{Now: func() time.Time { return time.Unix(1_800_000_000, 0) }}
	o.fill()
	return o
}()

func TestComputePinOverridesRing(t *testing.T) {
	collectors := []Collector{{ID: "c1", Weight: 1}, {ID: "c2", Weight: 1}}
	exporters := []Exporter{{IP: "10.0.0.1"}, {IP: "10.0.0.2", PinnedTo: "c2"}}
	plan, err := computePlan(collectors, exporters, testOpts)
	if err != nil {
		t.Fatalf("compute: %v", err)
	}
	e := plan["10.0.0.2"]
	if !e.Pinned || e.Collector != "c2" {
		t.Fatalf("pin entry = %+v, want pinned to c2", e)
	}
	if plan["10.0.0.1"].Pinned {
		t.Fatal("unpinned exporter marked pinned")
	}
}

// TestComputeOverloadExclusive —— 超载 exporter（>5w fps）独占绑定（dd/07 §3）。
func TestComputeOverloadExclusive(t *testing.T) {
	collectors := []Collector{{ID: "c1", Weight: 2}, {ID: "c2", Weight: 1}, {ID: "c3", Weight: 1}}
	exporters := []Exporter{
		{IP: "10.9.9.1", RateFPS: 60000}, // 超载
		{IP: "10.9.9.2", RateFPS: 60001}, // 超载
		{IP: "10.0.0.1"},
		{IP: "10.0.0.2"},
		{IP: "10.0.0.3"},
	}
	plan, err := computePlan(collectors, exporters, testOpts)
	if err != nil {
		t.Fatalf("compute: %v", err)
	}
	holders := map[string]string{}
	for ip, e := range plan {
		if e.Overload {
			if holders[e.Collector] != "" {
				t.Fatalf("collector %s holds two overload exporters (%s, %s)", e.Collector, holders[e.Collector], ip)
			}
			holders[e.Collector] = ip
		}
	}
	// 独占 collector 不得再承接普通 exporter
	for _, e := range plan {
		if !e.Overload && holders[e.Collector] != "" {
			t.Fatalf("normal exporter %s shares exclusive collector %s with %s",
				e.Exporter, e.Collector, holders[e.Collector])
		}
	}
}

// TestComputeCapacityCap —— 单 collector 承载 ≤ weight 份额 × 1.2（全满兜底除外）。
func TestComputeCapacityCap(t *testing.T) {
	collectors := []Collector{{ID: "big", Weight: 3}, {ID: "small", Weight: 1}}
	var exporters []Exporter
	for i := 0; i < 100; i++ {
		exporters = append(exporters, Exporter{IP: fmt.Sprintf("10.3.%d.%d", i/256, i%256)})
	}
	plan, err := computePlan(collectors, exporters, testOpts)
	if err != nil {
		t.Fatalf("compute: %v", err)
	}
	load := map[string]int{}
	for _, e := range plan {
		load[e.Collector]++
	}
	// cap(big)=⌈1.2×100×3/4⌉=90, cap(small)=⌈1.2×100×1/4⌉=30
	if load["big"] > 90 || load["small"] > 30 {
		t.Fatalf("capacity exceeded: big=%d small=%d (caps 90/30)", load["big"], load["small"])
	}
	if load["big"]+load["small"] != 100 {
		t.Fatalf("total = %d, want 100", load["big"]+load["small"])
	}
}

func TestComputeNoCollectors(t *testing.T) {
	if _, err := computePlan(nil, []Exporter{{IP: "1.2.3.4"}}, testOpts); err == nil {
		t.Fatal("expected error with no collectors")
	}
}

// TestAssignerDebounce —— 30s 防抖窗口内多次触发合并为一次计算。
func TestAssignerDebounce(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	opts := Options{Debounce: 50 * time.Millisecond, Now: func() time.Time { return now }}
	opts.fill()
	pubs := 0
	a := New(opts)
	a.Publisher = nopPubFunc(func(_ context.Context, _ Table) error { pubs++; return nil })
	a.Collectors = func(context.Context) ([]Collector, error) {
		return []Collector{{ID: "c1", Weight: 1}}, nil
	}
	a.Exporters = func(context.Context) ([]Exporter, error) {
		return []Exporter{{IP: "10.0.0.1"}}, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { a.Run(ctx); close(done) }()
	for i := 0; i < 10; i++ {
		a.Trigger()
	}
	time.Sleep(200 * time.Millisecond)
	cancel()
	<-done
	if pubs != 1 {
		t.Fatalf("publishes = %d, want 1 (debounce merged)", pubs)
	}
	cur := a.Current()
	if cur.Version != 1 || len(cur.Entries) != 1 {
		t.Fatalf("current table = v%d %d entries", cur.Version, len(cur.Entries))
	}
}

// TestAssignerVersionMonotonic —— 多轮发布版本单调递增。
func TestAssignerVersionMonotonic(t *testing.T) {
	opts := Options{Debounce: time.Millisecond}
	opts.fill()
	last := uint64(0)
	a := New(opts)
	a.Publisher = nopPubFunc(func(_ context.Context, tbl Table) error {
		if tbl.Version <= last {
			t.Fatalf("version not monotonic: %d after %d", tbl.Version, last)
		}
		last = tbl.Version
		return nil
	})
	a.Collectors = func(context.Context) ([]Collector, error) {
		return []Collector{{ID: "c1", Weight: 1}}, nil
	}
	a.Exporters = func(context.Context) ([]Exporter, error) {
		return []Exporter{{IP: "10.0.0.1"}}, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	go a.Run(ctx)
	for i := 0; i < 3; i++ {
		a.Trigger()
		time.Sleep(30 * time.Millisecond)
	}
	cancel()
	if last != 3 {
		t.Fatalf("last version = %d, want 3", last)
	}
}

type nopPubFunc func(context.Context, Table) error

func (f nopPubFunc) PublishAssign(ctx context.Context, t Table) error { return f(ctx, t) }

// TestSubscribeGetsCurrentAndUpdates.
func TestSubscribeGetsCurrentAndUpdates(t *testing.T) {
	opts := Options{Debounce: time.Millisecond}
	opts.fill()
	a := New(opts)
	a.Publisher = NopPublisher{}
	a.Collectors = func(context.Context) ([]Collector, error) {
		return []Collector{{ID: "c1", Weight: 1}}, nil
	}
	a.Exporters = func(context.Context) ([]Exporter, error) {
		return []Exporter{{IP: "10.0.0.1"}}, nil
	}
	if err := a.ComputeOnce(context.Background()); err != nil {
		t.Fatalf("compute once: %v", err)
	}
	ch, cancel := a.Subscribe()
	defer cancel()
	select {
	case tbl := <-ch:
		if tbl.Version != 1 {
			t.Fatalf("first push version = %d", tbl.Version)
		}
	case <-time.After(time.Second):
		t.Fatal("no initial table pushed")
	}
}
