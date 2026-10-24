package detector

import (
	"errors"
	"testing"
	"time"

	"github.com/SchearLoe/lucidnet/analytics/internal/fsm"
	"github.com/SchearLoe/lucidnet/shared"
)

// manualClock —— 注入时间源（确定性单测）。
type manualClock struct{ t time.Time }

func (c *manualClock) Now() time.Time          { return c.t }
func (c *manualClock) Set(sec int64)           { c.t = time.Unix(sec, 0).UTC() }
func (c *manualClock) Advance(d time.Duration) { c.t = c.t.Add(d) }

// evCollector —— fsm Emitter 收集器。
type evCollector struct{ events []*shared.AttackEvent }

func (c *evCollector) EmitAttack(ev *shared.AttackEvent) { c.events = append(c.events, ev) }

func (c *evCollector) of(t shared.AttackType, st shared.AttackStatus) []*shared.AttackEvent {
	var out []*shared.AttackEvent
	for _, ev := range c.events {
		if ev.AttackType == t && ev.Status == st {
			out = append(out, ev)
		}
	}
	return out
}

// staticBaseline —— 固定基线桩。
type staticBaseline struct{ bps float64 }

func (b staticBaseline) ZoneBps(int32) (float64, bool) { return b.bps, true }

// harness —— 检测引擎 + 共享时钟 + 事件收集。
type harness struct {
	clk *manualClock
	col *evCollector
	mgr *fsm.Manager
	d   *Detector
}

func newHarness(cfg Config) *harness {
	clk := &manualClock{t: time.Unix(10_000, 0).UTC()}
	cfg.Clock = clk.Now
	col := &evCollector{}
	fcfg := fsm.DefaultConfig()
	fcfg.Now = clk.Now
	h := &harness{clk: clk, col: col, mgr: fsm.New(fcfg, col)}
	h.d = New(cfg, h.mgr)
	return h
}

// quietAnomaly —— 关闭波动规则（非 ANOMALY 用例防空秒骤降噪声）。
func quietAnomaly(cfg Config) Config {
	cfg.AnomalyMinSamples = 1 << 30
	return cfg
}

// rec —— FlowRecord 构造器（默认 TCP SYN 单包、zone 命中 dst 面）。
func rec(zone int32, tsSec int64, mutate func(*shared.FlowRecord)) *shared.FlowRecord {
	r := &shared.FlowRecord{
		TimeStartMs: tsSec * 1000,
		Exporter:    "exp-test",
		IPVersion:   4,
		Proto:       protoTCP,
		SrcIP:       v4IP(10, 0, 0, 1),
		DstIP:       v4IP(10, 1, 2, 3),
		SrcPort:     40000,
		DstPort:     443,
		Packets:     1,
		Bytes:       100,
		TCPFlags:    flagSYN,
		ZoneID:      zone,
		ZoneSide:    uint8(shared.ZoneSideDst),
		IfRole:      shared.IfRoleInBoundary | shared.IfRoleOutBoundary,
		SampleRate:  1,
	}
	if mutate != nil {
		mutate(r)
	}
	return r
}

func v4IP(a, b, c, d byte) [16]byte {
	var ip [16]byte
	ip[10], ip[11] = 0xff, 0xff
	ip[12], ip[13], ip[14], ip[15] = a, b, c, d
	return ip
}

func v6IP(seg [8]byte, suffix byte) [16]byte {
	var ip [16]byte
	copy(ip[:8], seg[:])
	ip[15] = suffix
	return ip
}

// step —— 推进一秒：置钟 → 加记录 → 检测 Tick + FSM Tick（评估恒落后 2s，确定性）。
func (h *harness) step(sec int64, recs ...*shared.FlowRecord) {
	h.clk.Set(sec)
	for _, r := range recs {
		if err := h.d.Add(r); err != nil {
			panic(err)
		}
	}
	h.d.Tick()
	h.mgr.Tick()
}

// drain —— 置钟并推进全部 Tick，将最后 2s 关闭评估。
func (h *harness) drain(sec int64) {
	h.clk.Set(sec)
	h.d.Tick()
	h.mgr.Tick()
}

func TestAddNilRecord(t *testing.T) {
	t.Parallel()
	h := newHarness(DefaultConfig())
	if err := h.d.Add(nil); !errors.Is(err, errNilRecord) {
		t.Fatalf("nil record should return errNilRecord, got %v", err)
	}
}

func TestZoneZeroSkipsDetection(t *testing.T) {
	t.Parallel()
	h := newHarness(DefaultConfig())
	h.step(10_000, rec(0, 10_000, nil))
	if st := h.d.Stats(); st.NoZone != 1 || h.d.ZoneCount() != 0 {
		t.Fatalf("zone_id=0 must skip detection engine: %+v zones=%d", st, h.d.ZoneCount())
	}
}

func TestStaleRecordDropped(t *testing.T) {
	t.Parallel()
	h := newHarness(DefaultConfig())
	h.clk.Set(10_100)
	if err := h.d.Add(rec(11, 10_000, nil)); err != nil { // 100s 迟到 > 60s
		t.Fatal(err)
	}
	if st := h.d.Stats(); st.StaleDrop != 1 {
		t.Fatalf("stale record should be dropped, stats=%+v", st)
	}
}

func TestZoneIdlePrune(t *testing.T) {
	t.Parallel()
	h := newHarness(quietAnomaly(DefaultConfig()))
	h.step(10_000, rec(12, 10_000, nil))
	if h.d.ZoneCount() != 1 {
		t.Fatal("zone should exist")
	}
	h.drain(10_000 + 10*60 + 30) // 空闲 >10min 且无活跃攻击
	if h.d.ZoneCount() != 0 {
		t.Fatalf("idle zone should be pruned, zones=%d", h.d.ZoneCount())
	}
}

// TestSecBucketCounting —— flag/协议计数与 newflows LRU（追加路径，dd/03 §3.3）。
func TestSecBucketCounting(t *testing.T) {
	t.Parallel()
	h := newHarness(DefaultConfig())
	base := int64(10_000)
	h.step(base, rec(13, base, func(r *shared.FlowRecord) {
		r.TCPFlags = flagSYN | flagACK
		r.Packets = 10
		r.Bytes = 500
	}))
	h.step(base, rec(13, base, func(r *shared.FlowRecord) {
		r.SrcIP = v4IP(10, 0, 0, 2)
	}))
	h.step(base, rec(13, base, func(r *shared.FlowRecord) {
		r.SrcIP = v4IP(10, 0, 0, 2) // 同 (src,dst,proto) 复用 → 非新流
		r.DstPort = 80
	}))
	h.step(base, rec(13, base, func(r *shared.FlowRecord) {
		r.Proto = protoUDP
		r.SrcIP = v4IP(10, 0, 0, 3)
	}))
	z := h.d.zones[13]
	b := z.bucketAt(base)
	if b.SynAck != 10 || b.TCPPkts != 12 || b.UDPPkts != 1 || b.Pps != 13 {
		t.Fatalf("bucket counters wrong: %+v", b)
	}
	if b.Bps != (500+100+100+100)*8 {
		t.Fatalf("bps = %d", b.Bps)
	}
	if b.NewFlows != 3 { // 10.0.0.1 / 10.0.0.2 / 10.0.0.3(udp)；第三包复用键
		t.Fatalf("newflows = %d, want 3", b.NewFlows)
	}
}

// TestSrcAggOverflow —— 50,000 上限降级 Count-Min Sketch 桩（小上限模拟）。
func TestSrcAggOverflow(t *testing.T) {
	t.Parallel()
	cfg := DefaultConfig()
	cfg.SrcAggCap = 5
	h := newHarness(cfg)
	base := int64(11_000)
	var recs []*shared.FlowRecord
	for i := 0; i < 7; i++ {
		src := byte(i)
		recs = append(recs, rec(14, base, func(r *shared.FlowRecord) { r.SrcIP = v4IP(192, 0, 2, src) }))
	}
	h.step(base, recs...)
	st := h.d.Stats()
	if st.SrcAggOverflow != 2 {
		t.Fatalf("overflow count = %d, want 2", st.SrcAggOverflow)
	}
	z := h.d.zones[14]
	if len(z.srcAgg) != 5 || !z.srcOverflow {
		t.Fatalf("srcAgg len=%d overflow=%v, want 5/true", len(z.srcAgg), z.srcOverflow)
	}
	// 原有源继续精算
	h.step(base+1, rec(14, base+1, func(r *shared.FlowRecord) { r.SrcIP = v4IP(192, 0, 2, 0) }))
	if got := z.srcAgg[srcHash(rec(14, 0, func(r *shared.FlowRecord) { r.SrcIP = v4IP(192, 0, 2, 0) }))].Pkts; got != 2 {
		t.Fatalf("existing source should keep exact accounting, pkts=%d", got)
	}
}

// TestPortSet16 —— 定容端口集合。
func TestPortSet16(t *testing.T) {
	t.Parallel()
	var p PortSet16
	for i := uint32(0); i < 20; i++ {
		p.Add(1000 + i)
	}
	p.Add(1005) // 已存在
	if got := p.Ports(); len(got) != 16 || got[0] != 1000 {
		t.Fatalf("port set cap broken: %v", got)
	}
}
