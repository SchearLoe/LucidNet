package detector

import (
	"testing"

	"github.com/SchearLoe/lucidnet/shared"
)

// synSecondSpec —— 一个攻击秒的构造参数。
type synSecondSpec struct {
	flows    int     // 该秒新流数（每流 1 条记录 1 包）
	synShare float64 // SYN 占 (SYN+SYNACK) 比例
	bytesPer uint64  // 每流字节数
}

// synSecond —— 灌入一个秒的 SYN/SYNACK 混合流量（源地址随秒变化，保证跨秒新流）。
func synSecond(h *harness, zone int32, sec int64, s synSecondSpec) {
	var recs []*shared.FlowRecord
	for i := 0; i < s.flows; i++ {
		i := i
		r := rec(zone, sec, func(r *shared.FlowRecord) {
			r.SrcIP = v4IP(10, byte(i>>8), byte(i), byte(sec%251))
			r.Bytes = s.bytesPer
			if float64(i) < s.synShare*float64(s.flows) {
				r.TCPFlags = flagSYN // 纯 SYN
			} else {
				r.TCPFlags = flagSYN | flagACK // SYN+ACK
			}
		})
		recs = append(recs, r)
	}
	h.step(sec, recs...)
}

func TestSYNFloodTableDriven(t *testing.T) {
	t.Parallel()
	// 基线 1,000 bps → 比率条件需 bps ≥ 3,000
	baseline := staticBaseline{bps: 1_000}

	type want struct {
		candidate bool
		confirmed bool
	}
	cases := []struct {
		name     string
		baseline BaselineProvider
		seconds  []synSecondSpec // 依次为攻击秒；nil=无
		want     want
	}{
		{
			name:     "hit two consecutive seconds confirms",
			baseline: baseline,
			seconds:  []synSecondSpec{{flows: 6000, synShare: 1.0, bytesPer: 100}, {flows: 6000, synShare: 0.9, bytesPer: 100}},
			want:     want{candidate: true, confirmed: true},
		},
		{
			name:     "ratio below threshold no fire",
			baseline: baseline,
			seconds:  []synSecondSpec{{flows: 6000, synShare: 0.5, bytesPer: 100}, {flows: 6000, synShare: 0.5, bytesPer: 100}, {flows: 6000, synShare: 0.5, bytesPer: 100}},
			want:     want{},
		},
		{
			name:     "newflows below absolute threshold no fire",
			baseline: baseline,
			seconds:  []synSecondSpec{{flows: 4000, synShare: 1.0, bytesPer: 100}, {flows: 4000, synShare: 1.0, bytesPer: 100}},
			want:     want{},
		},
		{
			name:     "bps below baseline ratio no fire",
			baseline: staticBaseline{bps: 1_000_000}, // ×3=3M bps，实际 6000×100×8=4.8M? bytes=1 → 48k
			seconds:  []synSecondSpec{{flows: 6000, synShare: 1.0, bytesPer: 1}, {flows: 6000, synShare: 1.0, bytesPer: 1}},
			want:     want{},
		},
		{
			name:     "cold start no baseline abs-only fallback fires",
			baseline: nil, // NoneBaseline：bps 条件自动通过
			seconds:  []synSecondSpec{{flows: 6000, synShare: 1.0, bytesPer: 1}, {flows: 6000, synShare: 1.0, bytesPer: 1}},
			want:     want{candidate: true, confirmed: true},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := quietAnomaly(DefaultConfig())
			if tc.baseline != nil {
				cfg.Baseline = tc.baseline
			}
			h := newHarness(cfg)
			base := int64(12_000)
			for i, s := range tc.seconds {
				synSecond(h, 21, base+int64(i), s)
			}
			h.drain(base + int64(len(tc.seconds)) + 2) // 关闭最后的攻击秒

			cand := h.col.of(shared.AttackSYNFlood, shared.AttackCandidate)
			conf := h.col.of(shared.AttackSYNFlood, shared.AttackConfirmed)
			if (len(cand) > 0) != tc.want.candidate {
				t.Fatalf("candidate events = %d, want present=%v", len(cand), tc.want.candidate)
			}
			if (len(conf) > 0) != tc.want.confirmed {
				t.Fatalf("confirmed events = %d, want present=%v", len(conf), tc.want.confirmed)
			}
			if tc.want.confirmed {
				ev := conf[len(conf)-1]
				if ev.ZoneID != 21 || ev.TopSources == nil || ev.EvidenceJSON == "" {
					t.Fatalf("confirmed event missing evidence: %+v", ev)
				}
			}
		})
	}
}

// TestSYNFloodJitterNotConfirmed —— 命中间隔 ≥3s（1/3 占空比）：候选刷新但永不确认。
func TestSYNFloodJitterNotConfirmed(t *testing.T) {
	t.Parallel()
	cfg := quietAnomaly(DefaultConfig())
	h := newHarness(cfg)
	base := int64(13_000)
	hit := synSecondSpec{flows: 6000, synShare: 1.0, bytesPer: 100}
	for cycle := 0; cycle < 4; cycle++ {
		s := base + int64(cycle)*3
		synSecond(h, 22, s, hit) // 命中秒
		h.step(s + 1)            // 空秒（无记录）
		h.step(s + 2)
	}
	h.drain(base + 12 + 2)

	if got := len(h.col.of(shared.AttackSYNFlood, shared.AttackCandidate)); got == 0 {
		t.Fatal("single hits should raise candidate")
	}
	if got := len(h.col.of(shared.AttackSYNFlood, shared.AttackConfirmed)); got != 0 {
		t.Fatalf("jitter (1-in-3) must not confirm, got %d confirm events", got)
	}
	// 候选静默关闭后无活跃攻击
	h.drain(base + 20)
	if h.mgr.ActiveCount() != 0 {
		t.Fatalf("candidate should close silently after 3s without confirm, active=%d", h.mgr.ActiveCount())
	}
}

// TestSYNFloodSingleHitThenQuiet —— 单秒命中：候选 3s 未再命中静默关闭（不外发关闭事件）。
func TestSYNFloodSingleHitThenQuiet(t *testing.T) {
	t.Parallel()
	h := newHarness(quietAnomaly(DefaultConfig()))
	base := int64(14_000)
	synSecond(h, 23, base, synSecondSpec{flows: 6000, synShare: 1.0, bytesPer: 100})
	h.drain(base + 6)
	if got := len(h.col.of(shared.AttackSYNFlood, shared.AttackCandidate)); got != 1 {
		t.Fatalf("want exactly 1 candidate, got %d", got)
	}
	if got := len(h.col.of(shared.AttackSYNFlood, shared.AttackClosed)); got != 0 {
		t.Fatalf("silent close must not emit, got %d", got)
	}
}
