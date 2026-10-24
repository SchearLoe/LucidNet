package detector

import (
	"testing"

	"github.com/SchearLoe/lucidnet/shared"
)

// sweepWindow —— 在 [start, start+winSec) 窗内灌入扫段流量：
// totalDsts 个目的均匀分布到各秒（每 (src,dst) pkts 包，srcs 个源），
// per_dst_avg_pkts = srcs×pkts，源集中度 = srcs/totalDsts。
func sweepWindow(h *harness, zone int32, start int64, winSec int64, totalDsts, srcs int, v6 bool, pkts uint64) {
	seg := [8]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 1} // 2001:db8:1::/64
	perSec := totalDsts / int(winSec)
	if perSec < 1 {
		perSec = 1
	}
	for s := int64(0); s < winSec; s++ {
		sec := start + s
		var recs []*shared.FlowRecord
		for d := 0; d < perSec; d++ {
			dstIdx := int(s)*perSec + d
			if dstIdx >= totalDsts {
				break
			}
			for i := 0; i < srcs; i++ {
				for p := uint64(0); p < pkts; p++ {
					i, dstIdx := i, dstIdx
					r := rec(zone, sec, func(r *shared.FlowRecord) {
						r.SrcIP = v4IP(172, 16, 0, byte(i+1))
						if v6 {
							r.IPVersion = 6
							r.DstIP = v6IP(seg, byte(dstIdx+1))
						} else {
							r.DstIP = v4IP(203, 0, 113, byte(dstIdx+1)) // 同 /24
						}
						r.Bytes = 60
						r.TCPFlags = flagSYN // 半开 SYN 扫段（dd/03 §4.2 归类）
					})
					recs = append(recs, r)
				}
			}
		}
		h.step(sec, recs...)
	}
}

func TestSweepV4Confirmed(t *testing.T) {
	t.Parallel()
	h := newHarness(quietAnomaly(DefaultConfig()))
	base := int64(20_000) // 对齐 10s 窗边界（win=2000）
	const winSec = 10

	sweepWindow(h, 31, base, winSec, 40, 1, false, 1) // 40 dst × 1 源 × 1 包
	h.drain(base + winSec + 2)                        // 窗 1 关闭 → 命中（candidate）
	if got := len(h.col.of(shared.AttackSweep, shared.AttackCandidate)); got != 1 {
		t.Fatalf("window 1 hit should raise 1 sweep candidate, got %d", got)
	}

	sweepWindow(h, 31, base+winSec, winSec, 40, 1, false, 1)
	h.drain(base + 2*winSec + 2) // 窗 2 连续命中 → 确认
	conf := h.col.of(shared.AttackSweep, shared.AttackConfirmed)
	if len(conf) != 1 {
		t.Fatalf("two consecutive window hits should confirm sweep, got %d events", len(conf))
	}
	if conf[0].TargetPrefix != "203.0.113.0/24" {
		t.Fatalf("target prefix = %q, want 203.0.113.0/24", conf[0].TargetPrefix)
	}
	if conf[0].ZoneID != 31 || conf[0].EvidenceJSON == "" || len(conf[0].TopSources) == 0 {
		t.Fatalf("confirmed sweep event incomplete: %+v", conf[0])
	}
}

func TestSweepV6Confirmed(t *testing.T) {
	t.Parallel()
	h := newHarness(quietAnomaly(DefaultConfig()))
	base := int64(21_000)
	const winSec = 10

	sweepWindow(h, 32, base, winSec, 40, 1, true, 1)
	h.drain(base + winSec + 2)
	sweepWindow(h, 32, base+winSec, winSec, 40, 1, true, 1)
	h.drain(base + 2*winSec + 2)

	conf := h.col.of(shared.AttackSweep, shared.AttackConfirmed)
	if len(conf) != 1 {
		t.Fatalf("v6 /64 sweep should confirm, got %d", len(conf))
	}
	if conf[0].TargetPrefix != "2001:db8:0:1::/64" {
		t.Fatalf("v6 prefix = %q, want 2001:db8:0:1::/64", conf[0].TargetPrefix)
	}
}

// TestSweepFloodNotSweep —— 泛洪（每目的 50 包）不判扫段（per_dst_avg ≥ 3 区分泛洪）。
func TestSweepFloodNotSweep(t *testing.T) {
	t.Parallel()
	h := newHarness(quietAnomaly(DefaultConfig()))
	base := int64(22_000)
	const winSec = 10

	sweepWindow(h, 33, base, winSec, 40, 1, false, 50)
	h.drain(base + winSec + 2)
	sweepWindow(h, 33, base+winSec, winSec, 40, 1, false, 50)
	h.drain(base + 2*winSec + 2)

	for _, st := range []shared.AttackStatus{shared.AttackCandidate, shared.AttackConfirmed} {
		if got := len(h.col.of(shared.AttackSweep, st)); got != 0 {
			t.Fatalf("flood (per_dst_avg=50) must not be sweep, %d events with status %d", got, st)
		}
	}
}

// TestSweepFewDstNotSweep —— distinct_dst < 32 下限不判扫段。
func TestSweepFewDstNotSweep(t *testing.T) {
	t.Parallel()
	h := newHarness(quietAnomaly(DefaultConfig()))
	base := int64(23_000)
	const winSec = 10

	sweepWindow(h, 34, base, winSec, 10, 1, false, 1)
	h.drain(base + winSec + 2)
	sweepWindow(h, 34, base+winSec, winSec, 10, 1, false, 1)
	h.drain(base + 2*winSec + 2)

	if got := len(h.col.events); got != 0 {
		t.Fatalf("distinct_dst=10 below floor must not fire, got %d events", got)
	}
}

// TestSweepDistributedSources —— 高强度触达（每目的 10 包/10 源）非扫段。
func TestSweepDistributedSources(t *testing.T) {
	t.Parallel()
	h := newHarness(quietAnomaly(DefaultConfig()))
	base := int64(24_000)
	const winSec = 10

	sweepWindow(h, 35, base, winSec, 40, 10, false, 1) // per_dst_avg=10
	h.drain(base + winSec + 2)
	sweepWindow(h, 35, base+winSec, winSec, 40, 10, false, 1)
	h.drain(base + 2*winSec + 2)

	if got := len(h.col.events); got != 0 {
		t.Fatalf("high-intensity touch (per_dst_avg=10) must not be sweep, got %d", got)
	}
}

// TestSweepStreakReset —— 命中后下一窗未命中 → streak 清零，需重新两窗确认。
func TestSweepStreakReset(t *testing.T) {
	t.Parallel()
	h := newHarness(quietAnomaly(DefaultConfig()))
	base := int64(25_000)
	const winSec = 10

	sweepWindow(h, 36, base, winSec, 40, 1, false, 1) // 窗 1 命中
	h.drain(base + winSec + 2)
	sweepWindow(h, 36, base+winSec, winSec, 10, 1, false, 1) // 窗 2 未命中（dst<32）
	h.drain(base + 2*winSec + 2)
	sweepWindow(h, 36, base+2*winSec, winSec, 40, 1, false, 1) // 窗 3 重新命中
	h.drain(base + 3*winSec + 2)

	if got := len(h.col.of(shared.AttackSweep, shared.AttackConfirmed)); got != 0 {
		t.Fatalf("streak reset requires two fresh consecutive hits, confirmed=%d", got)
	}
	if got := len(h.col.of(shared.AttackSweep, shared.AttackCandidate)); got < 2 {
		t.Fatalf("re-hit should raise candidate again, got %d", got)
	}
}

// TestSweepUnalignedWindows —— 窗口起点不与 10s 边界对齐（真实时钟场景）：
// 翻转快照保证评估滞后（秒关闭 2s 宽限）不丢已完结窗。
func TestSweepUnalignedWindows(t *testing.T) {
	t.Parallel()
	for _, baseOff := range []int64{0, 3, 6, 9} {
		base := int64(20_006) + baseOff
		h := newHarness(quietAnomaly(DefaultConfig()))
		const winSec = 10
		for s := int64(0); s < 30; s++ {
			sec := base + s
			var recs []*shared.FlowRecord
			for d := 0; d < 4; d++ { // 4 新目的/s，10 个偏移覆盖 40 目的
				dstIdx := int(s%10)*4 + d
				r := rec(38, sec, func(r *shared.FlowRecord) {
					r.SrcIP = v4IP(172, 16, 0, 1)
					r.DstIP = v4IP(203, 0, 113, byte(dstIdx+1))
					r.Packets = 1
					r.Bytes = 60
					r.TCPFlags = flagSYN
				})
				recs = append(recs, r)
			}
			h.step(sec, recs...)
		}
		h.drain(base + 32)
		if got := len(h.col.of(shared.AttackSweep, shared.AttackConfirmed)); got == 0 {
			t.Fatalf("baseOff=%d: unaligned sweep should confirm eventually", baseOff)
		}
	}
}

// TestSweepCellLRUCap —— cell 上限 LRU 淘汰（小上限模拟 4,096）。
func TestSweepCellLRUCap(t *testing.T) {
	t.Parallel()
	cfg := quietAnomaly(DefaultConfig())
	cfg.SweepCellsMax = 4
	h := newHarness(cfg)
	base := int64(26_000)

	var recs []*shared.FlowRecord
	for p := 0; p < 6; p++ { // 6 个 /24 > 上限 4
		p := p
		recs = append(recs, rec(37, base, func(r *shared.FlowRecord) {
			r.DstIP = v4IP(198, 51, 100, 1)
			r.DstIP[13] = byte(p) // 198.51.p.1 → 不同 /24
			r.TCPFlags = flagSYN
		}))
	}
	h.step(base, recs...)
	if got := h.d.Stats().SweepCells; got != 4 {
		t.Fatalf("sweep cells = %d, want cap 4", got)
	}
}

// TestPrefixKeyCIDR —— 前缀文本。
func TestPrefixKeyCIDR(t *testing.T) {
	t.Parallel()
	v4k := prefixKeyOf(&shared.FlowRecord{IPVersion: 4, DstIP: v4IP(203, 0, 113, 77)})
	if got := v4k.cidr(); got != "203.0.113.0/24" {
		t.Fatalf("v4 cidr = %q", got)
	}
	v6k := prefixKeyOf(&shared.FlowRecord{IPVersion: 6, DstIP: v6IP([8]byte{0x20, 0x01, 0x0d, 0xb8, 9, 9, 9, 9}, 55)})
	if got := v6k.cidr(); got != "2001:db8:909:909::/64" {
		t.Fatalf("v6 cidr = %q", got)
	}
	if v4k == v6k {
		t.Fatal("v4/v6 keys must differ")
	}
}
