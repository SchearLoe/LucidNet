package detector

import (
	"strings"
	"testing"

	"github.com/SchearLoe/lucidnet/shared"
)

// anomalyStep —— 单记录秒（zone 总流量 = bytes×8 bps）。
func anomalyStep(h *harness, zone int32, sec int64, bytes uint64) {
	h.step(sec, rec(zone, sec, func(r *shared.FlowRecord) {
		r.SrcIP = v4IP(192, 168, 0, 1)
		r.DstIP = v4IP(10, 2, 3, 4)
		r.Bytes = bytes
		r.TCPFlags = flagACK // 非新流形态，避免干扰 SYN 规则
	}))
}

// TestAnomalySpikeConfirmed —— 平稳 1000bps → 200kbps 连续 3s → ANOMALY 确认（暴涨）。
func TestAnomalySpikeConfirmed(t *testing.T) {
	t.Parallel()
	h := newHarness(DefaultConfig())
	base := int64(30_000)

	for i := 0; i < 15; i++ { // 学习 15s（≥ MinSamples 10）
		anomalyStep(h, 41, base+int64(i), 125)
	}
	for i := 0; i < 3; i++ { // 突变 3s
		anomalyStep(h, 41, base+15+int64(i), 25_000)
	}
	h.drain(base + 19) // 关闭最后的突变秒（不越过流量末端）

	conf := h.col.of(shared.AttackAnomaly, shared.AttackConfirmed)
	if len(conf) != 1 {
		t.Fatalf("3s spike should confirm ANOMALY, events=%d (all=%d)", len(conf), len(h.col.events))
	}
	if !strings.Contains(conf[0].EvidenceJSON, `"direction":"spike"`) {
		t.Fatalf("spike evidence direction wrong: %s", conf[0].EvidenceJSON)
	}
	if got := len(h.col.of(shared.AttackAnomaly, shared.AttackCandidate)); got < 1 {
		t.Fatal("candidate should be raised before confirm")
	}
}

// TestAnomalyDropDirection —— 流量骤停 3s → direction=drop。
func TestAnomalyDropDirection(t *testing.T) {
	t.Parallel()
	h := newHarness(DefaultConfig())
	base := int64(31_000)

	for i := 0; i < 15; i++ {
		anomalyStep(h, 42, base+int64(i), 125)
	}
	for i := 0; i < 3; i++ {
		anomalyStep(h, 42, base+15+int64(i), 0) // bps=0
	}
	h.drain(base + 19)

	conf := h.col.of(shared.AttackAnomaly, shared.AttackConfirmed)
	if len(conf) != 1 {
		t.Fatalf("3s drop should confirm ANOMALY, events=%d", len(conf))
	}
	if !strings.Contains(conf[0].EvidenceJSON, `"direction":"drop"`) {
		t.Fatalf("drop evidence direction wrong: %s", conf[0].EvidenceJSON)
	}
}

// TestAnomalyJitterNoFire —— ±10% 抖动在 8×MAD 阈内不告警。
func TestAnomalyJitterNoFire(t *testing.T) {
	t.Parallel()
	h := newHarness(DefaultConfig())
	base := int64(32_000)

	for i := 0; i < 40; i++ {
		bytes := uint64(125)
		if i%2 == 1 {
			bytes = 138 // ±10%
		}
		anomalyStep(h, 43, base+int64(i), bytes)
	}
	h.drain(base + 41) // 关闭最后 2 个流量秒，不评估空秒

	if got := len(h.col.events); got != 0 {
		t.Fatalf("jitter within threshold must not fire, got %d events", got)
	}
}

// TestAnomalyShortSpikeNoConfirm —— 突变仅 1s（候选后中断）不确认。
func TestAnomalyShortSpikeNoConfirm(t *testing.T) {
	t.Parallel()
	h := newHarness(DefaultConfig())
	base := int64(33_000)

	for i := 0; i < 15; i++ {
		anomalyStep(h, 44, base+int64(i), 125)
	}
	anomalyStep(h, 44, base+15, 25_000) // 单秒突变
	for i := 0; i < 5; i++ {
		anomalyStep(h, 44, base+16+int64(i), 125)
	}
	h.drain(base + 22)

	if got := len(h.col.of(shared.AttackAnomaly, shared.AttackConfirmed)); got != 0 {
		t.Fatalf("1s spike must not confirm, got %d", got)
	}
}

// TestAnomalySuppression —— 同 zone 5 分钟内不重复告警；期满可再告警。
func TestAnomalySuppression(t *testing.T) {
	t.Parallel()
	h := newHarness(DefaultConfig())
	base := int64(34_000)

	spike := func(from int64) {
		for i := 0; i < 3; i++ {
			anomalyStep(h, 45, from+int64(i), 25_000)
		}
	}
	baseline := func(from, n int64) {
		for i := int64(0); i < n; i++ {
			anomalyStep(h, 45, from+i, 125)
		}
	}

	baseline(base, 15) // 0..14 学习
	spike(base + 15)   // 15..17 → 候选+确认
	h.drain(base + 19)
	cand1 := len(h.col.of(shared.AttackAnomaly, shared.AttackCandidate))
	conf1 := len(h.col.of(shared.AttackAnomaly, shared.AttackConfirmed))
	if cand1 != 1 || conf1 != 1 {
		t.Fatalf("first spike should raise candidate+confirm: %d/%d", cand1, conf1)
	}

	baseline(base+18, 60) // 18..77 回落
	spike(base + 78)      // 78..80 5 分钟内二次突变 → 抑制
	h.drain(base + 82)
	if got := len(h.col.of(shared.AttackAnomaly, shared.AttackCandidate)); got != cand1 {
		t.Fatalf("suppressed spike must not raise new candidate, got %d", got)
	}
	if got := len(h.col.of(shared.AttackAnomaly, shared.AttackConfirmed)); got != conf1 {
		t.Fatalf("suppressed spike must not confirm again, got %d", got)
	}

	baseline(base+81, 240) // 回落至 +320s（抑制期满，避开尾部空秒）
	spike(base + 321)      // 321..323 → 重新告警
	h.drain(base + 325)
	if got := len(h.col.of(shared.AttackAnomaly, shared.AttackConfirmed)); got != conf1+1 {
		t.Fatalf("spike after suppression window should confirm again, got %d", got)
	}
}

// TestMedianAbsDev —— MAD 计算正确性。
func TestMedianAbsDev(t *testing.T) {
	t.Parallel()
	if got := medianOf([]float64{3, 1, 2}); got != 2 {
		t.Fatalf("median = %v, want 2", got)
	}
	if got := medianOf([]float64{4, 1, 2, 3}); got != 2.5 {
		t.Fatalf("even median = %v, want 2.5", got)
	}
	// [1,1,2,5,7]：median=2，|dev|=[1,1,0,3,5] → MAD=1
	if got := medianAbsDev([]float64{1, 1, 2, 5, 7}); got != 1 {
		t.Fatalf("MAD = %v, want 1", got)
	}
	if got := medianAbsDev(nil); got != 0 {
		t.Fatalf("MAD(nil) = %v, want 0", got)
	}
}
