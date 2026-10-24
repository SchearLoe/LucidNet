package fsm

import (
	"fmt"
	"testing"
	"time"

	"github.com/SchearLoe/lucidnet/shared"
)

// clock —— 注入时钟。
type clock struct{ t time.Time }

func (c *clock) Now() time.Time          { return c.t }
func (c *clock) Advance(d time.Duration) { c.t = c.t.Add(d) }

// collector —— 收集 EmitAttack 输出。
type collector struct{ events []*shared.AttackEvent }

func (c *collector) EmitAttack(ev *shared.AttackEvent) { c.events = append(c.events, ev) }

var base = time.Unix(1_700_000_000, 0).UTC() // 整秒对齐

func newTestManager() (*Manager, *clock, *collector) {
	clk := &clock{t: base}
	col := &collector{}
	cfg := DefaultConfig()
	cfg.Now = clk.Now
	return New(cfg, col), clk, col
}

func statusOf(c *collector, want shared.AttackStatus) []*shared.AttackEvent {
	var out []*shared.AttackEvent
	for _, ev := range c.events {
		if ev.Status == want {
			out = append(out, ev)
		}
	}
	return out
}

// TestCandidateSilentClose —— CANDIDATE ─(3s 未再命中)─► 关闭（不展示，无事件外发）。
func TestCandidateSilentClose(t *testing.T) {
	t.Parallel()
	m, clk, col := newTestManager()
	m.Candidate(101, shared.AttackSYNFlood, Evidence{PeakBps: 100})
	if m.State(101, shared.AttackSYNFlood) != StateCandidate {
		t.Fatal("want candidate right after hit")
	}
	clk.Advance(3 * time.Second)
	m.Tick()
	if got := m.State(101, shared.AttackSYNFlood); got != StateNone {
		t.Fatalf("candidate should close silently after 3s, state=%v", got)
	}
	if n := len(statusOf(col, shared.AttackClosed)); n != 0 {
		t.Fatalf("silent close must not emit CLOSED event, got %d", n)
	}
	if m.ActiveCount() != 0 {
		t.Fatal("closed attack should leave active table")
	}
}

// TestConfirmAndRecover —— CANDIDATE→CONFIRMED→(120s 静默)→RECOVERED→(60s 展示)→CLOSED。
func TestConfirmAndRecover(t *testing.T) {
	t.Parallel()
	m, clk, col := newTestManager()
	m.Candidate(101, shared.AttackSYNFlood, Evidence{PeakBps: 1_000})
	m.Confirm(101, shared.AttackSYNFlood, Evidence{PeakBps: 9_000, PeakPps: 500})
	if m.State(101, shared.AttackSYNFlood) != StateConfirmed {
		t.Fatalf("want confirmed, got %v", m.State(101, shared.AttackSYNFlood))
	}
	ev, ok := m.Event(101, shared.AttackSYNFlood)
	if !ok || ev.PeakBps != 9_000 {
		t.Fatalf("confirm should merge heavier evidence: %+v", ev)
	}

	// 静默 120s → RECOVERED（EndMs 落定，展示期）
	clk.Advance(120 * time.Second)
	m.Tick()
	if got := m.State(101, shared.AttackSYNFlood); got != StateRecovered {
		t.Fatalf("want recovered after 120s quiet, got %v", got)
	}
	ev, _ = m.Event(101, shared.AttackSYNFlood)
	if ev.EndMs == 0 {
		t.Fatal("recovered should set end_ms")
	}

	// 再 60s → CLOSED（外发 AttackClosed）
	clk.Advance(60 * time.Second)
	m.Tick()
	if got := m.State(101, shared.AttackSYNFlood); got != StateNone {
		t.Fatalf("want closed/removed after display, got %v", got)
	}
	closed := statusOf(col, shared.AttackClosed)
	if len(closed) != 1 || closed[0].AttackID != ev.AttackID {
		t.Fatalf("want one CLOSED emit, got %+v", closed)
	}
}

// TestConfirmWithoutCandidate —— 无候选直接 Confirm 自动建档（首告警 ≤5s 路径）。
func TestConfirmWithoutCandidate(t *testing.T) {
	t.Parallel()
	m, _, col := newTestManager()
	ev := m.Confirm(202, shared.AttackUDPFlood, Evidence{PeakBps: 5})
	if ev == nil || ev.Status != shared.AttackConfirmed {
		t.Fatalf("confirm auto-creates candidate, got %+v", ev)
	}
	if len(statusOf(col, shared.AttackConfirmed)) != 1 {
		t.Fatal("confirmed event should be emitted")
	}
}

// TestMergeWithin60s —— 同 zone 同类型终态 60s 内合并：沿用原 AttackID。
func TestMergeWithin60s(t *testing.T) {
	t.Parallel()
	m, clk, _ := newTestManager()
	first := m.Candidate(303, shared.AttackSweep, Evidence{PeakBps: 1})
	id1 := first.AttackID
	clk.Advance(3 * time.Second)
	m.Tick() // 静默关闭 → 登记 60s 合并窗

	clk.Advance(30 * time.Second) // 窗内重开
	second := m.Candidate(303, shared.AttackSweep, Evidence{PeakBps: 2})
	if second == nil || second.AttackID != id1 {
		t.Fatalf("merge should reuse attack id %s, got %+v", id1, second)
	}
	if m.State(303, shared.AttackSweep) != StateCandidate {
		t.Fatal("reopened attack should be candidate")
	}

	// 窗外：新 ULID
	clk.Advance(4 * time.Second)
	m.Tick() // 再次静默关闭
	clk.Advance(61 * time.Second)
	third := m.Candidate(303, shared.AttackSweep, Evidence{PeakBps: 3})
	if third == nil || third.AttackID == id1 {
		t.Fatalf("outside merge window should mint new id, got %+v", third)
	}
}

// TestMitigationTransitions —— CONFIRMED→MITIGATING（applied）→RESOLVED（回落 60s）。
func TestMitigationTransitions(t *testing.T) {
	t.Parallel()
	m, clk, col := newTestManager()
	ev := m.Confirm(404, shared.AttackSYNFlood, Evidence{PeakBps: 10_000_000})

	ok := m.Mitigation(shared.MitigationEvent{
		MitigationID: "mit-1",
		Action:       "blackhole",
		Result:       "applied",
		AttackID:     ev.AttackID,
		TsMs:         clk.t.UnixMilli(),
	})
	if !ok || m.State(404, shared.AttackSYNFlood) != StateMitigating {
		t.Fatal("applied mitigation should move FSM to MITIGATING")
	}
	got, _ := m.Event(404, shared.AttackSYNFlood)
	if got.MitigationID != "mit-1" {
		t.Fatalf("mitigation_id not recorded: %+v", got)
	}

	// 回落不足（bps 仍 > 基线×1.3）：保持 MITIGATING 且计时重置
	m.Rate(404, shared.AttackSYNFlood, 9_000_000, 1_000_000)
	clk.Advance(50 * time.Second)
	if got := m.Rate(404, shared.AttackSYNFlood, 1_100_000, 1_000_000); got != StateMitigating {
		t.Fatalf("under-threshold must sustain 60s, got %v", got)
	}

	// 持续回落满 60s → RESOLVED（AttackMitigated，EndMs 落定）
	clk.Advance(61 * time.Second)
	if got := m.Rate(404, shared.AttackSYNFlood, 1_100_000, 1_000_000); got != StateResolved {
		t.Fatalf("want resolved after 60s under baseline×1.3, got %v", got)
	}
	if n := len(statusOf(col, shared.AttackMitigated)); n != 1 {
		t.Fatalf("resolved should emit MITIGATED once, got %d", n)
	}
	if m.ActiveCount() != 0 {
		t.Fatal("resolved attack should retire from active table")
	}
}

// TestMitigationBounceResets —— 回落后反弹：回落计时清零重计。
func TestMitigationBounceResets(t *testing.T) {
	t.Parallel()
	m, clk, _ := newTestManager()
	ev := m.Confirm(505, shared.AttackSYNFlood, Evidence{})
	m.Mitigation(shared.MitigationEvent{Result: "applied", AttackID: ev.AttackID})

	m.Rate(505, shared.AttackSYNFlood, 100, 1_000) // 回落开始
	clk.Advance(50 * time.Second)
	m.Rate(505, shared.AttackSYNFlood, 100, 1_000)
	clk.Advance(5 * time.Second)
	m.Rate(505, shared.AttackSYNFlood, 5_000_000, 1_000) // 反弹
	clk.Advance(50 * time.Second)
	if got := m.Rate(505, shared.AttackSYNFlood, 100, 1_000); got != StateMitigating {
		t.Fatalf("bounce must reset sustained timer, got %v", got)
	}
	clk.Advance(60 * time.Second)
	if got := m.Rate(505, shared.AttackSYNFlood, 100, 1_000); got != StateResolved {
		t.Fatalf("should resolve after fresh 60s under baseline, got %v", got)
	}
}

// TestMitigationWithdrawAndFailed —— withdrawn 回退 CONFIRMED；failed 忽略。
func TestMitigationWithdrawAndFailed(t *testing.T) {
	t.Parallel()
	m, _, _ := newTestManager()
	ev := m.Confirm(606, shared.AttackSYNFlood, Evidence{})

	if m.Mitigation(shared.MitigationEvent{Result: "failed", AttackID: ev.AttackID}) {
		t.Fatal("failed mitigation must be ignored")
	}
	if !m.Mitigation(shared.MitigationEvent{Result: "applied", AttackID: ev.AttackID}) {
		t.Fatal("applied should engage")
	}
	if !m.Mitigation(shared.MitigationEvent{Result: "withdrawn", AttackID: ev.AttackID, MitigationID: "mit-x"}) {
		t.Fatal("withdrawn should disengage")
	}
	if got := m.State(606, shared.AttackSYNFlood); got != StateConfirmed {
		t.Fatalf("withdrawn should fall back to CONFIRMED, got %v", got)
	}
}

// TestMitigationUnknownAttack —— 回执不匹配任何活跃攻击。
func TestMitigationUnknownAttack(t *testing.T) {
	t.Parallel()
	m, _, _ := newTestManager()
	if m.Mitigation(shared.MitigationEvent{Result: "applied", AttackID: "nope"}) {
		t.Fatal("unmatched mitigation should return false")
	}
}

// TestRateWithoutBaseline —— 基线缺失时 MITIGATING 保持（TODO 绝对阈值兜底）。
func TestRateWithoutBaseline(t *testing.T) {
	t.Parallel()
	m, clk, _ := newTestManager()
	ev := m.Confirm(707, shared.AttackSYNFlood, Evidence{})
	m.Mitigation(shared.MitigationEvent{Result: "applied", AttackID: ev.AttackID})
	clk.Advance(10 * time.Minute)
	if got := m.Rate(707, shared.AttackSYNFlood, 0, 0); got != StateMitigating {
		t.Fatalf("no baseline should hold MITIGATING, got %v", got)
	}
}

// TestRateOnNonMitigating —— 非 MITIGATING 态 Rate 原样返回。
func TestRateOnNonMitigating(t *testing.T) {
	t.Parallel()
	m, _, _ := newTestManager()
	m.Candidate(808, shared.AttackSYNFlood, Evidence{})
	if got := m.Rate(808, shared.AttackSYNFlood, 0, 1_000); got != StateCandidate {
		t.Fatalf("rate on candidate should be no-op, got %v", got)
	}
	if got := m.Rate(999, shared.AttackSYNFlood, 0, 1_000); got != StateNone {
		t.Fatalf("rate on missing attack should be none, got %v", got)
	}
}

// TestHitRefreshKeepsConfirmed —— 确认后持续命中刷新，不进入恢复。
func TestHitRefreshKeepsConfirmed(t *testing.T) {
	t.Parallel()
	m, clk, _ := newTestManager()
	m.Confirm(909, shared.AttackSYNFlood, Evidence{PeakBps: 1})
	for i := 0; i < 30; i++ { // 30×5s=150s 持续命中 > RecoverQuiet 120s
		clk.Advance(5 * time.Second)
		m.Hit(909, shared.AttackSYNFlood, Evidence{PeakBps: 1})
		m.Tick()
	}
	if got := m.State(909, shared.AttackSYNFlood); got != StateConfirmed {
		t.Fatalf("continuing hits must keep CONFIRMED, got %v", got)
	}
}

// TestEvidenceHeavierMerge —— 证据合并取更重（PeakBps 优先，其次 PeakPps）。
func TestEvidenceHeavierMerge(t *testing.T) {
	t.Parallel()
	m, _, _ := newTestManager()
	m.Candidate(111, shared.AttackSYNFlood, Evidence{PeakBps: 100, PeakPps: 10})
	m.Hit(111, shared.AttackSYNFlood, Evidence{PeakBps: 50, PeakPps: 999}) // 更轻：不覆盖
	ev, _ := m.Event(111, shared.AttackSYNFlood)
	if ev.PeakBps != 100 || ev.PeakPps != 10 {
		t.Fatalf("lighter evidence must not overwrite: %+v", ev)
	}
	m.Hit(111, shared.AttackSYNFlood, Evidence{PeakBps: 200, PeakPps: 1})
	ev, _ = m.Event(111, shared.AttackSYNFlood)
	if ev.PeakBps != 200 {
		t.Fatalf("heavier evidence should merge: %+v", ev)
	}
}

// TestDifferentZonesIndependent —— 不同 zone / 类型互不影响。
func TestDifferentZonesIndependent(t *testing.T) {
	t.Parallel()
	m, clk, _ := newTestManager()
	m.Confirm(1, shared.AttackSYNFlood, Evidence{})
	m.Confirm(2, shared.AttackSYNFlood, Evidence{})
	m.Confirm(1, shared.AttackUDPFlood, Evidence{})
	if m.ActiveCount() != 3 {
		t.Fatalf("want 3 active attacks, got %d", m.ActiveCount())
	}
	clk.Advance(3 * time.Second)
	m.Tick()
	if m.State(1, shared.AttackSYNFlood) != StateConfirmed || m.State(1, shared.AttackUDPFlood) != StateConfirmed {
		t.Fatal("confirmed attacks should not close on candidate timeout")
	}
}

// TestStateString —— 状态命名（可读性/日志）。
func TestStateString(t *testing.T) {
	t.Parallel()
	for _, s := range []State{StateNone, StateCandidate, StateConfirmed, StateMitigating, StateRecovered, StateResolved, StateClosed} {
		if str := s.String(); str == "" || str == "unknown" {
			t.Errorf("state %d should have name", s)
		}
	}
}

// TestAttackStatusMapping —— State→shared.AttackStatus 契约映射。
func TestAttackStatusMapping(t *testing.T) {
	t.Parallel()
	cases := []struct {
		s    State
		want shared.AttackStatus
	}{
		{StateCandidate, shared.AttackCandidate},
		{StateConfirmed, shared.AttackConfirmed},
		{StateRecovered, shared.AttackConfirmed}, // RECOVERED 展示期保持 CONFIRMED（dd/03 §6.1）
		{StateMitigating, shared.AttackMitigating},
		{StateResolved, shared.AttackMitigated},
		{StateClosed, shared.AttackClosed},
	}
	for _, tc := range cases {
		if got := tc.s.AttackStatus(); got != tc.want {
			t.Errorf("state %v attack status = %d, want %d", tc.s, got, tc.want)
		}
	}
}

// ExampleManager —— 最小生命周期演示。
func ExampleManager() {
	clk := &clock{t: base}
	col := &collector{}
	cfg := DefaultConfig()
	cfg.Now = clk.Now
	m := New(cfg, col)

	m.Confirm(101, shared.AttackSYNFlood, Evidence{PeakBps: 42})
	fmt.Println(m.State(101, shared.AttackSYNFlood))
	clk.Advance(120 * time.Second)
	m.Tick()
	fmt.Println(m.State(101, shared.AttackSYNFlood))
	clk.Advance(60 * time.Second)
	m.Tick()
	fmt.Println(m.ActiveCount())
	// Output:
	// confirmed
	// recovered
	// 0
}
