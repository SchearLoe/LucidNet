package ratelimit

import (
	"testing"
	"time"
)

// TestAllowBurstAndRefill —— 表驱动：突发预算、超限、随时间回填（docs/dd/05 §6 10 QPS）。
func TestAllowBurstAndRefill(t *testing.T) {
	base := time.Unix(1700000000, 0)
	now := base
	l := New(10, 5).WithClock(func() time.Time { return now })

	cases := []struct {
		advance time.Duration
		want    bool
	}{
		{0, true}, {0, true}, {0, true}, {0, true}, {0, true}, // 突发 5
		{0, false},      // 桶空
		{100 * time.Millisecond, true}, // 回填 1 个（10 QPS × 0.1s）
		{0, false},
		{100 * time.Millisecond, true}, // 再回填 1 个
		{0, false},
	}
	for i, tc := range cases {
		now = now.Add(tc.advance)
		if got := l.Allow("u1"); got != tc.want {
			t.Fatalf("step %d: allow = %v, want %v", i, got, tc.want)
		}
	}
}

// TestPerKeyIsolation —— 不同 key 互不影响。
func TestPerKeyIsolation(t *testing.T) {
	l := New(0.001, 1)
	if !l.Allow("a") {
		t.Fatal("first a should pass")
	}
	if l.Allow("a") {
		t.Fatal("second a should fail")
	}
	if !l.Allow("b") {
		t.Fatal("b should pass")
	}
}
