package store

import (
	"context"
	"testing"

	"github.com/SchearLoe/lucidnet/shared"

	"github.com/SchearLoe/lucidnet/console/internal/query"
)

func mkAttack(id string, zone int32, typ shared.AttackType, st shared.AttackStatus, bps int64, conf float32) *shared.AttackEvent {
	return &shared.AttackEvent{
		AttackID: id, ZoneID: zone, ZoneName: "客户A", AttackType: typ, Status: st,
		PeakBps: bps, Confidence: conf,
	}
}

// TestUpsertAndSortOngoingFirst —— docs/dd/05 §3.1：攻击中置顶，按峰值/置信度降序；
// 状态机推进覆盖写。
func TestUpsertAndSortOngoingFirst(t *testing.T) {
	m := NewMemory(100, 100)
	m.UpsertAttack(mkAttack("a-old", 1, shared.AttackSYNFlood, shared.AttackMitigated, 10_000_000_000, 0.9))
	m.UpsertAttack(mkAttack("a-cand", 1, shared.AttackUDPFlood, shared.AttackCandidate, 1_000_000, 0.5))
	m.UpsertAttack(mkAttack("a-conf", 2, shared.AttackSweep, shared.AttackConfirmed, 2_000_000, 0.8))

	page, err := m.ListAttacks(context.Background(), query.All())
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if page.Total != 3 {
		t.Fatalf("total = %d", page.Total)
	}
	got := []string{page.Rows[0].AttackID, page.Rows[1].AttackID, page.Rows[2].AttackID}
	want := []string{"a-conf", "a-cand", "a-old"} // 攻击中(bps 降序) → 已缓解
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("order = %v, want %v", got, want)
		}
	}

	// 状态推进：确认 → 已缓解，排序位置应后移。
	m.UpsertAttack(mkAttack("a-conf", 2, shared.AttackSweep, shared.AttackMitigated, 2_000_000, 0.8))
	page, _ = m.ListAttacks(context.Background(), query.All())
	if page.Rows[0].AttackID != "a-cand" {
		t.Fatalf("after status advance first = %s", page.Rows[0].AttackID)
	}
}

// TestFilterAndPage —— 表驱动：zone/type/status 过滤 + 分页（docs/00 §6）。
func TestFilterAndPage(t *testing.T) {
	m := NewMemory(100, 100)
	m.UpsertAttack(mkAttack("a1", 1, shared.AttackSYNFlood, shared.AttackConfirmed, 3, 0.9))
	m.UpsertAttack(mkAttack("a2", 2, shared.AttackSYNFlood, shared.AttackConfirmed, 2, 0.9))
	m.UpsertAttack(mkAttack("a3", 1, shared.AttackUDPFlood, shared.AttackConfirmed, 1, 0.9))

	cases := []struct {
		name  string
		f     func() query.AttackFilter
		total int
		first string
	}{
		{"zone", func() query.AttackFilter { return query.FilterZone(1) }, 2, "a1"},
		{"type", func() query.AttackFilter { return query.FilterTypes(shared.AttackUDPFlood) }, 1, "a3"},
		{"page", func() query.AttackFilter { return query.WithPage(2, 2) }, 3, "a3"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			page, err := m.ListAttacks(context.Background(), tc.f())
			if err != nil {
				t.Fatalf("list: %v", err)
			}
			if page.Total != tc.total {
				t.Fatalf("total = %d, want %d", page.Total, tc.total)
			}
			if len(page.Rows) > 0 && page.Rows[0].AttackID != tc.first {
				t.Fatalf("first = %s, want %s", page.Rows[0].AttackID, tc.first)
			}
		})
	}
}

// TestAlarmRingAndZoneRealtime —— 告警环形缓冲淘汰 + 客户域快照计数。
func TestAlarmRingAndZoneRealtime(t *testing.T) {
	m := NewMemory(100, 2)
	for i := 0; i < 3; i++ {
		m.AppendAlarm(&shared.Alarm{AlarmID: string(rune('a' + i)), ZoneID: 1, Severity: shared.SeverityWarning, Category: shared.CategoryAttack})
	}
	page, _ := m.ListAlarms(context.Background(), query.AlarmFilter{})
	if page.Total != 2 {
		t.Fatalf("ring total = %d, want 2 (cap)", page.Total)
	}
	if page.Rows[0].AlarmID != "c" {
		t.Fatalf("newest first, got %s", page.Rows[0].AlarmID)
	}

	m.UpdateZone(1, "客户A", 1e9, 2e8, 1e6, 2e5, 1, 1700000000000)
	m.UpsertAttack(mkAttack("a1", 1, shared.AttackSYNFlood, shared.AttackConfirmed, 0, 0.9))
	zones, _ := m.ZoneRealtime(context.Background())
	if len(zones) != 1 || zones[0].ZoneID != 1 || zones[0].AttackCount != 1 || zones[0].Ongoing != 1 {
		t.Fatalf("zones = %+v", zones)
	}
}

// TestEvictionCap —— 攻击注册表容量淘汰最旧。
func TestEvictionCap(t *testing.T) {
	m := NewMemory(2, 10)
	m.UpsertAttack(mkAttack("a1", 1, shared.AttackSYNFlood, shared.AttackConfirmed, 0, 0))
	m.UpsertAttack(mkAttack("a2", 1, shared.AttackSYNFlood, shared.AttackConfirmed, 0, 0))
	m.UpsertAttack(mkAttack("a3", 1, shared.AttackSYNFlood, shared.AttackConfirmed, 0, 0))
	if _, err := m.GetAttack(context.Background(), "a1"); err == nil {
		t.Fatal("a1 should be evicted")
	}
	if _, err := m.GetAttack(context.Background(), "a3"); err != nil {
		t.Fatalf("a3 should exist: %v", err)
	}
}
