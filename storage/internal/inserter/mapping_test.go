package inserter

import (
	"errors"
	"testing"
	"time"

	"github.com/SchearLoe/lucidnet/shared"
)

// v4Mapped —— 构造 ::ffff:a.b.c.d。
func v4Mapped(a, b, c, d byte) [16]byte {
	return [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, a, b, c, d}
}

// validRecord —— 合法 FlowRecord 基准（v4 映射）。
func validRecord() shared.FlowRecord {
	return shared.FlowRecord{
		TimeStartMs: 1771901100123,
		TimeEndMs:   1771901101400,
		Exporter:    "10.0.0.1",
		DeviceID:    7,
		InIf:        12, OutIf: 15,
		SrcIP: v4Mapped(1, 2, 3, 4), DstIP: v4Mapped(5, 6, 7, 8),
		SrcPort: 55555, DstPort: 80,
		Proto: 6, IPVersion: 4,
		Packets: 10, Bytes: 6400,
		TCPFlags: 0x102, TOS: 0x10, SampleRate: 100,
		SrcAS: 65001, DstAS: 4808, AppID: 3, ZoneID: 101, IfRole: 3,
	}
}

// TestMapFlowRecord —— 字段逐项映射 + 秒/毫秒拆分 + 截断语义。
func TestMapFlowRecord(t *testing.T) {
	rec := validRecord()
	row, err := MapFlowRecord(rec)
	if err != nil {
		t.Fatalf("map: %v", err)
	}
	if want := time.Unix(1771901100, 0).UTC(); !row.TimeSecond.Equal(want) {
		t.Errorf("TimeSecond = %v, want %v", row.TimeSecond, want)
	}
	if row.TimeMs != 123 {
		t.Errorf("TimeMs = %d, want 123", row.TimeMs)
	}
	if row.Exporter != "10.0.0.1" || row.DeviceID != 7 || row.InIf != 12 || row.OutIf != 15 {
		t.Errorf("source dims wrong: %+v", row)
	}
	if row.SrcIP != v4Mapped(1, 2, 3, 4) || row.DstIP != v4Mapped(5, 6, 7, 8) {
		t.Errorf("ips must stay 16B raw: %+v", row)
	}
	if row.SrcPort != 55555 || row.DstPort != 80 || row.Proto != 6 || row.IPVersion != 4 {
		t.Errorf("tuple wrong: %+v", row)
	}
	if row.TCPFlags != 0x02 { // 0x102 & 0xFF 截断（DDL UInt8，契约缺口）
		t.Errorf("TCPFlags = 0x%02x, want 0x02 (truncated)", row.TCPFlags)
	}
	if row.TOS != 0x10 || row.SampleRate != 100 || row.SrcAS != 65001 || row.DstAS != 4808 {
		t.Errorf("metering wrong: %+v", row)
	}
	if row.ZoneID != 101 || row.IfRole != 3 {
		t.Errorf("zone/if_role wrong: %+v", row)
	}
}

// TestMapFlowRecordIPv6 —— v6 记录原样 16B。
func TestMapFlowRecordIPv6(t *testing.T) {
	rec := validRecord()
	rec.IPVersion = 6
	rec.SrcIP = [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	rec.DstIP = [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0x80}
	if _, err := MapFlowRecord(rec); err != nil {
		t.Fatalf("map v6: %v", err)
	}
}

// TestMapFlowRecordInvalid —— 校验失败表驱动（哨兵 ErrInvalidRecord）。
func TestMapFlowRecordInvalid(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*shared.FlowRecord)
	}{
		{"ip_version 5", func(r *shared.FlowRecord) { r.IPVersion = 5 }},
		{"ip_version 0", func(r *shared.FlowRecord) { r.IPVersion = 0 }},
		{"v4 not mapped", func(r *shared.FlowRecord) {
			r.SrcIP = [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
		}},
		{"negative time", func(r *shared.FlowRecord) { r.TimeStartMs = -1 }},
		{"proto overflow", func(r *shared.FlowRecord) { r.Proto = 256 }},
		{"src_port overflow", func(r *shared.FlowRecord) { r.SrcPort = 65536 }},
		{"dst_port overflow", func(r *shared.FlowRecord) { r.DstPort = 70000 }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rec := validRecord()
			c.mut(&rec)
			_, err := MapFlowRecord(rec)
			if !errors.Is(err, ErrInvalidRecord) {
				t.Fatalf("err = %v, want ErrInvalidRecord", err)
			}
		})
	}
}

// TestIsV4Mapped —— v4 映射前缀判定。
func TestIsV4Mapped(t *testing.T) {
	if !IsV4Mapped(v4Mapped(1, 2, 3, 4)) {
		t.Error("mapped addr must be detected")
	}
	if IsV4Mapped([16]byte{0x20, 0x01}) {
		t.Error("v6 addr must not be detected as mapped")
	}
	// ::a.b.c.d（非 ::ffff:）不算映射
	if IsV4Mapped([16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 2, 3, 4}) {
		t.Error("::0102:0304 prefix must not be v4-mapped")
	}
}

// TestDayOfUnixSec —— day 维度（UTC 日期串；负值截 0）。
func TestDayOfUnixSec(t *testing.T) {
	if got := DayOfUnixSec(0); got != "1970-01-01" {
		t.Errorf("epoch day = %q", got)
	}
	if got := DayOfUnixSec(1771901100); got != "2026-02-24" {
		t.Errorf("day = %q, want 2026-02-24", got)
	}
	if got := DayOfUnixSec(-1); got != "1970-01-01" {
		t.Errorf("negative day = %q", got)
	}
}

// TestMapAggrMinuteRow —— 聚合行映射与校验。
func TestMapAggrMinuteRow(t *testing.T) {
	row := shared.AggrRow{
		Minute: 1771901100, Exporter: "10.0.0.1", DeviceID: 7,
		InIf: 12, OutIf: 15, Direction: shared.DirIn, ZoneID: 101,
		SrcAS: 65001, DstAS: 4808, Proto: 6, DstPort: 443, AppID: 3,
		BytesSum: 1000, PacketsSum: 100, FlowsCount: 10,
	}
	got, err := MapAggrMinuteRow(row)
	if err != nil {
		t.Fatalf("map: %v", err)
	}
	if !got.Minute.Equal(time.Unix(1771901100, 0).UTC()) || got.Direction != uint8(shared.DirIn) ||
		got.Bytes != 1000 || got.Packets != 100 || got.Flows != 10 {
		t.Errorf("aggr row = %+v", got)
	}

	for _, mut := range []func(*shared.AggrRow){
		func(r *shared.AggrRow) { r.Minute = -1 },
		func(r *shared.AggrRow) { r.Proto = 256 },
		func(r *shared.AggrRow) { r.DstPort = 65536 },
		func(r *shared.AggrRow) { r.Direction = shared.Direction(9) },
	} {
		bad := row
		mut(&bad)
		if _, err := MapAggrMinuteRow(bad); !errors.Is(err, ErrInvalidRecord) {
			t.Errorf("invalid aggr row accepted: %+v", bad)
		}
	}
}

// TestMapAttackMinuteRow —— 攻击分钟行映射（Top 数组克隆）与校验。
func TestMapAttackMinuteRow(t *testing.T) {
	src := shared.AttackMinute{
		AttackID: "01JTEST", MinuteEpoch: 1771901100,
		BpsIn: 1e9, PpsIn: 1e6, BpsOut: 10, PpsOut: 2,
		NewFlows: 999, SynRatio: 0.9, UdpRatio: 0.05,
		TopSources: []string{"1.1.1.1", "2.2.2.2"}, TopPorts: []uint32{80, 443},
	}
	got, err := MapAttackMinuteRow(src)
	if err != nil {
		t.Fatalf("map: %v", err)
	}
	got.TopSources[0] = "mutated"
	if src.TopSources[0] != "1.1.1.1" {
		t.Error("TopSources must be cloned")
	}

	for _, mut := range []func(*shared.AttackMinute){
		func(r *shared.AttackMinute) { r.AttackID = "" },
		func(r *shared.AttackMinute) { r.MinuteEpoch = -5 },
	} {
		bad := src
		mut(&bad)
		if _, err := MapAttackMinuteRow(bad); !errors.Is(err, ErrInvalidRecord) {
			t.Errorf("invalid attack minute accepted: %+v", bad)
		}
	}
}

// TestMapAttackEvent —— AttackEvent → attacks 行。
func TestMapAttackEvent(t *testing.T) {
	ev := shared.AttackEvent{
		AttackID: "01JATTACK", ZoneID: 101, ZoneName: "客户A",
		AttackType: shared.AttackSYNFlood, TargetPrefix: "203.0.113.0/24",
		StartMs: 1771901100000, EndMs: 1771904700000,
		PeakBps: 9e9, PeakPps: 8e6, Confidence: 0.93,
		TopSources: []string{"1.1.1.1"}, EvidenceJSON: `{"syn":0.9}`,
		Status: shared.AttackConfirmed, MitigationID: "M-1",
	}
	got, err := MapAttackEvent(ev)
	if err != nil {
		t.Fatalf("map: %v", err)
	}
	if got.AttackID != ev.AttackID || got.AttackType != uint32(shared.AttackSYNFlood) ||
		got.Status != uint32(shared.AttackConfirmed) || got.Confidence != 0.93 {
		t.Errorf("attack row = %+v", got)
	}
	ev.AttackID = ""
	if _, err := MapAttackEvent(ev); !errors.Is(err, ErrInvalidRecord) {
		t.Error("empty attack_id accepted")
	}
}

// TestMapAlarm —— Alarm → 告警历史行。
func TestMapAlarm(t *testing.T) {
	a := shared.Alarm{
		AlarmID: "alm-1", Source: "analytics", Severity: shared.SeverityCritical,
		Category: shared.CategoryAttack, RaiseMs: 1771901100000, ClearMs: 0,
		Subject: "SYN flood", DetailJSON: `{"k":1}`, ZoneID: 101, AttackID: "01J",
	}
	got, err := MapAlarm(a)
	if err != nil {
		t.Fatalf("map: %v", err)
	}
	if got.Severity != uint32(shared.SeverityCritical) || got.Subject != "SYN flood" {
		t.Errorf("alarm row = %+v", got)
	}
	a.AlarmID = ""
	if _, err := MapAlarm(a); !errors.Is(err, ErrInvalidRecord) {
		t.Error("empty alarm_id accepted")
	}
}

// TestMapAlarmEnvelope —— 信封拆包三分支（Attack / Alarm / 空）。
func TestMapAlarmEnvelope(t *testing.T) {
	atk, _, err := MapAlarmEnvelope(shared.AlarmEnvelope{Attack: &shared.AttackEvent{AttackID: "01J"}})
	if err != nil || len(atk) != 1 || len(atk[0].AttackID) == 0 {
		t.Fatalf("attack envelope = %v, %v", atk, err)
	}
	_, alm, err := MapAlarmEnvelope(shared.AlarmEnvelope{Alarm: &shared.Alarm{AlarmID: "a1"}})
	if err != nil || len(alm) != 1 {
		t.Fatalf("alarm envelope = %v, %v", alm, err)
	}
	if _, _, err := MapAlarmEnvelope(shared.AlarmEnvelope{}); !errors.Is(err, ErrInvalidRecord) {
		t.Fatal("empty envelope must fail")
	}
}
