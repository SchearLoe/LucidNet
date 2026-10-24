package enrich

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/SchearLoe/lucidnet/collector/internal/zone"
	"github.com/SchearLoe/lucidnet/shared"
)

// mustIP16 —— 地址文本 → 16B（v4 用 ::ffff: 映射）。
func mustIP16(s string) [16]byte {
	a := netip.MustParseAddr(s)
	var b [16]byte
	if a.Is4() {
		v4 := a.As4()
		b[10], b[11] = 0xff, 0xff
		copy(b[12:16], v4[:])
	} else {
		b = a.As16()
	}
	return b
}

// newTestPipeline —— 全组件流水线：RIB（/24、/16、v6 /32）+ Geo + App + Zone + IfRole。
func newTestPipeline(t *testing.T, matchField zone.MatchField) (*Pipeline, *zone.Matcher, *IfRoleSnapshot) {
	t.Helper()

	dir := t.TempDir()
	path := filepath.Join(dir, "rib.json")
	body := `[
		{"prefix":"203.0.113.0/24","asn":65001,"peer_as":64500},
		{"prefix":"203.0.0.0/16","asn":65010,"peer_as":64500},
		{"prefix":"2001:db8::/32","asn":65002,"peer_as":64501}
	]`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write rib snapshot: %v", err)
	}
	snap, err := LoadRibSnapshot(path)
	if err != nil {
		t.Fatalf("load rib snapshot: %v", err)
	}

	geo := NewGeoStub()
	geo.Set(mustIP16("203.0.113.7"), 86)
	geo.Set(mustIP16("198.51.100.2"), 49)

	apps := NewAppTable()
	apps.Set(6, 443, 20) // tcp/443
	apps.Set(17, 53, 21) // udp/53

	m := zone.NewMatcher(matchField)
	if err := m.Update([]zone.ZoneSpec{
		{ID: 7, Name: "cust-a", IPs: []zone.IPEntry{mustZoneEntry("203.0.113.0/24")}},
		{ID: 8, Name: "cust-b", IPs: []zone.IPEntry{mustZoneEntry("2001:db8:1::/64")}},
	}); err != nil {
		t.Fatalf("zone update: %v", err)
	}

	roles := NewIfRoleSnapshot()
	roles.Update(map[IfRef]IfRole{
		{DeviceID: 1, IfIndex: 5}:  IfRoleBoundary, // in：客户口
		{DeviceID: 1, IfIndex: 9}:  IfRoleInternal, // out：互联口
		{DeviceID: 1, IfIndex: 10}: IfRoleInternal,
		{DeviceID: 2, IfIndex: 1}:  IfRoleInternal, // 双互联
		{DeviceID: 2, IfIndex: 2}:  IfRoleInternal,
	})

	return NewPipeline(snap, geo, apps, m, roles), m, roles
}

func mustZoneEntry(cidr string) zone.IPEntry {
	p := netip.MustParsePrefix(cidr).Masked()
	var b [16]byte
	if p.Addr().Is4() {
		v4 := p.Addr().As4()
		b[10], b[11] = 0xff, 0xff
		copy(b[12:16], v4[:])
	} else {
		b = p.Addr().As16()
	}
	return zone.IPEntry{Prefix: b, MaskLen: int32(p.Bits())}
}

func TestPipelineFullEnrich(t *testing.T) {
	p, _, _ := newTestPipeline(t, zone.MatchDst)
	rec := &shared.FlowRecord{
		Exporter: "10.0.0.1", DeviceID: 1, InIf: 5, OutIf: 9,
		SrcIP: mustIP16("198.51.100.2"), DstIP: mustIP16("203.0.113.7"),
		SrcPort: 50000, DstPort: 443, Proto: 6, IPVersion: 4,
		SrcAS: 64512, DstAS: 64513, // 解码原值（RIB 未覆盖 198.51.100.2 → 保留）
	}
	p.Enrich(rec)

	// ASN：dst 命中 RIB /24 → 覆盖为 65001；src 未命中 → 保留解码原值 64512
	if rec.DstAS != 65001 {
		t.Errorf("dst_as = %d, want 65001 (rib /24 命中覆盖)", rec.DstAS)
	}
	if rec.SrcAS != 64512 {
		t.Errorf("src_as = %d, want 64512 (rib miss 保留解码值)", rec.SrcAS)
	}
	if rec.SrcGeo != 49 || rec.DstGeo != 86 {
		t.Errorf("geo = %d/%d, want 49/86", rec.SrcGeo, rec.DstGeo)
	}
	if rec.AppID != 20 {
		t.Errorf("app_id = %d, want 20 (tcp/443)", rec.AppID)
	}
	// zone：dst 命中 → zone_id + ZoneSideDst（docs/09 §3）
	if rec.ZoneID != 7 || rec.ZoneSide != uint8(shared.ZoneSideDst) {
		t.Errorf("zone = (%d,%d), want (7,%d)", rec.ZoneID, rec.ZoneSide, shared.ZoneSideDst)
	}
	// if_role：in boundary(bit0) + out internal → 位图 0b01
	if rec.IfRole != shared.IfRoleInBoundary {
		t.Errorf("if_role = %#x, want %#x", rec.IfRole, shared.IfRoleInBoundary)
	}
	// 方向换算唯一依据（docs/09 §3）：dst 命中 → 客户视角 in
	if d := shared.DirectionFromZoneSide(shared.ZoneSide(rec.ZoneSide)); d != shared.DirIn {
		t.Errorf("direction = %d, want DirIn", d)
	}
}

func TestPipelineZoneSideSrc(t *testing.T) {
	p, m, _ := newTestPipeline(t, zone.MatchSrc)
	_ = m
	// src 在 zone、dst 不在 → src 模式命中 side=2 → 客户视角 out
	rec := &shared.FlowRecord{
		DeviceID: 1, InIf: 5, OutIf: 9,
		SrcIP: mustIP16("203.0.113.9"), DstIP: mustIP16("198.51.100.2"),
		Proto: 17, DstPort: 53,
	}
	p.Enrich(rec)
	if rec.ZoneID != 7 || shared.ZoneSide(rec.ZoneSide) != shared.ZoneSideSrc {
		t.Errorf("zone = (%d,%d), want (7,%d)", rec.ZoneID, rec.ZoneSide, shared.ZoneSideSrc)
	}
	if rec.AppID != 21 {
		t.Errorf("app_id = %d, want 21 (udp/53)", rec.AppID)
	}
	if d := shared.DirectionFromZoneSide(shared.ZoneSide(rec.ZoneSide)); d != shared.DirOut {
		t.Errorf("direction = %d, want DirOut", d)
	}

	// dst 模式下同一记录：dst 不在 zone → 未命中
	rec2 := &shared.FlowRecord{SrcIP: mustIP16("203.0.113.9"), DstIP: mustIP16("198.51.100.2")}
	p2, _, _ := newTestPipeline(t, zone.MatchDst)
	p2.Enrich(rec2)
	if rec2.ZoneID != 0 || shared.ZoneSide(rec2.ZoneSide) != shared.ZoneSideNone {
		t.Errorf("dst mode both-side record = (%d,%d), want (0,0)（只标一个客户域）", rec2.ZoneID, rec2.ZoneSide)
	}
}

func TestPipelineIfRoleBitmapAndInternalFilter(t *testing.T) {
	p, _, _ := newTestPipeline(t, zone.MatchDst)

	tests := []struct {
		name     string
		deviceID uint32
		inIf     uint32
		outIf    uint32
		wantBits uint8
		wantDrop bool
	}{
		// 09 §3 裁定：仅 in 与 out 均 internal（两位均 0）才丢弃；boundary↔internal 保留
		{"boundary in + internal out", 1, 5, 9, shared.IfRoleInBoundary, false},
		{"internal in + boundary out", 1, 9, 5, shared.IfRoleOutBoundary, false},
		{"internal both", 2, 1, 2, 0, true},
		{"unknown both (default boundary)", 9, 100, 200, shared.IfRoleInBoundary | shared.IfRoleOutBoundary, false},
	}
	for _, tc := range tests {
		rec := &shared.FlowRecord{DeviceID: tc.deviceID, InIf: tc.inIf, OutIf: tc.outIf}
		p.Enrich(rec)
		if rec.IfRole != tc.wantBits {
			t.Errorf("%s: if_role = %#x, want %#x", tc.name, rec.IfRole, tc.wantBits)
		}
		if got := shared.InternalFilterDrop(rec.IfRole); got != tc.wantDrop {
			t.Errorf("%s: InternalFilterDrop = %v, want %v (09 §3 互联过滤)", tc.name, got, tc.wantDrop)
		}
	}
}

func TestPipelineNilComponentsKeepOriginal(t *testing.T) {
	p := NewPipeline(nil, nil, nil, nil, nil)
	rec := &shared.FlowRecord{
		DeviceID: 1, InIf: 5, OutIf: 9,
		SrcIP: mustIP16("203.0.113.7"), DstIP: mustIP16("198.51.100.1"),
		SrcAS: 111, DstAS: 222, SrcGeo: 1, DstGeo: 2, AppID: 3,
		Proto: 6, DstPort: 443,
	}
	p.Enrich(rec)
	if rec.SrcAS != 111 || rec.DstAS != 222 || rec.SrcGeo != 1 || rec.DstGeo != 2 || rec.AppID != 3 {
		t.Errorf("nil components must not touch fields: %+v", rec)
	}
	if rec.ZoneID != 0 || rec.ZoneSide != 0 {
		t.Errorf("nil zone matcher: zone = (%d,%d), want (0,0)", rec.ZoneID, rec.ZoneSide)
	}
	if rec.IfRole != 0 {
		t.Errorf("nil if_role source: bits = %#x, want 0", rec.IfRole)
	}
}

func TestIfRoleSnapshotHotUpdate(t *testing.T) {
	s := NewIfRoleSnapshot()
	if r := s.Role(1, 5); r != IfRoleUnknown {
		t.Errorf("empty snapshot role = %v, want unknown", r)
	}
	s.Update(map[IfRef]IfRole{{DeviceID: 1, IfIndex: 5}: IfRoleInternal})
	if r := s.Role(1, 5); r != IfRoleInternal {
		t.Errorf("after update role = %v, want internal", r)
	}
	// 全量换表：旧条目消失
	s.Update(map[IfRef]IfRole{{DeviceID: 2, IfIndex: 1}: IfRoleBoundary})
	if r := s.Role(1, 5); r != IfRoleUnknown {
		t.Errorf("after replace role(1,5) = %v, want unknown", r)
	}
}

func TestAppTable(t *testing.T) {
	a := NewAppTable()
	a.Set(6, 443, 20)
	if id := a.AppID(6, 443); id != 20 {
		t.Errorf("hit = %d, want 20", id)
	}
	if id := a.AppID(6, 8443); id != 0 {
		t.Errorf("miss = %d, want 0", id)
	}
	if id := a.AppID(17, 443); id != 0 {
		t.Errorf("proto mismatch = %d, want 0", id)
	}
}
