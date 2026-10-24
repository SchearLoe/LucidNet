package enrich

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/SchearLoe/lucidnet/shared"
)

func writeTemp(t *testing.T, name, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return path
}

func TestSnapshotRIBLPM(t *testing.T) {
	path := writeTemp(t, "rib.json", `[
		{"prefix":"203.0.113.0/24","asn":65001,"peer_as":64500},
		{"prefix":"203.0.0.0/16","asn":65010,"peer_as":64501},
		{"prefix":"0.0.0.0/0","asn":64512,"peer_as":64512},
		{"prefix":"2001:db8:1::/48","asn":65002,"peer_as":64502},
		{"prefix":"2001:db8::/32","asn":65003,"peer_as":64503}
	]`)
	rib, err := LoadRibSnapshot(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if rib.Len() != 5 {
		t.Fatalf("len = %d, want 5", rib.Len())
	}
	tests := []struct {
		ip     string
		asn    uint32
		peerAS uint32
		prefix string
	}{
		{"203.0.113.9", 65001, 64500, "203.0.113.0/24"}, // /24 最长
		{"203.0.200.1", 65010, 64501, "203.0.0.0/16"},   // 回落 /16
		{"198.51.100.1", 64512, 64512, "0.0.0.0/0"},     // 默认路由
		{"2001:db8:1::1", 65002, 64502, "2001:db8:1::/48"},
		{"2001:db8:2::1", 65003, 64503, "2001:db8::/32"},
	}
	for _, tc := range tests {
		r, ok := rib.Lookup(mustIP16(tc.ip))
		if !ok {
			t.Errorf("lookup %s: miss, want hit", tc.ip)
			continue
		}
		if r.ASN != tc.asn || r.PeerAS != tc.peerAS || r.Prefix.String() != tc.prefix {
			t.Errorf("lookup %s = (asn %d, peer %d, %s), want (%d, %d, %s)",
				tc.ip, r.ASN, r.PeerAS, r.Prefix, tc.asn, tc.peerAS, tc.prefix)
		}
	}
	// v6：默认路由 0.0.0.0/0 不覆盖 v6 空间；2001:dc8:: 不在 2001:db8::/32 内 → miss
	if _, ok := rib.Lookup(mustIP16("2001:dc8::1")); ok {
		t.Error("lookup 2001:dc8::1 = hit, want miss（v4 默认路由不得覆盖 v6）")
	}
}

func TestSnapshotRIBEmptyAndMiss(t *testing.T) {
	rib, err := LoadRibSnapshot(writeTemp(t, "empty.json", `[]`))
	if err != nil {
		t.Fatalf("load empty: %v", err)
	}
	if _, ok := rib.Lookup(mustIP16("1.2.3.4")); ok {
		t.Error("empty snapshot: want miss")
	}
	if rib.LoadedAt.IsZero() {
		t.Error("LoadedAt must be set (stale 判定依据，dd/02 §3.1)")
	}
}

func TestSnapshotRIBErrors(t *testing.T) {
	if _, err := LoadRibSnapshot(filepath.Join(t.TempDir(), "missing.json")); err == nil {
		t.Error("missing file: want error")
	}
	if _, err := LoadRibSnapshot(writeTemp(t, "bad.json", `{not json`)); err == nil {
		t.Error("bad json: want error")
	}
	if _, err := LoadRibSnapshot(writeTemp(t, "badcidr.json", `[{"prefix":"not-a-cidr","asn":1}]`)); err == nil || !strings.Contains(err.Error(), "parse rib prefix") {
		t.Errorf("bad cidr err = %v, want parse rib prefix error", err)
	}
}

func TestGRPCRIBStub(t *testing.T) {
	r := NewGRPCRIB(shared.AddrRibNameLookup)
	if r.Target() != ":9131" {
		t.Errorf("target = %q, want :9131 (shared.AddrRibNameLookup)", r.Target())
	}
	if _, ok := r.Lookup(mustIP16("203.0.113.1")); ok {
		t.Error("stub lookup: want miss")
	}
}
