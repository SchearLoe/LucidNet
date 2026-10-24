package zone

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand"
	"net/netip"
	"strings"
	"sync"
	"testing"

	"github.com/SchearLoe/lucidnet/shared"
)

// mustIPEntry —— CIDR → IPEntry（测试助手）。
func mustIPEntry(cidr string) IPEntry {
	e, err := ipEntryFromCIDR(cidr)
	if err != nil {
		panic(err)
	}
	return e
}

// mustIP16 —— 地址文本 → 16B（v4 用 ::ffff: 映射，测试助手）。
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

func TestRadixLPMV4(t *testing.T) {
	tr := &radixTree{keyLen: 32}
	insert := func(cidr string, zone int32) {
		p := netip.MustParsePrefix(cidr).Masked()
		a := p.Addr().As4()
		tr.insert(key128{hi: uint64(binary.BigEndian.Uint32(a[:])) << 32}, p.Bits(), zone)
	}
	insert("10.0.0.0/8", 1)
	insert("10.1.0.0/16", 2)
	insert("10.1.2.0/24", 3)

	tests := []struct {
		ip    string
		zone  int32
		found bool
	}{
		{"10.1.2.3", 3, true},   // 最长前缀
		{"10.1.9.9", 2, true},   // /16
		{"10.9.9.9", 1, true},   // /8
		{"11.0.0.1", 0, false},  // 未命中
		{"10.1.2.255", 3, true}, // 边界内
		{"10.1.3.0", 2, true},   // /24 外一位
	}
	for _, tc := range tests {
		a := netip.MustParseAddr(tc.ip).As4()
		zid, mask, ok := tr.lookup(key128{hi: uint64(binary.BigEndian.Uint32(a[:])) << 32})
		if ok != tc.found || (ok && (zid != tc.zone || mask == 0)) {
			t.Errorf("lookup %s = (%d,%d,%v), want zone %d found %v", tc.ip, zid, mask, ok, tc.zone, tc.found)
		}
	}
}

func TestRadixLPMV6ChainAcross64Bits(t *testing.T) {
	tr := &radixTree{keyLen: 128}
	insert := func(cidr string, zone int32) {
		p := netip.MustParsePrefix(cidr).Masked()
		a := p.Addr().As16()
		tr.insert(key128{
			hi: binary.BigEndian.Uint64(a[:8]),
			lo: binary.BigEndian.Uint64(a[8:]),
		}, p.Bits(), zone)
	}
	insert("2001:db8::/32", 1)
	insert("2001:db8:0:ffff::/64", 2)
	insert("2001:db8:0:ffff:8000::/81", 3) // >64bit：跨压缩链

	tests := []struct {
		ip    string
		zone  int32
		found bool
	}{
		{"2001:db8:0:ffff:8000::1", 3, true},
		{"2001:db8:0:ffff:1::1", 2, true},
		{"2001:db8:1::1", 1, true},
		{"2001:dc8::1", 0, false},
	}
	for _, tc := range tests {
		a := netip.MustParseAddr(tc.ip).As16()
		zid, _, ok := tr.lookup(key128{hi: binary.BigEndian.Uint64(a[:8]), lo: binary.BigEndian.Uint64(a[8:])})
		if ok != tc.found || (ok && zid != tc.zone) {
			t.Errorf("lookup %s = (%d,%v), want zone %d found %v", tc.ip, zid, ok, tc.zone, tc.found)
		}
	}
}

func TestRadixOverwriteSamePrefix(t *testing.T) {
	tr := &radixTree{keyLen: 32}
	k := key128{hi: uint64(0x0A000000) << 32} // 10.0.0.0
	tr.insert(k, 8, 1)
	tr.insert(k, 8, 2)
	zid, mask, ok := tr.lookup(k)
	if !ok || zid != 2 || mask != 8 {
		t.Errorf("overwrite = (%d,%d,%v), want (2,8,true)", zid, mask, ok)
	}
}

// —— fork 回归（历史上 insertNode 分叉路径子节点 skip 未丢弃分叉位，导致 lookup 错位一位） ——

func v4KeyOf(ip string) key128 {
	a := netip.MustParseAddr(ip).As4()
	return key128{hi: uint64(binary.BigEndian.Uint32(a[:])) << 32}
}

func TestRadixForkSiblingPrefixes(t *testing.T) {
	// 兄弟前缀在同一压缩段内分叉（10/8 与 11/8 公共前缀 7 位 < 8 位）
	tr := &radixTree{keyLen: 32}
	tr.insert(v4KeyOf("10.0.0.0"), 8, 1)
	tr.insert(v4KeyOf("11.0.0.0"), 8, 2)
	tests := []struct {
		ip   string
		zone int32
	}{
		{"11.0.0.1", 2}, {"11.255.255.255", 2}, {"11.128.0.1", 2},
		{"10.0.0.1", 1}, {"10.255.255.255", 1},
		{"12.0.0.1", 0},
	}
	for _, tc := range tests {
		if zid, _, ok := tr.lookup(v4KeyOf(tc.ip)); !ok != (tc.zone == 0) || (ok && zid != tc.zone) {
			t.Errorf("lookup %s = (%d,%v), want zone %d", tc.ip, zid, ok, tc.zone)
		}
	}
}

func TestRadixForkShallowInsideDeep(t *testing.T) {
	// c==remaining 分叉：/8 在 /9 压缩段内结束；查询分叉位后各位取值不同的地址
	tr := &radixTree{keyLen: 32}
	tr.insert(v4KeyOf("10.128.0.0"), 9, 9)
	tr.insert(v4KeyOf("10.0.0.0"), 8, 8)
	tests := []struct {
		ip   string
		zone int32
	}{
		{"10.128.0.5", 9}, // 分叉位=1 且次位=0（曾因错位 miss /9）
		{"10.130.0.5", 9}, // LPM 曾被破坏为 /8
		{"10.200.1.1", 9},
		{"10.255.255.255", 9},
		{"10.1.1.1", 8},
		{"10.127.255.255", 8},
	}
	for _, tc := range tests {
		if zid, _, ok := tr.lookup(v4KeyOf(tc.ip)); !ok || zid != tc.zone {
			t.Errorf("lookup %s = (%d,%v), want (%d,true)", tc.ip, zid, ok, tc.zone)
		}
	}
}

func TestRadixForkV6Cross64(t *testing.T) {
	// v6 高 64 位内分叉 + 跨 64 位链上分叉
	tr := &radixTree{keyLen: 128}
	insert := func(cidr string, zone int32) {
		p := netip.MustParsePrefix(cidr).Masked()
		a := p.Addr().As16()
		tr.insert(key128{hi: binary.BigEndian.Uint64(a[:8]), lo: binary.BigEndian.Uint64(a[8:])}, p.Bits(), zone)
	}
	insert("2001:db8::/32", 1)
	insert("2001:db8:8000::/33", 2) // 与 /32 在第 32 位分叉
	insert("2001:db8:0:0:8000::/65", 3)
	insert("2001:db8:0:0:8000:8000::/96", 4) // 跨 64 位边界的深前缀
	tests := []struct {
		ip   string
		zone int32
	}{
		{"2001:db8:8000::1", 2},
		{"2001:db8:7fff::1", 1},
		{"2001:db8::1", 1},
		{"2001:db8:0:0:8000::1", 3},
		{"2001:db8:0:0:8000:8000::1", 4},
		{"2001:db8:0:0:8000:7fff::1", 3},
		{"2001:db9::1", 0},
	}
	for _, tc := range tests {
		a := netip.MustParseAddr(tc.ip).As16()
		k := key128{hi: binary.BigEndian.Uint64(a[:8]), lo: binary.BigEndian.Uint64(a[8:])}
		if zid, _, ok := tr.lookup(k); !ok != (tc.zone == 0) || (ok && zid != tc.zone) {
			t.Errorf("lookup %s = (%d,%v), want zone %d", tc.ip, zid, ok, tc.zone)
		}
	}
}

// —— 随机压测：radix LPM vs 暴力参照 ——

// contains16 —— 前缀是否包含 16B 地址（v4 前缀与 v4 映射地址同族判定）。
// v4 的 32 位位于 128bit 空间的 96..127（::ffff:/96 映射），比较时按有效位长展开。
func contains16(p netip.Prefix, b [16]byte) bool {
	var pb [16]byte
	v4 := p.Addr().Is4()
	if v4 {
		v4b := p.Addr().As4()
		pb[10], pb[11] = 0xff, 0xff
		copy(pb[12:16], v4b[:])
	} else {
		pb = p.Addr().As16()
	}
	if v4 != isV4Mapped16(b) {
		return false
	}
	bitLen := p.Bits()
	if v4 {
		bitLen += 96
	}
	full, rem := bitLen/8, bitLen%8
	for i := 0; i < full; i++ {
		if pb[i] != b[i] {
			return false
		}
	}
	if rem > 0 {
		mask := byte(0xff << (8 - rem))
		if pb[full]&mask != b[full]&mask {
			return false
		}
	}
	return true
}

func TestRadixRandomStressVsBruteForce(t *testing.T) {
	const rounds = 40
	for round := 0; round < rounds; round++ {
		rng := rand.New(rand.NewSource(int64(round) + 1))
		type entry struct {
			p    netip.Prefix
			zone int32
		}
		seen := make(map[string]bool)
		var entries []entry
		for i := 0; i < 60; i++ {
			var p netip.Prefix
			if rng.Intn(2) == 0 { // v4
				var a [4]byte
				rng.Read(a[:])
				p = netip.PrefixFrom(netip.AddrFrom4(a), 1+rng.Intn(32))
			} else { // v6
				var a [16]byte
				rng.Read(a[:])
				p = netip.PrefixFrom(netip.AddrFrom16(a), 1+rng.Intn(128))
			}
			p = p.Masked()
			if seen[p.String()] {
				continue
			}
			seen[p.String()] = true
			entries = append(entries, entry{p, int32(i + 1)})
		}
		v4tr, v6tr := &radixTree{keyLen: 32}, &radixTree{keyLen: 128}
		// 打乱插入顺序
		rng.Shuffle(len(entries), func(i, j int) { entries[i], entries[j] = entries[j], entries[i] })
		for _, e := range entries {
			var b [16]byte
			if e.p.Addr().Is4() {
				v4 := e.p.Addr().As4()
				b[10], b[11] = 0xff, 0xff
				copy(b[12:16], v4[:])
				_, k := keyOf16(b)
				v4tr.insert(k, e.p.Bits(), e.zone)
			} else {
				b = e.p.Addr().As16()
				_, k := keyOf16(b)
				v6tr.insert(k, e.p.Bits(), e.zone)
			}
		}
		// 查询集合：随机地址 + 各前缀网络地址（边界）
		var queries [][16]byte
		for i := 0; i < 300; i++ {
			var b [16]byte
			rng.Read(b[:])
			queries = append(queries, b)
		}
		for _, e := range entries {
			if e.p.Addr().Is4() {
				v4 := e.p.Addr().As4()
				var b [16]byte
				b[10], b[11] = 0xff, 0xff
				copy(b[12:16], v4[:])
				queries = append(queries, b)
			} else {
				queries = append(queries, e.p.Addr().As16())
			}
		}
		for _, q := range queries {
			// 暴力参照：最长覆盖前缀
			wantZone, wantMask, found := int32(0), -1, false
			for _, e := range entries {
				if contains16(e.p, q) && e.p.Bits() > wantMask {
					wantZone, wantMask, found = e.zone, e.p.Bits(), true
				}
			}
			famV4, k := keyOf16(q)
			tr := v6tr
			if famV4 {
				tr = v4tr
			}
			zid, mask, ok := tr.lookup(k)
			if ok != found || (ok && (zid != wantZone || mask != wantMask)) {
				var buf strings.Builder
				buf.WriteString("\nentries:\n")
				for _, e := range entries {
					fmt.Fprintf(&buf, "  %s -> %d\n", e.p, e.zone)
				}
				t.Fatalf("round %d: lookup %s = (%d,%d,%v), want (%d,%d,%v)%s",
					round, netip.AddrFrom16(q), zid, mask, ok, wantZone, wantMask, found, buf.String())
			}
		}
	}
}

// TestMatcherRandomDisjointStress —— Matcher 级随机压测：两两不相交前缀（+同前缀重复 zone）
// → 期望 = 覆盖前缀的最小 zone id；同时覆盖 exact 哈希与 radix 两条路径。
func TestMatcherRandomDisjointStress(t *testing.T) {
	const rounds = 20
	for round := 0; round < rounds; round++ {
		rng := rand.New(rand.NewSource(int64(round) + 1000))
		var picked []netip.Prefix
		disjoint := func(p netip.Prefix) bool {
			for _, q := range picked {
				if contains16(p, addr16Of(q)) || contains16(q, addr16Of(p)) {
					return false
				}
			}
			return true
		}
		var specs []ZoneSpec
		for i := 0; i < 40; i++ {
			var p netip.Prefix
			if rng.Intn(2) == 0 {
				var a [4]byte
				rng.Read(a[:])
				// v4：一半概率全长掩码（走 exact 哈希路径）
				bits := 32
				if rng.Intn(2) == 0 {
					bits = 1 + rng.Intn(31)
				}
				p = netip.PrefixFrom(netip.AddrFrom4(a), bits)
			} else {
				var a [16]byte
				rng.Read(a[:])
				bits := 128
				if rng.Intn(2) == 0 {
					bits = 1 + rng.Intn(127)
				}
				p = netip.PrefixFrom(netip.AddrFrom16(a), bits)
			}
			p = p.Masked()
			if !disjoint(p) {
				continue
			}
			picked = append(picked, p)
			specs = append(specs, ZoneSpec{ID: int32(i + 1), IPs: []IPEntry{mustIPEntry(p.String())}})
			if rng.Intn(4) == 0 { // 同前缀重复：更大 id → 期望取小
				specs = append(specs, ZoneSpec{ID: int32(100 + i), IPs: []IPEntry{mustIPEntry(p.String())}})
			}
		}
		m := NewMatcher(MatchDst)
		if err := m.Update(specs); err != nil {
			t.Fatalf("round %d: update: %v", round, err)
		}
		var queries [][16]byte
		for i := 0; i < 200; i++ {
			var b [16]byte
			rng.Read(b[:])
			queries = append(queries, b)
		}
		for _, p := range picked {
			queries = append(queries, addr16Of(p))
		}
		for _, q := range queries {
			wantZone, wantMask := int32(0), -1
			for _, s := range specs {
				for _, e := range s.IPs {
					if contains16Entry(e.Prefix, int(e.MaskLen), q) && int(e.MaskLen) > wantMask {
						wantZone, wantMask = s.ID, int(e.MaskLen)
					}
				}
			}
			// 同前缀多 zone：等长覆盖中取小 id
			for _, s := range specs {
				for _, e := range s.IPs {
					if contains16Entry(e.Prefix, int(e.MaskLen), q) && int(e.MaskLen) == wantMask && s.ID < wantZone {
						wantZone = s.ID
					}
				}
			}
			zid, ok := m.Lookup(q)
			if ok != (wantMask >= 0) || (ok && zid != wantZone) {
				t.Fatalf("round %d: lookup %s = (%d,%v), want (%d,%v)",
					round, netip.AddrFrom16(q), zid, ok, wantZone, wantMask >= 0)
			}
		}
	}
}

// addr16Of —— 前缀网络地址 → 16B。
func addr16Of(p netip.Prefix) [16]byte {
	if p.Addr().Is4() {
		var b [16]byte
		v4 := p.Addr().As4()
		b[10], b[11] = 0xff, 0xff
		copy(b[12:16], v4[:])
		return b
	}
	return p.Addr().As16()
}

// isV4Mapped16 —— 16B 地址是否 v4 映射形式。
func isV4Mapped16(b [16]byte) bool {
	for i := 0; i < 10; i++ {
		if b[i] != 0 {
			return false
		}
	}
	return b[10] == 0xff && b[11] == 0xff
}

// contains16Entry —— IPEntry(16B 前缀 + 掩码) 是否覆盖 16B 地址（同族）。
// v4 映射形式的 32 位位于 128bit 空间的 96..127，按有效位长展开比较。
func contains16Entry(prefix [16]byte, maskLen int, ip [16]byte) bool {
	v4 := isV4Mapped16(prefix)
	if v4 != isV4Mapped16(ip) {
		return false
	}
	if maskLen < 0 {
		return false
	}
	bitLen := maskLen
	if v4 {
		bitLen += 96
	}
	full, rem := bitLen/8, bitLen%8
	for i := 0; i < full; i++ {
		if prefix[i] != ip[i] {
			return false
		}
	}
	if rem > 0 {
		mask := byte(0xff << (8 - rem))
		if prefix[full]&mask != ip[full]&mask {
			return false
		}
	}
	return true
}

func TestRadixSplitShallowerIntoDeepChain(t *testing.T) {
	// 先插 /9（长链），再插 /8（在压缩段内结束）→ 需要拆分并挂 entry
	tr := &radixTree{keyLen: 32}
	insert := func(cidr string, zone int32) {
		p := netip.MustParsePrefix(cidr).Masked()
		a := p.Addr().As4()
		tr.insert(key128{hi: uint64(binary.BigEndian.Uint32(a[:])) << 32}, p.Bits(), zone)
	}
	insert("10.128.0.0/9", 9)
	insert("10.0.0.0/8", 8)
	if zid, _, ok := tr.lookup(key128{hi: uint64(binary.BigEndian.Uint32([]byte{10, 200, 1, 1})) << 32}); !ok || zid != 9 {
		t.Errorf("10.200.1.1 = %d,%v want 9", zid, ok)
	}
	if zid, _, ok := tr.lookup(key128{hi: uint64(binary.BigEndian.Uint32([]byte{10, 1, 1, 1})) << 32}); !ok || zid != 8 {
		t.Errorf("10.1.1.1 = %d,%v want 8", zid, ok)
	}
}

func TestMatcherHitAndMiss(t *testing.T) {
	m := NewMatcher(MatchDst)
	err := m.Update([]ZoneSpec{
		{ID: 7, Name: "cust-a", IPs: []IPEntry{mustIPEntry("203.0.113.0/24"), mustIPEntry("2001:db8:1::/64")}},
		{ID: 8, Name: "cust-b", IPs: []IPEntry{mustIPEntry("203.0.113.77/32")}},
	})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	tests := []struct {
		ip    string
		zone  int32
		found bool
	}{
		{"203.0.113.7", 7, true},    // /24
		{"203.0.113.77", 7, true},   // /32(77, zone8) 与 /24(zone7) 重叠 → 强制场景取小 id（dd/02 §3.3）
		{"203.0.113.78", 7, true},   // 回落 /24
		{"203.0.114.1", 0, false},   // 未命中
		{"2001:db8:1::ab", 7, true}, // v6
		{"2001:db8:2::1", 0, false},
	}
	for _, tc := range tests {
		zid, ok := m.Lookup(mustIP16(tc.ip))
		if ok != tc.found || (ok && zid != tc.zone) {
			t.Errorf("lookup %s = (%d,%v), want (%d,%v)", tc.ip, zid, ok, tc.zone, tc.found)
		}
	}
}

func TestMatcherMatchFieldDstSrc(t *testing.T) {
	m := NewMatcher(MatchDst)
	if err := m.Update([]ZoneSpec{{ID: 7, IPs: []IPEntry{mustIPEntry("203.0.113.0/24")}}}); err != nil {
		t.Fatalf("update: %v", err)
	}
	rec := &shared.FlowRecord{SrcIP: mustIP16("198.51.100.1"), DstIP: mustIP16("203.0.113.7")}

	// dst 模式（默认）：命中 → side=1（ZoneSideDst）→ 客户视角 in（docs/09 §3 方向换算唯一依据）
	if id, side := m.Match(rec); id != 7 || side != shared.ZoneSideDst {
		t.Errorf("dst mode = (%d,%d), want (7,%d)", id, side, shared.ZoneSideDst)
	}
	if d := shared.DirectionFromZoneSide(shared.ZoneSideDst); d != shared.DirIn {
		t.Errorf("DirectionFromZoneSide(dst) = %d, want %d", d, shared.DirIn)
	}

	// src 模式：同一记录 dst 命中不算；src 命中 → side=2 → out
	m.SetMatchField(MatchSrc)
	if id, side := m.Match(rec); id != 0 || side != shared.ZoneSideNone {
		t.Errorf("src mode (src not in zone) = (%d,%d), want (0,0)", id, side)
	}
	rec2 := &shared.FlowRecord{SrcIP: mustIP16("203.0.113.7"), DstIP: mustIP16("198.51.100.1")}
	if id, side := m.Match(rec2); id != 7 || side != shared.ZoneSideSrc {
		t.Errorf("src mode = (%d,%d), want (7,%d)", id, side, shared.ZoneSideSrc)
	}
	if d := shared.DirectionFromZoneSide(shared.ZoneSideSrc); d != shared.DirOut {
		t.Errorf("DirectionFromZoneSide(src) = %d, want %d", d, shared.DirOut)
	}
}

func TestMatcherHotUpdateSwap(t *testing.T) {
	m := NewMatcher(MatchDst)
	specsA := []ZoneSpec{{ID: 1, IPs: []IPEntry{mustIPEntry("10.0.0.0/8")}}}
	if err := m.Update(specsA); err != nil {
		t.Fatalf("update: %v", err)
	}
	rec := &shared.FlowRecord{DstIP: mustIP16("10.1.2.3")}
	if id, _ := m.Match(rec); id != 1 {
		t.Fatalf("before hot update = %d, want 1", id)
	}
	// 热更：改派 zone 2 —— Update 返回后新查询立即可见；
	// “≤2s 生效”由 etcd watch → Update 的投递路径保证（docs/09 §5），匹配器本身原子换树。
	if err := m.Update([]ZoneSpec{{ID: 2, IPs: []IPEntry{mustIPEntry("10.0.0.0/8")}}}); err != nil {
		t.Fatalf("hot update: %v", err)
	}
	if id, side := m.Match(rec); id != 2 || side != shared.ZoneSideDst {
		t.Errorf("after hot update = (%d,%d), want (2,%d)", id, side, shared.ZoneSideDst)
	}
	// 移除全部 → 未命中
	if err := m.Update(nil); err != nil {
		t.Fatalf("update nil: %v", err)
	}
	if id, side := m.Match(rec); id != 0 || side != shared.ZoneSideNone {
		t.Errorf("after remove = (%d,%d), want (0,0)", id, side)
	}
}

func TestMatcherConcurrentMatchDuringUpdate(t *testing.T) {
	m := NewMatcher(MatchDst)
	if err := m.Update([]ZoneSpec{{ID: 1, IPs: []IPEntry{mustIPEntry("10.0.0.0/8")}}}); err != nil {
		t.Fatalf("update: %v", err)
	}
	rec := &shared.FlowRecord{DstIP: mustIP16("10.1.2.3")}
	var wg sync.WaitGroup
	stop := make(chan struct{})
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					id, _ := m.Match(rec) // 任意时刻命中 1 或 2，绝不 panic
					if id != 1 && id != 2 && id != 0 {
						t.Errorf("unexpected zone %d", id)
						return
					}
				}
			}
		}()
	}
	for i := 0; i < 100; i++ {
		if err := m.Update([]ZoneSpec{{ID: 1 + int32(i%2), IPs: []IPEntry{mustIPEntry("10.0.0.0/8")}}}); err != nil {
			t.Fatalf("update: %v", err)
		}
	}
	close(stop)
	wg.Wait()
}

func TestMatcherOverlapSmallestIDWins(t *testing.T) {
	// dd/02 §3.3：一条 IP 同属多 zone（强制场景）→ 取小 id；结果与录入顺序无关
	build := func(order []ZoneSpec) *Matcher {
		m := NewMatcher(MatchDst)
		if err := m.Update(order); err != nil {
			t.Fatalf("update: %v", err)
		}
		return m
	}
	deep := ZoneSpec{ID: 3, IPs: []IPEntry{mustIPEntry("203.0.113.9/32")}}
	wide := ZoneSpec{ID: 5, IPs: []IPEntry{mustIPEntry("203.0.113.0/24")}}
	small := ZoneSpec{ID: 3, IPs: []IPEntry{mustIPEntry("203.0.113.0/24")}}
	large := ZoneSpec{ID: 9, IPs: []IPEntry{mustIPEntry("203.0.113.9/32")}}

	// 嵌套重叠：/32(id3) 压制 /24(id5) 上的 .9，其余回落 /24(id5)
	for name, m := range map[string]*Matcher{
		"deep-first": build([]ZoneSpec{deep, wide}),
		"wide-first": build([]ZoneSpec{wide, deep}),
	} {
		if zid, ok := m.Lookup(mustIP16("203.0.113.9")); !ok || zid != 3 {
			t.Errorf("%s: 203.0.113.9 = (%d,%v), want (3,true)", name, zid, ok)
		}
		if zid, ok := m.Lookup(mustIP16("203.0.113.8")); !ok || zid != 5 {
			t.Errorf("%s: 203.0.113.8 = (%d,%v), want (5,true)", name, zid, ok)
		}
	}
	// 同前缀重复：小 id(3) 生效，大 id(9) 被压制；.8 仅 /24(id3) 覆盖
	m := build([]ZoneSpec{large, small})
	if zid, ok := m.Lookup(mustIP16("203.0.113.9")); !ok || zid != 3 {
		t.Errorf("same-prefix: 203.0.113.9 = (%d,%v), want (3,true)", zid, ok)
	}
	if zid, ok := m.Lookup(mustIP16("203.0.113.8")); !ok || zid != 3 {
		t.Errorf("same-prefix: 203.0.113.8 = (%d,%v), want (3,true)", zid, ok)
	}
}

func TestMatcherInvalidSpecs(t *testing.T) {
	tests := []struct {
		name  string
		specs []ZoneSpec
	}{
		{"zero id", []ZoneSpec{{ID: 0, IPs: []IPEntry{mustIPEntry("10.0.0.0/8")}}}},
		{"negative id", []ZoneSpec{{ID: -1}}},
		{"v4 mask overflow", []ZoneSpec{{ID: 1, IPs: []IPEntry{IPEntry{Prefix: mustIP16("10.0.0.0"), MaskLen: 33}}}}},
		{"v6 mask overflow", []ZoneSpec{{ID: 1, IPs: []IPEntry{IPEntry{Prefix: mustIP16("2001:db8::1"), MaskLen: 129}}}}},
		{"negative mask", []ZoneSpec{{ID: 1, IPs: []IPEntry{IPEntry{Prefix: mustIP16("10.0.0.0"), MaskLen: -1}}}}},
	}
	for _, tc := range tests {
		m := NewMatcher(MatchDst)
		if err := m.Update(tc.specs); !errors.Is(err, ErrInvalidSpec) {
			t.Errorf("%s: err = %v, want ErrInvalidSpec", tc.name, err)
		}
	}
}

func TestParseSpecsJSON(t *testing.T) {
	data := []byte(`[
		{"id":1,"name":"cust-a","tenant":"t1",
		 "ips":[{"prefix":"203.0.113.0/24"},{"prefix":"2001:db8:1::/64"}],
		 "boundary_ifs":[{"device_id":11,"if_index":2}],
		 "policy_id":7}
	]`)
	specs, err := ParseSpecsJSON(data)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(specs) != 1 || specs[0].ID != 1 || len(specs[0].IPs) != 2 || specs[0].PolicyID != 7 {
		t.Fatalf("unexpected specs: %+v", specs)
	}
	if len(specs[0].BoundaryIFs) != 1 || specs[0].BoundaryIFs[0].IfIndex != 2 {
		t.Fatalf("unexpected boundary ifs: %+v", specs[0].BoundaryIFs)
	}
	m := NewMatcher(MatchDst)
	if err := m.Update(specs); err != nil {
		t.Fatalf("update: %v", err)
	}
	if zid, ok := m.Lookup(mustIP16("203.0.113.1")); !ok || zid != 1 {
		t.Errorf("v4 lookup = (%d,%v)", zid, ok)
	}
	if zid, ok := m.Lookup(mustIP16("2001:db8:1::5")); !ok || zid != 1 {
		t.Errorf("v6 lookup = (%d,%v)", zid, ok)
	}

	if _, err := ParseSpecsJSON([]byte(`[{"id":1,"ips":[{"prefix":"not-a-cidr"}]}]`)); err == nil || !strings.Contains(err.Error(), "parse prefix") {
		t.Errorf("bad cidr err = %v, want prefix parse error", err)
	}
}

func TestParseMatchField(t *testing.T) {
	if f, err := ParseMatchField(""); err != nil || f != MatchDst {
		t.Errorf("empty = (%v,%v), want (dst,nil)", f, err)
	}
	if f, err := ParseMatchField("src"); err != nil || f != MatchSrc {
		t.Errorf("src = (%v,%v)", f, err)
	}
	if _, err := ParseMatchField("both"); !errors.Is(err, ErrInvalidSpec) {
		t.Errorf("both err = %v, want ErrInvalidSpec（docs/09 §3 禁止 both）", err)
	}
}
