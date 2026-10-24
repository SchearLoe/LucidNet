package zone

import (
	"cmp"
	"encoding/binary"
	"fmt"
	"net/netip"
	"slices"
	"sync/atomic"

	"github.com/SchearLoe/lucidnet/shared"
)

// Matcher —— 双栈 Zone 匹配器（R2 关键路径，dd/02 §3.3）。
//
// 快照不可变；Update 全量重建新快照后以原子指针替换（copy-on-write），
// 在读的旧快照不受影响，热更新对后续查询立即可见。
// etcd /lucid/zones watch → Update 的投递路径保证“写后 ≤2s 全节点可见”（docs/09 §5）。
type Matcher struct {
	field atomic.Uint32 // MatchField（zone_match=dst|src，docs/09 §3）
	snap  atomic.Pointer[snapshot]
}

// NewMatcher —— 构造匹配器（空表：全部未命中）。
func NewMatcher(f MatchField) *Matcher {
	m := &Matcher{}
	m.field.Store(uint32(f))
	m.snap.Store(&snapshot{exact: make(map[[16]byte]int32)})
	return m
}

// MatchField / SetMatchField —— 匹配面读取与切换（docs/09 §3：dst|src，禁止 both）。
func (m *Matcher) MatchField() MatchField     { return MatchField(m.field.Load()) }
func (m *Matcher) SetMatchField(f MatchField) { m.field.Store(uint32(f)) }

// Update —— 用新 ZoneSpec 全量构建快照并原子换树（dd/02 §3.3 热更新）。
func (m *Matcher) Update(specs []ZoneSpec) error {
	snap, err := buildSnapshot(specs)
	if err != nil {
		return err
	}
	m.snap.Store(snap)
	return nil
}

// Match —— 按 docs/09 §3 匹配一条流记录：
// 只查 zone_match 指定的一侧（禁止 both）；命中返回 (zone_id, ZoneSideDst|ZoneSideSrc)，
// 未命中返回 (0, ZoneSideNone)。zone_side 是下游方向换算的唯一依据。
func (m *Matcher) Match(rec *shared.FlowRecord) (int32, shared.ZoneSide) {
	var ip [16]byte
	side := shared.ZoneSideNone
	switch m.MatchField() {
	case MatchSrc:
		ip, side = rec.SrcIP, shared.ZoneSideSrc
	default: // MatchDst（默认 dst）
		ip, side = rec.DstIP, shared.ZoneSideDst
	}
	id, ok := m.snap.Load().lookup(ip)
	if !ok {
		return 0, shared.ZoneSideNone
	}
	return id, side
}

// Lookup —— 直接按 16B 地址查（运维/测试用；不做 dst/src 语义）。
func (m *Matcher) Lookup(ip [16]byte) (int32, bool) {
	return m.snap.Load().lookup(ip)
}

// snapshot —— 不可变匹配快照：单 IP 哈希表（掩码全长）+ v4/v6 两棵 radix（dd/02 §3.3 两级结构）。
// radix 树内同时保留全长条目（exact 表仅作加速，二者结果恒一致）。
type snapshot struct {
	exact map[[16]byte]int32
	v4    *radixTree
	v6    *radixTree
}

func (s *snapshot) lookup(ip [16]byte) (int32, bool) {
	if id, ok := s.exact[ip]; ok {
		return id, true
	}
	famV4, k := keyOf16(ip)
	tree := s.v6
	if famV4 {
		tree = s.v4
	}
	if tree == nil {
		return 0, false
	}
	id, _, ok := tree.lookup(k)
	return id, ok
}

// prefixEntry —— 构建期中间表示。
type prefixEntry struct {
	ip      [16]byte
	famV4   bool
	maskLen int
	zone    int32
	key     key128
}

// buildSnapshot —— 全量构建：
//  1. 校验（id>0；v4 掩码 0-32 / v6 掩码 0-128）；
//  2. 按 (mask_len, key, zone_id) 升序插入，已有覆盖条目 id 更小则压制新条目
//     —— 等价于“一条 IP 同属多 zone 时取小 zone_id”（dd/02 §3.3 强制场景 zone_priority 兜底）；
//  3. 全长掩码条目同时进单 IP 哈希表。
func buildSnapshot(specs []ZoneSpec) (*snapshot, error) {
	entries := make([]prefixEntry, 0, 64)
	for _, z := range specs {
		if z.ID <= 0 {
			return nil, fmt.Errorf("zone id %d: %w (zone_id 0 = 未命中保留，docs/09 §3)", z.ID, ErrInvalidSpec)
		}
		for i, e := range z.IPs {
			famV4, k := keyOf16(e.Prefix)
			maxLen := 128
			if famV4 {
				maxLen = 32
			}
			if e.MaskLen < 0 || int(e.MaskLen) > maxLen {
				return nil, fmt.Errorf("zone %d ip entry %d: mask_len %d out of range (v4 0-32 / v6 0-128): %w", z.ID, i, e.MaskLen, ErrInvalidSpec)
			}
			entries = append(entries, prefixEntry{ip: e.Prefix, famV4: famV4, maskLen: int(e.MaskLen), zone: z.ID, key: k})
		}
	}
	slices.SortFunc(entries, func(a, b prefixEntry) int {
		if c := cmp.Compare(a.maskLen, b.maskLen); c != 0 {
			return c
		}
		if c := cmp.Compare(a.key.hi, b.key.hi); c != 0 {
			return c
		}
		if c := cmp.Compare(a.key.lo, b.key.lo); c != 0 {
			return c
		}
		return cmp.Compare(a.zone, b.zone)
	})
	snap := &snapshot{
		exact: make(map[[16]byte]int32),
		v4:    &radixTree{keyLen: 32},
		v6:    &radixTree{keyLen: 128},
	}
	for _, e := range entries {
		tree, keyLen := snap.v6, 128
		if e.famV4 {
			tree, keyLen = snap.v4, 32
		}
		if zid, _, ok := tree.lookup(e.key); ok && zid <= e.zone {
			continue // 已有 id 更小的覆盖条目 → 压制（dd/02 §3.3 取小 id）
		}
		tree.insert(e.key, e.maskLen, e.zone)
		if e.maskLen == keyLen {
			snap.exact[e.ip] = e.zone
		}
	}
	return snap, nil
}

// keyOf16 —— 16B 地址 → (是否 v4 映射, 128bit 键)。
// v4 用 ::ffff:/96 映射表示（proto zone.proto IpEntry.prefix），键放高 32bit。
// 注意：netip.Addr.Is4 对 4-in-6 映射地址返回 false（须用 Is4In6 判定，
// 否则 v4 条目会被误判为 v6、落入 v6 树导致跨族误命中）。
func keyOf16(b [16]byte) (famV4 bool, k key128) {
	if netip.AddrFrom16(b).Is4In6() {
		return true, key128{hi: uint64(binary.BigEndian.Uint32(b[12:16])) << 32}
	}
	return false, key128{hi: binary.BigEndian.Uint64(b[0:8]), lo: binary.BigEndian.Uint64(b[8:16])}
}
