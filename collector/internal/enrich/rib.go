// Package enrich —— 富化流水线（dd/02 §3：顺序 ASN→Geo→App→Zone→IfRole）。
//
// 全链路预算 ≤2µs/条（dd/02 §3）：
//
//	ASN≈200ns（本地 radix）+ Geo≈100ns（mmdb mmap）+ App 数组直查
//	+ Zone LPM ≤0.5µs（dd/02 §3.3）+ IfRole 查表。
//
// 各步骤为可替换组件（接口 + 开发实现/桩），组装见 cmd/lucid-collector。
package enrich

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"sort"
	"time"
)

// RibResult —— RibNameLookup.Lookup 响应镜像（docs/09 §4：{asn, prefix, peer_as, ts}）。
type RibResult struct {
	ASN    uint32
	PeerAS uint32
	Prefix netip.Prefix
	TS     time.Time
}

// RibLookup —— ASN/前缀富化源（dd/02 §3.1）。
//
// 生产路径：全量 RIB 快照本地 radix（IPv4+IPv6 ≤150 万前缀，≈200ns/条）
// + WatchSnapshot 增量订阅；gRPC Lookup 仅在缓存未命中/回填时使用。
type RibLookup interface {
	// Lookup —— 前缀 LPM；未命中返回 ok=false（调用方保留解码器给出的原值）。
	Lookup(ip [16]byte) (RibResult, bool)
}

// GRPCRIB —— RibNameLookup gRPC 客户端桩（docs/09 §4：服务端 RIB Feeder，:9131）。
//
// TODO(grpc)：接入 gen/go/lucidnet/v1 RibNameLookupClient（proto 生成后）：
//   - Lookup(ip)→{asn,prefix,peer_as,ts}（09 §4 方法签名）；
//   - GetSnapshot()→全量 + WatchSnapshot()→增量，构建本地 radix 缓存（dd/02 §3.1）；
//   - Feeder 不可用：降级旧快照，打点 enrich_rib_stale，超 10min 告警（dd/02 §3.1）。
//
// 桩语义：Lookup 恒未命中（不打断流水线，仅 ASN 富化缺席）。
type GRPCRIB struct {
	target string
}

// NewGRPCRIB —— 构造桩（target 形如 shared.AddrRibNameLookup）。
func NewGRPCRIB(target string) *GRPCRIB { return &GRPCRIB{target: target} }

// Target —— gRPC 目标地址（诊断用）。
func (r *GRPCRIB) Target() string { return r.target }

// Lookup —— TODO(grpc)：真实 gRPC 调用；桩恒 miss。
func (r *GRPCRIB) Lookup(ip [16]byte) (RibResult, bool) { return RibResult{}, false }

// —— 本地快照文件开发实现（dd/02 §3.1“本地缓存”的开发替身） ——

// ribEntryJSON —— 快照文件行（GetSnapshot 全量结果的 JSON 落盘格式）。
type ribEntryJSON struct {
	Prefix string `json:"prefix"`
	ASN    uint32 `json:"asn"`
	PeerAS uint32 `json:"peer_as"`
}

// ribEntry —— 归一化后的表项：128bit 键（v4 占 96..127 位）+ 有效位长。
type ribEntry struct {
	ip     [16]byte
	bitLen int // v4: 96+maskLen(0-32)；v6: maskLen(0-128)
	asn    uint32
	peerAS uint32
	prefix netip.Prefix
}

// SnapshotRIB —— 本地快照文件实现（开发/联调用）。
//
// 与生产差异（TODO(radix)）：线性扫 LPM（按位长降序首个包含即命中），
// 生产换 radix 树（≤150 万前缀 ≈200ns，dd/02 §3.1）；文件格式与
// GetSnapshot 全量结果对齐，接入 gRPC 后同一结构可直接灌树。
type SnapshotRIB struct {
	entries  []ribEntry // bitLen 降序
	LoadedAt time.Time  // 快照时点（stale 判定：RIB Feeder 不可用降级旧快照，>10min 告警）
}

// LoadRibSnapshot —— 从 JSON 快照文件构建（格式见 ribEntryJSON）。
func LoadRibSnapshot(path string) (*SnapshotRIB, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read rib snapshot %s: %w", path, err)
	}
	var rows []ribEntryJSON
	if err := json.Unmarshal(raw, &rows); err != nil {
		return nil, fmt.Errorf("parse rib snapshot %s: %w", path, err)
	}
	entries := make([]ribEntry, 0, len(rows))
	for i, row := range rows {
		e, err := parseRibPrefix(row.Prefix, row.ASN, row.PeerAS)
		if err != nil {
			return nil, fmt.Errorf("rib snapshot %s entry %d: %w", path, i, err)
		}
		entries = append(entries, e)
	}
	// 位长降序：线性扫首个包含即最长前缀（LPM 语义）
	sort.SliceStable(entries, func(i, j int) bool { return entries[i].bitLen > entries[j].bitLen })
	return &SnapshotRIB{entries: entries, LoadedAt: time.Now().UTC()}, nil
}

// Lookup —— LPM：位长降序线性扫（开发实现；生产 radix，dd/02 §3.1）。
func (r *SnapshotRIB) Lookup(ip [16]byte) (RibResult, bool) {
	for _, e := range r.entries {
		if ribContains(e, ip) {
			return RibResult{ASN: e.asn, PeerAS: e.peerAS, Prefix: e.prefix, TS: r.LoadedAt}, true
		}
	}
	return RibResult{}, false
}

// Len —— 表项数（诊断/测试）。
func (r *SnapshotRIB) Len() int { return len(r.entries) }

// ribContains —— 表项是否覆盖 16B 地址（族由 96..127 位是否为 ::ffff: 映射判定）。
func ribContains(e ribEntry, ip [16]byte) bool {
	if isV4Mapped16(e.ip) != isV4Mapped16(ip) {
		return false
	}
	full, rem := e.bitLen/8, e.bitLen%8
	for i := 0; i < full; i++ {
		if e.ip[i] != ip[i] {
			return false
		}
	}
	if rem > 0 {
		mask := byte(0xff << (8 - rem))
		if e.ip[full]&mask != ip[full]&mask {
			return false
		}
	}
	return true
}

// isV4Mapped16 —— 16B 地址是否 ::ffff:a.b.c.d（v4 映射，proto IpEntry 同一表示）。
func isV4Mapped16(b [16]byte) bool {
	for i := 0; i < 10; i++ {
		if b[i] != 0 {
			return false
		}
	}
	return b[10] == 0xff && b[11] == 0xff
}

// parseRibPrefix —— CIDR → ribEntry（v4 → ::ffff: 映射 16B + bitLen=96+m）。
func parseRibPrefix(cidr string, asn, peerAS uint32) (ribEntry, error) {
	p, err := netip.ParsePrefix(cidr)
	if err != nil {
		return ribEntry{}, fmt.Errorf("parse rib prefix %q: %w", cidr, err)
	}
	p = p.Masked()
	var e ribEntry
	e.prefix = p
	if p.Addr().Is4() {
		v4 := p.Addr().As4()
		e.ip[10], e.ip[11] = 0xff, 0xff
		copy(e.ip[12:16], v4[:])
		e.bitLen = 96 + p.Bits()
	} else {
		e.ip = p.Addr().As16()
		e.bitLen = p.Bits()
	}
	e.asn, e.peerAS = asn, peerAS
	return e, nil
}
