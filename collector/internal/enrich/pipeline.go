package enrich

import (
	"github.com/SchearLoe/lucidnet/shared"
)

// ZoneMatcher —— zone 匹配面（dd/02 §3.3；生产实现 = collector/internal/zone.Matcher，
// 匹配语义 docs/09 §3：zone_match=dst|src 一侧，一条记录只标一个客户域）。
type ZoneMatcher interface {
	Match(rec *shared.FlowRecord) (zoneID int32, side shared.ZoneSide)
}

// Pipeline —— 富化流水线编排（dd/02 §3 顺序执行：ASN→Geo→App→Zone→IfRole）。
//
// 预算注释（dd/02 §3）：全链路 ≤2µs/条 ——
//
//	ASN 本地 radix ≈200ns + Geo mmdb ≈100ns + App 表直查
//	+ Zone LPM ≤0.5µs（dd/02 §3.3）+ IfRole 原子指针查表。
//
// 各组件可为 nil（对应步骤跳过，字段保持解码原值/零值），便于骨架分阶段组装。
type Pipeline struct {
	rib    RibLookup
	geo    GeoResolver
	apps   AppMapper
	zones  ZoneMatcher
	ifRole IfRoleSource
}

// NewPipeline —— 组装流水线（参数顺序即执行顺序，dd/02 §3）。
func NewPipeline(rib RibLookup, geo GeoResolver, apps AppMapper, zones ZoneMatcher, ifRole IfRoleSource) *Pipeline {
	return &Pipeline{rib: rib, geo: geo, apps: apps, zones: zones, ifRole: ifRole}
}

// Enrich —— 就地富化一条 FlowRecord（热路径：零分配）。
func (p *Pipeline) Enrich(rec *shared.FlowRecord) {
	// 1. ASN/前缀（dd/02 §3.1）：RIB 命中覆盖（RIB 为权威富化源），未命中保留解码器原值。
	if p.rib != nil {
		if r, ok := p.rib.Lookup(rec.SrcIP); ok {
			rec.SrcAS = r.ASN
		}
		if r, ok := p.rib.Lookup(rec.DstIP); ok {
			rec.DstAS = r.ASN
		}
	}
	// 2. Geo（dd/02 §3.2）。
	if p.geo != nil {
		rec.SrcGeo = p.geo.GeoID(rec.SrcIP)
		rec.DstGeo = p.geo.GeoID(rec.DstIP)
	}
	// 3. 应用（dd/02 §3.2）：{proto, 目的端口}→app_id。
	if p.apps != nil {
		rec.AppID = p.apps.AppID(rec.Proto, rec.DstPort)
	}
	// 4. Zone（dd/02 §3.3 / docs/09 §3）：zone_id + zone_side 一次写入，
	//    zone_side 是下游方向换算唯一依据（1=dst 命中→in / 2=src 命中→out）。
	if p.zones != nil {
		id, side := p.zones.Match(rec)
		rec.ZoneID, rec.ZoneSide = id, uint8(side)
	}
	// 5. 接口角色（dd/02 §3.4 / docs/09 §3）：bit0 = in boundary，bit1 = out boundary；
	//    unknown 按 boundary 置位；互联过滤语义 = shared.InternalFilterDrop
	//    （仅 in 与 out 均 internal、两位皆 0 时丢弃）。
	if p.ifRole != nil {
		var bits uint8
		bits |= roleBit(p.ifRole.Role(rec.DeviceID, rec.InIf), shared.IfRoleInBoundary)
		bits |= roleBit(p.ifRole.Role(rec.DeviceID, rec.OutIf), shared.IfRoleOutBoundary)
		rec.IfRole = bits
	}
}
