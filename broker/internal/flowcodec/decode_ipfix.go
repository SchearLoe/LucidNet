package flowcodec

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"

	"github.com/SchearLoe/lucidnet/shared"
)

// IPFIX 解码（RFC 7011；代理路径按需解码）。与 v9 共用模板布局与 TemplateCache
// （差异：set id 2/3、options 模板头按字段数、变长字段支持）；相对时间 IE
// （flowStart/EndSysUpTime）经 systemInitTimeMilliseconds(160) 锚点换算，
// 无锚点时回退报文头 Export Time（限制见最终报告）。

const ipfixMinDataTemplateID = 256

// IPFIXHeader —— IPFIX Message Header（RFC 7011 §3.1）。
type IPFIXHeader struct {
	Version     uint16
	Length      uint16
	ExportTime  uint32 // epoch 秒
	Sequence    uint32 // 数据记录计数（导出侧，审计参考）
	ObsDomainID uint32 // 模板作用域
}

// DecodeIPFIX —— IPFIX Message → FlowRecord 列表 + 头摘录 + 逐 set 异常计数。
// 模板缺失不视为致命错误：相应数据集跳过并计入 DecodeStats，包内其余 set
// 正常解码（不 panic、不阻塞热路径）。
func DecodeIPFIX(datagram []byte, exporter netip.Addr, tc *TemplateCache) ([]shared.FlowRecord, IPFIXHeader, DecodeStats, error) {
	if !exporter.IsValid() {
		return nil, IPFIXHeader{}, DecodeStats{}, errors.New("decode ipfix: invalid exporter address")
	}
	if len(datagram) < ipfixHeaderLen {
		return nil, IPFIXHeader{}, DecodeStats{}, fmt.Errorf("decode ipfix from %s: %w", exporter, ErrHeaderTooShort)
	}
	var h IPFIXHeader
	h.Version = binary.BigEndian.Uint16(datagram[0:2])
	if h.Version != ipfixVersion {
		return nil, h, DecodeStats{}, fmt.Errorf("decode ipfix from %s: got version %d: %w", exporter, h.Version, ErrVersionMismatch)
	}
	h.Length = binary.BigEndian.Uint16(datagram[2:4])
	h.ExportTime = binary.BigEndian.Uint32(datagram[4:8])
	h.Sequence = binary.BigEndian.Uint32(datagram[8:12])
	h.ObsDomainID = binary.BigEndian.Uint32(datagram[12:16])

	exp := exporter.String()
	tb := timeBase{exportMs: int64(h.ExportTime) * 1000, bootMs: -1}
	if boot, ok := tc.Anchor(exp, h.ObsDomainID); ok {
		tb.bootMs = boot
	}
	recs, stats := decodeIPFIXBody(datagram[ipfixHeaderLen:], exp, h.ObsDomainID, &tb, tc)
	return recs, h, stats, nil
}

// decodeIPFIXBody —— IPFIX Set 序列走查（set 长度含 4B 对齐 padding，
// 按 Length 整步推进；模板/options 模板学习，数据集解码）。
func decodeIPFIXBody(body []byte, exporter string, obsDomain uint32, tb *timeBase, tc *TemplateCache) ([]shared.FlowRecord, DecodeStats) {
	key := TemplateKey{Exporter: exporter, ObsDomain: obsDomain}
	var recs []shared.FlowRecord
	var stats DecodeStats
	for len(body) >= 4 {
		setID := binary.BigEndian.Uint16(body[0:2])
		setLen := int(binary.BigEndian.Uint16(body[2:4]))
		if setLen < 4 || setLen > len(body) {
			stats.BadSets++
			break
		}
		setBody := body[4:setLen]
		switch setID {
		case ipfixTemplateSetID:
			defs, bad := parseDataTemplateSet(setBody)
			stats.BadSets += bad
			stats.LearnedTemplates += learnDefs(tc, exporter, obsDomain, defs)
		case ipfixOptionsSetID:
			defs, rest, bad := parseOptionsTemplateSet(setBody, false)
			stats.BadSets += bad
			stats.LearnedTemplates += learnDefs(tc, exporter, obsDomain, defs)
			// IPFIX options 数据走独立数据集（set id=模板 id）；容错处理
			// 同 set 内联记录的 v9 风格导出方
			for _, d := range defs {
				if d.def != nil && d.def.IsOptions && len(rest) > 0 {
					_, ds := decodeSetRecords(d.def, rest, tb, tc, key)
					stats.SkippedDataSets += ds.SkippedDataSets
				}
			}
		default:
			if setID < ipfixMinDataTemplateID {
				break // 保留 set id：静默忽略
			}
			def := tc.Lookup(exporter, obsDomain, setID)
			if def == nil {
				stats.SkippedDataSets++ // 模板先于数据缺失：跳过等重学
				break
			}
			rs, ds := decodeSetRecords(def, setBody, tb, tc, key)
			recs = append(recs, rs...)
			stats.SkippedDataSets += ds.SkippedDataSets
			stats.SkippedRecords += ds.SkippedRecords
			stats.BadSets += ds.BadSets
		}
		body = body[setLen:]
	}
	return recs, stats
}
