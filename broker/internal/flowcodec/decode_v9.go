package flowcodec

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"

	"github.com/SchearLoe/lucidnet/shared"
)

// NetFlow v9 解码（RFC 3954；代理路径按需解码，协议解码属主仍为 Collector，
// hld/01 §1）。模板按 (exporter, source_id, template_id) 经 TemplateCache 管理：
// 数据集先于模板到达时跳过计数，包内或后续包模板集学习后即可解码。

const (
	V9HeaderLen            = 20
	v9TemplateSetID        = 0
	v9OptionsTemplateSetID = 1
	v9MinDataTemplateID    = 256
)

// V9Header —— v9 报文头摘录（RFC 3954 §5.1）。
type V9Header struct {
	Version   uint16
	Count     uint16
	SysUptime uint32 // exporter 开机毫秒
	UnixSecs  uint32
	Sequence  uint32 // package_sequence（导出侧事件计数，审计参考）
	SourceID  uint32 // 模板作用域 observation domain
}

// DecodeV9 —— NetFlow v9 数据报 → FlowRecord 列表 + 头摘录 + 逐 set 异常计数。
// 地址 ::ffff: 映射（docs/00 §1）；时间经 header SYSUPTIME 基准换算（含 32bit
// 回绕修正，与 v5 同源 flowTimeMs）。模板缺失不视为致命错误：相应数据集跳过
// 并计入 DecodeStats，包内其余 set 正常解码（不 panic、不阻塞热路径）。
func DecodeV9(datagram []byte, exporter netip.Addr, tc *TemplateCache) ([]shared.FlowRecord, V9Header, DecodeStats, error) {
	if !exporter.IsValid() {
		return nil, V9Header{}, DecodeStats{}, errors.New("decode netflow v9: invalid exporter address")
	}
	if len(datagram) < V9HeaderLen {
		return nil, V9Header{}, DecodeStats{}, fmt.Errorf("decode netflow v9 from %s: %w", exporter, ErrHeaderTooShort)
	}
	var h V9Header
	h.Version = binary.BigEndian.Uint16(datagram[0:2])
	if h.Version != 9 {
		return nil, h, DecodeStats{}, fmt.Errorf("decode netflow v9 from %s: got version %d: %w", exporter, h.Version, ErrVersionMismatch)
	}
	h.Count = binary.BigEndian.Uint16(datagram[2:4])
	h.SysUptime = binary.BigEndian.Uint32(datagram[4:8])
	h.UnixSecs = binary.BigEndian.Uint32(datagram[8:12])
	h.Sequence = binary.BigEndian.Uint32(datagram[12:16])
	h.SourceID = binary.BigEndian.Uint32(datagram[16:20])

	exp := exporter.String()
	tb := timeBase{
		exportMs:  int64(h.UnixSecs) * 1000,
		bootMs:    int64(h.UnixSecs)*1000 - int64(h.SysUptime),
		uptime:    h.SysUptime,
		hasUptime: true,
	}
	recs, stats := decodeV9Body(datagram[V9HeaderLen:], exp, h.SourceID, &tb, tc)
	return recs, h, stats, nil
}

// decodeV9Body —— v9 Set 序列走查（模板/options 模板学习，数据集解码）。
// set 内 break 仅为跳出 switch 继续下一 set；长度非法才终止整包（边界不可信）。
func decodeV9Body(body []byte, exporter string, obsDomain uint32, tb *timeBase, tc *TemplateCache) ([]shared.FlowRecord, DecodeStats) {
	key := TemplateKey{Exporter: exporter, ObsDomain: obsDomain}
	var recs []shared.FlowRecord
	var stats DecodeStats
	for len(body) >= 4 {
		setID := binary.BigEndian.Uint16(body[0:2])
		setLen := int(binary.BigEndian.Uint16(body[2:4]))
		if setLen < 4 || setLen > len(body) {
			stats.BadSets++ // 长度非法/越界：后续 set 边界不可信，停止本包
			break
		}
		setBody := body[4:setLen]
		switch setID {
		case v9TemplateSetID:
			defs, bad := parseDataTemplateSet(setBody)
			stats.BadSets += bad
			stats.LearnedTemplates += learnDefs(tc, exporter, obsDomain, defs)
		case v9OptionsTemplateSetID:
			defs, rest, bad := parseOptionsTemplateSet(setBody, true)
			stats.BadSets += bad
			stats.LearnedTemplates += learnDefs(tc, exporter, obsDomain, defs)
			// v9 options 数据记录与模板同行内联（RFC 3954 §5.3）：按刚学的模板
			// 继续解码，吸收采样间隔等全局语义
			for _, d := range defs {
				if d.def != nil && d.def.IsOptions && len(rest) > 0 {
					_, ds := decodeSetRecords(d.def, rest, tb, tc, key)
					stats.SkippedDataSets += ds.SkippedDataSets
				}
			}
		default:
			if setID < v9MinDataTemplateID {
				break // 保留 set id：静默忽略（合法保留区间，非异常）
			}
			def := tc.Lookup(exporter, obsDomain, setID)
			if def == nil {
				stats.SkippedDataSets++ // 模板先于数据缺失：跳过等重学（任务一场景）
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

// learnDefs —— 模板/撤回写入缓存，返回学习条数。
func learnDefs(tc *TemplateCache, exporter string, obsDomain uint32, defs []parsedTemplate) int {
	n := 0
	for _, d := range defs {
		if d.withdrawn {
			tc.Withdraw(exporter, obsDomain, d.id)
			continue
		}
		n += tc.Learn(exporter, obsDomain, d.id, d.def)
	}
	return n
}
