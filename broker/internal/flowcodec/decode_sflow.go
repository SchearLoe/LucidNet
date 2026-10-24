package flowcodec

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/SchearLoe/lucidnet/shared"
)

// sFlow v5 解码（RFC 3176 / sFlow v5 spec §5；代理路径按需解码）。
// flow sample（含 expanded）抽取为 FlowRecord 语义字段：raw packet header
// 记录经 L2/L3/L4 逐层解析取 5 元组，IPv4/IPv6 data 记录直接取字段；
// counter sample 等非流样本跳过（非异常）。sFlow 无模板机制，无需缓存。

// sFlow 样本类型（data_format = enterprise<<12 | format；enterprise 0）。
const (
	sFlowFlowSample          = 1
	sFlowCounterSample       = 2
	sFlowExpandedFlowSample  = 3
	sFlowExpandedCounterSamp = 4
)

// sFlow 流记录格式（enterprise 0）。
const (
	sFlowRecordRawHeader = 1
	sFlowRecordIPv4Data  = 3
	sFlowRecordIPv6Data  = 4
)

// sFlowHeader —— sFlow v5 数据报头摘录。
type SFlowHeader struct {
	Version    uint32
	Agent      [16]byte
	AgentV6    bool
	SubAgentID uint32
	Sequence   uint32
	UptimeMs   uint32
	NumSamples uint32
}

// IsSFlowV5 —— sFlow v5 探测（4B 大端版本=5 且 agent 地址类型合法；
// NetFlow v5 版本号占 2B，与 4B 布局不冲突，可安全共存在版本探测入口）。
func IsSFlowV5(datagram []byte) bool {
	if len(datagram) < 12 {
		return false
	}
	if binary.BigEndian.Uint32(datagram[0:4]) != 5 {
		return false
	}
	switch binary.BigEndian.Uint32(datagram[4:8]) {
	case 1, 2:
		return true
	default:
		return false
	}
}

// DecodeSFlowV5 —— sFlow v5 数据报 → FlowRecord 列表 + 头摘录 + 异常计数。
// 采样率写 SampleRate（1/N），字节数取原始帧长 frame_length；sFlow 无流起止
// 时间，TimeStart/TimeEnd 取解码时刻（now，限制见最终报告）。
func DecodeSFlowV5(datagram []byte, exporter netip.Addr, now time.Time) ([]shared.FlowRecord, SFlowHeader, DecodeStats, error) {
	if !exporter.IsValid() {
		return nil, SFlowHeader{}, DecodeStats{}, errors.New("decode sflow v5: invalid exporter address")
	}
	c := binCursor{b: datagram}
	var h SFlowHeader
	var stats DecodeStats
	var recs []shared.FlowRecord

	v, ok := c.u32()
	if !ok || v != 5 {
		return nil, h, stats, fmt.Errorf("decode sflow v5 from %s: %w", exporter, ErrVersionMismatch)
	}
	h.Version = v
	addrType, _ := c.u32()
	switch addrType {
	case 1:
		if a, ok := c.take(4); ok {
			copy(h.Agent[12:16], a)
			h.Agent[10], h.Agent[11] = 0xff, 0xff
		}
	case 2:
		if a, ok := c.take(16); ok {
			copy(h.Agent[:], a)
			h.AgentV6 = true
		}
	default:
		return nil, h, stats, fmt.Errorf("decode sflow v5 from %s: bad agent address type %d: %w", exporter, addrType, ErrHeaderTooShort)
	}
	if h.SubAgentID, ok = c.u32(); !ok {
		return nil, h, stats, fmt.Errorf("decode sflow v5 from %s: truncated header: %w", exporter, ErrHeaderTooShort)
	}
	if h.Sequence, ok = c.u32(); !ok {
		return nil, h, stats, fmt.Errorf("decode sflow v5 from %s: truncated header: %w", exporter, ErrHeaderTooShort)
	}
	if h.UptimeMs, ok = c.u32(); !ok {
		return nil, h, stats, fmt.Errorf("decode sflow v5 from %s: truncated header: %w", exporter, ErrHeaderTooShort)
	}
	if h.NumSamples, ok = c.u32(); !ok {
		return nil, h, stats, fmt.Errorf("decode sflow v5 from %s: truncated header: %w", exporter, ErrHeaderTooShort)
	}

	nowMs := now.UnixMilli()
	for i := uint32(0); i < h.NumSamples; i++ {
		format, ok := c.u32()
		if !ok {
			stats.BadSets++
			break
		}
		length, ok := c.u32()
		if !ok || int(length) > c.remain() {
			stats.BadSets++ // 样本长度越界：边界不可信，停止本包
			break
		}
		sample := c.b[c.off : c.off+int(length)]
		c.off += int(length)
		switch format {
		case sFlowFlowSample, sFlowExpandedFlowSample:
			rs, ds := decodeSFlowSample(format, sample, exporter, nowMs)
			recs = append(recs, rs...)
			stats.SkippedRecords += ds
		case sFlowCounterSample, sFlowExpandedCounterSamp:
			// 计数样本非流数据：正常跳过，不计异常
		default:
			stats.SkippedDataSets++ // 未知/私有样本类型
		}
	}
	return recs, h, stats, nil
}

// decodeSFlowSample —— flow sample / expanded flow sample → FlowRecord 列表，
// 返回（记录列表，跳过的记录数）。
func decodeSFlowSample(format uint32, sample []byte, exporter netip.Addr, nowMs int64) ([]shared.FlowRecord, int) {
	c := binCursor{b: sample}
	var samplingRate, inIf, outIf uint32
	skip := 0
	if format == sFlowFlowSample {
		// sequence_number(4), source_id(4), sampling_rate(4)（sFlow spec §5.2）
		if _, ok := c.take(8); !ok {
			return nil, 1
		}
		rate, ok := c.u32()
		if !ok {
			return nil, 1
		}
		samplingRate = rate
		if _, ok := c.take(8); !ok { // sample_pool/drops
			return nil, 1
		}
		if inIf, ok = c.u32(); !ok {
			return nil, 1
		}
		if outIf, ok = c.u32(); !ok {
			return nil, 1
		}
	} else {
		// sequence_number(4), source_id_type(4), source_id_index(4), sampling_rate(4)
		if _, ok := c.take(12); !ok {
			return nil, 1
		}
		rate, ok := c.u32()
		if !ok {
			return nil, 1
		}
		samplingRate = rate
		if _, ok := c.take(8); !ok { // sample_pool/drops
			return nil, 1
		}
		if _, ok := c.take(4); !ok { // input_format
			return nil, 1
		}
		if inIf, ok = c.u32(); !ok { // input_value
			return nil, 1
		}
		if _, ok := c.take(4); !ok { // output_format
			return nil, 1
		}
		if outIf, ok = c.u32(); !ok { // output_value
			return nil, 1
		}
	}
	numRecords, ok := c.u32()
	if !ok {
		return nil, 1
	}
	if samplingRate == 0 {
		samplingRate = 1
	}
	const ifUnknown = 0xFFFFFFFF
	if inIf == ifUnknown {
		inIf = 0
	}
	if outIf == ifUnknown {
		outIf = 0
	}

	recs := make([]shared.FlowRecord, 0, numRecords)
	for i := uint32(0); i < numRecords; i++ {
		recFormat, ok := c.u32()
		if !ok {
			break
		}
		length, ok := c.u32()
		if !ok || int(length) > c.remain() {
			skip += int(numRecords - i)
			return recs, skip
		}
		data := c.b[c.off : c.off+int(length)]
		c.off += int(length)
		rec, ok := decodeSFlowRecord(recFormat, data, exporter, nowMs, samplingRate, inIf, outIf)
		if !ok {
			skip++ // 非 IP 样本（ARP 等）或截断记录：跳过计数
			continue
		}
		recs = append(recs, rec)
	}
	if n := int(numRecords) - len(recs) - skip; n > 0 {
		skip += n // 样本头声称的记录数多于实际可解析
	}
	return recs, skip
}

// decodeSFlowRecord —— 单条流记录 → FlowRecord（ok=false=非 IP/无法解析，调用方跳过）。
func decodeSFlowRecord(format uint32, data []byte, exporter netip.Addr, nowMs int64, samplingRate, inIf, outIf uint32) (shared.FlowRecord, bool) {
	rec := shared.FlowRecord{
		Exporter:    exporter.String(),
		TimeStartMs: nowMs,
		TimeEndMs:   nowMs,
		SampleRate:  samplingRate,
		Packets:     1,
		InIf:        inIf,
		OutIf:       outIf,
	}
	c := binCursor{b: data}
	switch format {
	case sFlowRecordRawHeader:
		proto, ok := c.u32()
		if !ok {
			return rec, false
		}
		frameLen, _ := c.u32()
		stripped, _ := c.u32()
		hdrLen, _ := c.u32()
		hdr, ok := c.take(int(hdrLen))
		if !ok || hdrLen == 0 {
			return rec, false
		}
		rec.Bytes = uint64(frameLen)
		if rec.Bytes == 0 {
			rec.Bytes = uint64(stripped) + uint64(hdrLen)
		}
		switch proto {
		case 11: // IPv4 裸报文头（无以太网帧）
			return finishIPv4(rec, hdr)
		case 12: // IPv6 裸报文头
			return finishIPv6(rec, hdr)
		default: // 1=Ethernet：逐层剥出 L3
			l3, v6, ok := stripEthernet(hdr)
			if !ok {
				return rec, false
			}
			if v6 {
				return finishIPv6(rec, l3)
			}
			return finishIPv4(rec, l3)
		}
	case sFlowRecordIPv4Data:
		// source_addr/dest_addr/next_hop/src_mask/dst_mask/protocol/src_port/dst_port/tcp_flags/tos
		if len(data) < 8 {
			return rec, false
		}
		rec.SrcIP = v4Mapped(binary.BigEndian.Uint32(data[0:4]))
		rec.DstIP = v4Mapped(binary.BigEndian.Uint32(data[4:8]))
		rec.IPVersion = 4
		if len(data) >= 24 {
			rec.Proto = binary.BigEndian.Uint32(data[20:24])
		}
		if len(data) >= 32 {
			rec.SrcPort = binary.BigEndian.Uint32(data[24:28])
			rec.DstPort = binary.BigEndian.Uint32(data[28:32])
		}
		if len(data) >= 36 {
			rec.TCPFlags = binary.BigEndian.Uint32(data[32:36]) & 0xff
		}
		if len(data) >= 40 {
			rec.TOS = binary.BigEndian.Uint32(data[36:40]) & 0xff
		}
		return rec, true
	case sFlowRecordIPv6Data:
		// source_addr(16)/dest_addr(16)/next_hop(16)/src_mask(4)/dst_mask(4)/
		// protocol(4)/src_port(4)/dst_port(4)/tcp_flags(4)/priority(4)
		if len(data) < 32 {
			return rec, false
		}
		copy(rec.SrcIP[:], data[0:16])
		copy(rec.DstIP[:], data[16:32])
		rec.IPVersion = 6
		if len(data) >= 60 {
			rec.Proto = binary.BigEndian.Uint32(data[56:60])
		}
		if len(data) >= 68 {
			rec.SrcPort = binary.BigEndian.Uint32(data[60:64])
			rec.DstPort = binary.BigEndian.Uint32(data[64:68])
		}
		if len(data) >= 72 {
			rec.TCPFlags = binary.BigEndian.Uint32(data[68:72]) & 0xff
		}
		return rec, true
	default:
		return rec, false // extended switch/router 等扩展记录：无 5 元组，跳过
	}
}

// stripEthernet —— 以太网帧 → L3 载荷（VLAN 802.1Q/QinQ 有界剥层）。
func stripEthernet(frame []byte) ([]byte, bool, bool) {
	ethertypeBase := 12
	v6 := false
	for tag := 0; tag < 3; tag++ {
		if len(frame) < ethertypeBase+2 {
			return nil, false, false
		}
		switch binary.BigEndian.Uint16(frame[ethertypeBase : ethertypeBase+2]) {
		case 0x8100, 0x88A8, 0x9100: // VLAN tag：跳过 TCI 4B
			ethertypeBase += 4
		case 0x0800:
			return frame[ethertypeBase+2:], false, true
		case 0x86DD:
			return frame[ethertypeBase+2:], true, true
		default:
			return nil, v6, false // ARP/MPLS 等非 IP：跳过
		}
	}
	return nil, v6, false
}

// finishIPv4 —— IPv4 报文头 → 记录 L3/L4 字段（截断容忍：能解多少解多少）。
func finishIPv4(rec shared.FlowRecord, ip []byte) (shared.FlowRecord, bool) {
	if len(ip) < 20 || ip[0]>>4 != 4 {
		return rec, false
	}
	ihl := int(ip[0]&0xf) * 4
	if ihl < 20 || ihl > len(ip) {
		return rec, false
	}
	rec.SrcIP = v4Mapped(binary.BigEndian.Uint32(ip[12:16]))
	rec.DstIP = v4Mapped(binary.BigEndian.Uint32(ip[16:20]))
	rec.Proto = uint32(ip[9])
	rec.TOS = uint32(ip[1])
	rec.IPVersion = 4
	if fragOffset := binary.BigEndian.Uint16(ip[6:8]) & 0x1fff; fragOffset != 0 {
		return rec, true // 非首分片无 L4 头：端口留空
	}
	fillL4(&rec, ip[ihl:])
	return rec, true
}

// finishIPv6 —— IPv6 报文头 → 记录字段（有界扩展头链走查）。
func finishIPv6(rec shared.FlowRecord, ip []byte) (shared.FlowRecord, bool) {
	if len(ip) < 40 || ip[0]>>4 != 6 {
		return rec, false
	}
	copy(rec.SrcIP[:], ip[8:24])
	copy(rec.DstIP[:], ip[24:40])
	rec.IPVersion = 6
	nh := ip[6]
	off := 40
	for hop := 0; hop < 8; hop++ { // 扩展头链有界
		switch nh {
		case 0, 43, 60: // hop-by-hop / routing / destination options：8B+ext_len
			if off+2 > len(ip) {
				return rec, true
			}
			nh = ip[off]
			off += 8 + int(ip[off+1])
		case 51: // AH：4B 单位
			if off+2 > len(ip) {
				return rec, true
			}
			nh = ip[off]
			off += 4 * (int(ip[off+1]) + 2)
		case 6, 17, 132: // TCP/UDP/SCTP
			rec.Proto = uint32(nh)
			fillL4(&rec, ip[off:])
			return rec, true
		default:
			return rec, true // ICMP 等：端口留空
		}
		if off > len(ip) {
			return rec, true
		}
	}
	return rec, true
}

// fillL4 —— TCP/UDP/SCTP 端口与 TCP flags（截断容忍）。
func fillL4(rec *shared.FlowRecord, l4 []byte) {
	if len(l4) < 4 {
		return
	}
	rec.SrcPort = uint32(binary.BigEndian.Uint16(l4[0:2]))
	rec.DstPort = uint32(binary.BigEndian.Uint16(l4[2:4]))
	switch rec.Proto {
	case 6: // TCP flags 在第 13 字节（data offset<<4 | reserved 之后）
		if len(l4) >= 14 {
			rec.TCPFlags = uint32(l4[13])
		}
	}
}
