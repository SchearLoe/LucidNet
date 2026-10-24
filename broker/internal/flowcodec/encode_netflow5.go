package flowcodec

import (
	"encoding/binary"
	"net/netip"
	"time"

	"github.com/SchearLoe/lucidnet/shared"
)

// V5Encoder —— 代理模式 NetFlow v5 重编码（dd/01 §4.2）：
// v5 头 SYSUPTIME/UNIX_SECS/SEQUENCE 按目的地独立维护；≤30 记录/包；
// v5 头无采样字段，采样率无法写回报文（限制 dd/01 §4.2 已标注，线下登记表同步）。
type V5Encoder struct {
	expAddr [4]byte // 目的地地址不需要；此处为 exporter 侧无感知——保留占位避免误用

	bootMs   int64 // 会话起点（SYSUPTIME 基准，会话级独立）
	sequence uint32
	pending  [V5MaxRecords]shared.FlowRecord
	n        int
}

// NewV5Encoder 构造会话编码器（now 为会话起始时刻）。
func NewV5Encoder(now time.Time) *V5Encoder {
	return &V5Encoder{bootMs: now.UnixMilli()}
}

// Pending 返回缓冲中的记录数。
func (e *V5Encoder) Pending() int { return e.n }

// Append 缓冲一条记录；缓冲满（30 条）返回 true 提示调用方 Flush。
func (e *V5Encoder) Append(rec shared.FlowRecord) bool {
	e.pending[e.n] = rec
	e.n++
	return e.n == V5MaxRecords
}

// Flush 编码并返回当前缓冲的 v5 数据报（≤ 24+30×48 B）；
// 无缓冲记录时返回 nil。
func (e *V5Encoder) Flush(now time.Time) []byte {
	if e.n == 0 {
		return nil
	}
	buf := make([]byte, V5HeaderLen+e.n*V5RecordLen)
	uptime := uint32(now.UnixMilli() - e.bootMs) // 会话内回绕无碍（模 2^32 语义）
	secs := uint32(now.Unix())
	nsecs := uint32(now.Nanosecond())

	binary.BigEndian.PutUint16(buf[0:2], 5)
	binary.BigEndian.PutUint16(buf[2:4], uint16(e.n))
	binary.BigEndian.PutUint32(buf[4:8], uptime)
	binary.BigEndian.PutUint32(buf[8:12], secs)
	binary.BigEndian.PutUint32(buf[12:16], nsecs)
	binary.BigEndian.PutUint32(buf[16:20], e.sequence) // flow_sequence：目的地独立维护
	// buf[20] engine_type / buf[21] engine_id = 0
	// buf[22:24] sampling_interval = 0（重编码侧采样率经 effective_sample_rate 语义由下游登记）
	e.sequence += uint32(e.n)

	for i := 0; i < e.n; i++ {
		e.encodeRecord(buf[V5HeaderLen+i*V5RecordLen:], &e.pending[i], uptime)
	}
	e.n = 0
	return buf
}

// encodeRecord —— FlowRecord → 48B v5 记录体（字段映射与 DecodeV5 互逆；
// 超出 v5 表达域的字段（v6 地址/AS>16bit 等）截断：IPv6 记录不该进入 v5 会话，见 forwarder 路由）。
func (e *V5Encoder) encodeRecord(b []byte, rec *shared.FlowRecord, uptime uint32) {
	binary.BigEndian.PutUint32(b[0:4], v4Of(rec.SrcIP))
	binary.BigEndian.PutUint32(b[4:8], v4Of(rec.DstIP))
	binary.BigEndian.PutUint32(b[8:12], v4Of(rec.BGPNextHop))
	binary.BigEndian.PutUint16(b[12:14], uint16(rec.InIf))
	binary.BigEndian.PutUint16(b[14:16], uint16(rec.OutIf))
	binary.BigEndian.PutUint32(b[16:20], clampUint32(rec.Packets))
	binary.BigEndian.PutUint32(b[20:24], clampUint32(rec.Bytes))
	binary.BigEndian.PutUint32(b[24:28], offsetMs(rec.TimeStartMs, e.bootMs, uptime))
	binary.BigEndian.PutUint32(b[28:32], offsetMs(rec.TimeEndMs, e.bootMs, uptime))
	binary.BigEndian.PutUint16(b[32:34], uint16(rec.SrcPort))
	binary.BigEndian.PutUint16(b[34:36], uint16(rec.DstPort))
	// b[36] pad1
	b[37] = uint8(rec.TCPFlags)
	b[38] = uint8(rec.Proto)
	b[39] = uint8(rec.TOS)
	binary.BigEndian.PutUint16(b[40:42], uint16(rec.SrcAS))
	binary.BigEndian.PutUint16(b[42:44], uint16(rec.DstAS))
	// b[44] src_mask / b[45] dst_mask = 0
}

// V4MappedIPv4 —— 从 16B 地址取 IPv4（非 v4-mapped 返回 false）。
func V4MappedIPv4(a [16]byte) (netip.Addr, bool) {
	if a[10] == 0xff && a[11] == 0xff {
		return netip.AddrFrom4([4]byte(a[12:16])), true
	}
	return netip.Addr{}, false
}

func v4Of(a [16]byte) uint32 {
	if a[10] == 0xff && a[11] == 0xff {
		return binary.BigEndian.Uint32(a[12:16])
	}
	return 0
}

func clampUint32(v uint64) uint32 {
	if v > 0xffffffff {
		return 0xffffffff
	}
	return uint32(v)
}

// offsetMs —— 流时间 → 相对会话 boot 的 uptime 偏移（早于 boot 或回绕时钳为 0）。
func offsetMs(flowMs, bootMs int64, uptime uint32) uint32 {
	off := flowMs - bootMs
	if off < 0 {
		return 0
	}
	return clampUint32(uint64(off))
}
