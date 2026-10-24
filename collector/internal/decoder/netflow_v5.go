package decoder

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"

	"github.com/SchearLoe/lucidnet/shared"
)

// NetFlow v5 报文布局（RFC 3954 §5.1/Cisco NetFlow Export Datagram Format）。
const (
	v5HeaderLen = 24
	v5RecordLen = 48
)

// v5 解码错误哨兵（调用方 errors.Is 判定）。
var (
	ErrDatagramTooShort = errors.New("datagram shorter than netflow v5 header")
	ErrVersionMismatch  = errors.New("unexpected netflow version")
	ErrRecordTruncated  = errors.New("datagram truncated inside netflow v5 records")
)

// V5Decoder —— NetFlow v5 完整实现（头 + 记录体 → shared.FlowRecord）。
//
// v5 无模板机制（DecodeResult.TemplateEvents 恒空）；v5 记录仅 IPv4，
// IPVersion 恒为 4（v4 地址按 RFC 4291 §2.5.5.2 ::ffff:/96 映射进 16B 字段；
// 双栈 R3 由 v9/IPFIX 解码器覆盖，dd/02 §1 定制点 #4）。
type V5Decoder struct {
	opts options
}

// NewV5 —— 构造 v5 解码器。
func NewV5(opts ...Option) *V5Decoder {
	o := defaultOptions()
	for _, f := range opts {
		f(&o)
	}
	return &V5Decoder{opts: o}
}

// Decode —— 解析一个 NetFlow v5 数据报。
func (d *V5Decoder) Decode(datagram []byte, exporter netip.Addr) (DecodeResult, error) {
	if !exporter.IsValid() {
		return DecodeResult{}, errors.New("decode netflow v5: invalid exporter address")
	}
	if len(datagram) < v5HeaderLen {
		return DecodeResult{}, fmt.Errorf("decode netflow v5 from %s: %w", exporter, ErrDatagramTooShort)
	}
	version := binary.BigEndian.Uint16(datagram[0:2])
	if version != VersionNetFlowV5 {
		return DecodeResult{}, fmt.Errorf("decode netflow v5 from %s: got version %d: %w", exporter, version, ErrVersionMismatch)
	}
	count := int(binary.BigEndian.Uint16(datagram[2:4]))
	sysUptime := binary.BigEndian.Uint32(datagram[4:8])
	unixSecs := binary.BigEndian.Uint32(datagram[8:12])
	unixNsecs := binary.BigEndian.Uint32(datagram[12:16])
	// sampling_interval：bit15-14 = 采样模式，bit13-0 = 间隔（RFC 3954 §5.1）。
	// 多数 v5 导出器置 0（dd/02 §1 定制点 #3：v5 依赖 exporter 采样登记表）；
	// 头部携带非零采样信息时优先采用，否则用登记表缺省值。
	sampling := binary.BigEndian.Uint16(datagram[22:24])
	sampleRate := d.opts.defaultSampleRate
	if sampling>>14 != 0 {
		if interval := sampling & 0x3fff; interval > 0 {
			sampleRate = uint32(interval)
		}
	}

	// 时间换算（dd/02 §2：time_start_ms = unix_secs + sysuptime 差）：
	// boot 时刻(epoch ms) = 报文墙钟 - 头部 sysuptime；流起止 = boot + 记录 first/last 偏移。
	bootMs := int64(unixSecs)*1000 + int64(unixNsecs)/1_000_000 - int64(sysUptime)

	need := v5HeaderLen + count*v5RecordLen
	if len(datagram) < need {
		return DecodeResult{}, fmt.Errorf("decode netflow v5 from %s: %d records need %d bytes, got %d: %w", exporter, count, need, len(datagram), ErrRecordTruncated)
	}
	res := DecodeResult{Records: make([]shared.FlowRecord, 0, count)}
	exp := exporter.String()
	for i := 0; i < count; i++ {
		off := v5HeaderLen + i*v5RecordLen
		res.Records = append(res.Records, d.decodeRecord(datagram[off:off+v5RecordLen], exp, bootMs, sysUptime, sampleRate))
	}
	// 头部 count 之外的尾随字节（填充/粘包残留）忽略：UDP 单报文语义下无跨报文流集。
	return res, nil
}

// decodeRecord —— 48B 记录体 → FlowRecord（dd/02 §2 字段映射表 v5 列）。
func (d *V5Decoder) decodeRecord(b []byte, exporter string, bootMs int64, sysUptime, sampleRate uint32) shared.FlowRecord {
	var rec shared.FlowRecord
	rec.Exporter = exporter
	rec.DeviceID = 0 // TODO(snmp)：资产库设备 ID 对齐（dd/02 §5.2 对账校验 / manual_if_map）
	rec.SrcIP = v4Mapped16(binary.BigEndian.Uint32(b[0:4]))
	rec.DstIP = v4Mapped16(binary.BigEndian.Uint32(b[4:8]))
	rec.BGPNextHop = v4Mapped16(binary.BigEndian.Uint32(b[8:12])) // v5 nexthop = 下一跳路由器
	rec.InIf = uint32(binary.BigEndian.Uint16(b[12:14]))
	rec.OutIf = uint32(binary.BigEndian.Uint16(b[14:16]))
	rec.Packets = uint64(binary.BigEndian.Uint32(b[16:20]))
	rec.Bytes = uint64(binary.BigEndian.Uint32(b[20:24]))
	rec.TimeStartMs = flowTimeMs(bootMs, binary.BigEndian.Uint32(b[24:28]), sysUptime)
	rec.TimeEndMs = flowTimeMs(bootMs, binary.BigEndian.Uint32(b[28:32]), sysUptime)
	rec.SrcPort = uint32(binary.BigEndian.Uint16(b[32:34]))
	rec.DstPort = uint32(binary.BigEndian.Uint16(b[34:36]))
	// b[36] pad1
	rec.TCPFlags = uint32(b[37])
	rec.Proto = uint32(b[38])
	rec.TOS = uint32(b[39])
	rec.SrcAS = uint32(binary.BigEndian.Uint16(b[40:42]))
	rec.DstAS = uint32(binary.BigEndian.Uint16(b[42:44]))
	// b[44] src_mask / b[45] dst_mask：FlowRecord 无对应字段（完整映射表 TODO docs/mapping.md，dd/02 §2）
	rec.SampleRate = sampleRate
	rec.IPVersion = 4 // v5 仅 IPv4，恒定（双栈见 v9/IPFIX，dd/02 §1 定制点 #4）
	return rec
}

// flowTimeMs —— boot 时刻 + sysuptime 偏移。
// 若 offset > 头部 sysUptime，说明 32bit uptime 计数器（≈49.7 天回绕）在流开始后已回绕，
// 回退 2^32 ms 修正（流开始早于头部计数回绕点）。
func flowTimeMs(bootMs int64, offset, sysUptime uint32) int64 {
	t := bootMs + int64(offset)
	if offset > sysUptime {
		t -= 1 << 32
	}
	return t
}

// v4Mapped16 —— RFC 4291 §2.5.5.2 ::ffff:a.b.c.d 映射（shared.FlowRecord 地址统一 16B）。
func v4Mapped16(v4 uint32) [16]byte {
	var a [16]byte
	a[10], a[11] = 0xff, 0xff
	binary.BigEndian.PutUint32(a[12:16], v4)
	return a
}
