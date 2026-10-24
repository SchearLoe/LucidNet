package flowcodec

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"

	"github.com/SchearLoe/lucidnet/shared"
)

// NetFlow v5 布局（与 collector/internal/decoder 同源；跨模块禁 import 对方 internal，
// docs/11 §2，故 Broker 代理路径自带最小解码——promote 到 shared 见最终报告）。
const (
	V5HeaderLen  = 24
	V5RecordLen  = 48
	V5MaxRecords = 30 // v5 单包记录上限（RFC 3954 §5.1）
)

// v5 解码错误哨兵。
var (
	ErrDatagramTooShort = errors.New("datagram shorter than netflow v5 header")
	ErrVersionMismatch  = errors.New("unexpected netflow version")
	ErrRecordTruncated  = errors.New("datagram truncated inside netflow v5 records")
)

// DatagramHeader —— 报文头摘录（时间基准，供重编码会话换算 SYSUPTIME）。
type DatagramHeader struct {
	Version   uint16
	Count     int
	SysUptime uint32 // exporter 开机毫秒
	UnixSecs  uint32
	UnixNsecs uint32
}

// PeekVersion 读数据报版本号（前 2B 大端；过短返回 0）。
func PeekVersion(datagram []byte) uint16 {
	if len(datagram) < 2 {
		return 0
	}
	return binary.BigEndian.Uint16(datagram[0:2])
}

// DecodeV5 —— NetFlow v5 数据报 → FlowRecord 列表 + 头摘录。
// 语义与 collector 的 V5Decoder 一致（v5 仅 IPv4，地址 ::ffff: 映射，docs/00 §1）。
func DecodeV5(datagram []byte, exporter netip.Addr) ([]shared.FlowRecord, DatagramHeader, error) {
	if !exporter.IsValid() {
		return nil, DatagramHeader{}, errors.New("decode netflow v5: invalid exporter address")
	}
	if len(datagram) < V5HeaderLen {
		return nil, DatagramHeader{}, fmt.Errorf("decode netflow v5 from %s: %w", exporter, ErrDatagramTooShort)
	}
	var h DatagramHeader
	h.Version = binary.BigEndian.Uint16(datagram[0:2])
	if h.Version != 5 {
		return nil, h, fmt.Errorf("decode netflow v5 from %s: got version %d: %w", exporter, h.Version, ErrVersionMismatch)
	}
	h.Count = int(binary.BigEndian.Uint16(datagram[2:4]))
	h.SysUptime = binary.BigEndian.Uint32(datagram[4:8])
	h.UnixSecs = binary.BigEndian.Uint32(datagram[8:12])
	h.UnixNsecs = binary.BigEndian.Uint32(datagram[12:16])
	sampling := binary.BigEndian.Uint16(datagram[22:24])
	sampleRate := uint32(1)
	if sampling>>14 != 0 {
		if interval := sampling & 0x3fff; interval > 0 {
			sampleRate = uint32(interval)
		}
	}
	bootMs := int64(h.UnixSecs)*1000 + int64(h.UnixNsecs)/1_000_000 - int64(h.SysUptime)

	need := V5HeaderLen + h.Count*V5RecordLen
	if h.Count < 0 || len(datagram) < need {
		return nil, h, fmt.Errorf("decode netflow v5 from %s: %d records need %d bytes, got %d: %w",
			exporter, h.Count, need, len(datagram), ErrRecordTruncated)
	}
	exp := exporter.String()
	recs := make([]shared.FlowRecord, 0, h.Count)
	for i := 0; i < h.Count; i++ {
		off := V5HeaderLen + i*V5RecordLen
		recs = append(recs, decodeV5Record(datagram[off:off+V5RecordLen], exp, bootMs, h.SysUptime, sampleRate))
	}
	return recs, h, nil
}

func decodeV5Record(b []byte, exporter string, bootMs int64, sysUptime, sampleRate uint32) shared.FlowRecord {
	var rec shared.FlowRecord
	rec.Exporter = exporter
	rec.SrcIP = v4Mapped(binary.BigEndian.Uint32(b[0:4]))
	rec.DstIP = v4Mapped(binary.BigEndian.Uint32(b[4:8]))
	rec.BGPNextHop = v4Mapped(binary.BigEndian.Uint32(b[8:12]))
	rec.InIf = uint32(binary.BigEndian.Uint16(b[12:14]))
	rec.OutIf = uint32(binary.BigEndian.Uint16(b[14:16]))
	rec.Packets = uint64(binary.BigEndian.Uint32(b[16:20]))
	rec.Bytes = uint64(binary.BigEndian.Uint32(b[20:24]))
	rec.TimeStartMs = flowTimeMs(bootMs, binary.BigEndian.Uint32(b[24:28]), sysUptime)
	rec.TimeEndMs = flowTimeMs(bootMs, binary.BigEndian.Uint32(b[28:32]), sysUptime)
	rec.SrcPort = uint32(binary.BigEndian.Uint16(b[32:34]))
	rec.DstPort = uint32(binary.BigEndian.Uint16(b[34:36]))
	rec.TCPFlags = uint32(b[37])
	rec.Proto = uint32(b[38])
	rec.TOS = uint32(b[39])
	rec.SrcAS = uint32(binary.BigEndian.Uint16(b[40:42]))
	rec.DstAS = uint32(binary.BigEndian.Uint16(b[42:44]))
	rec.SampleRate = sampleRate
	rec.IPVersion = 4
	return rec
}

// flowTimeMs —— boot 时刻 + uptime 偏移（含 32bit 计数器回绕修正，dd/02 §2）。
func flowTimeMs(bootMs int64, offset, sysUptime uint32) int64 {
	t := bootMs + int64(offset)
	if offset > sysUptime {
		t -= 1 << 32
	}
	return t
}

func v4Mapped(v4 uint32) [16]byte {
	var a [16]byte
	a[10], a[11] = 0xff, 0xff
	binary.BigEndian.PutUint32(a[12:16], v4)
	return a
}
