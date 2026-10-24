package flowcodec

import (
	"encoding/binary"
	"errors"

	"github.com/SchearLoe/lucidnet/shared"
)

// 解码侧信息元素编号（IANA IPFIX registry 2026-09 核对；NetFlow v9 字段类型
// 0-127 与 IANA 同号，RFC 3954 §5.7 + registry 注记 "Values 0-127: NFv9-compatible"，
// 故 v9/IPFIX 共用一张映射表）。括号内为 v9 旧名对照。
const (
	ieOctetDeltaCount            = 1  // IN_BYTES
	iePacketDeltaCount           = 2  // IN_PKTS
	ieProtocolIdentifier         = 4  // PROTOCOL
	ieIPClassOfService           = 5  // SRC_TOS
	ieTCPControlBits             = 6  // TCP_FLAGS
	ieSourceTransportPort        = 7  // L4_SRC_PORT
	ieSourceIPv4Address          = 8  // IPV4_SRC_ADDR
	ieIngressInterface           = 10 // INPUT_SNMP
	ieDestinationTransportPort   = 11 // L4_DST_PORT
	ieDestinationIPv4Address     = 12 // IPV4_DST_ADDR
	ieEgressInterface            = 14 // OUTPUT_SNMP
	ieIPNextHopIPv4              = 15 // IPV4_NEXT_HOP
	ieBGPSourceASNumber          = 16 // SRC_AS
	ieBGPDestinationASNumber     = 17 // DST_AS
	ieBGPNextHopIPv4             = 18 // BGP_IPV4_NEXT_HOP
	ieFlowEndSysUpTime           = 21 // LAST_SWITCHED
	ieFlowStartSysUpTime         = 22 // FIRST_SWITCHED
	ieSourceIPv6Address          = 27
	ieDestinationIPv6Address     = 28
	ieSamplingInterval           = 34 // SAMPLING_INTERVAL（deprecated，v9 常用）
	ieIPVersion                  = 60
	ieIPNextHopIPv6              = 62
	ieBGPNextHopIPv6             = 63
	ieFlowStartSeconds           = 150
	ieFlowEndSeconds             = 151
	ieFlowStartMilliseconds      = 152
	ieFlowEndMilliseconds        = 153
	ieFlowStartMicroseconds      = 154
	ieFlowEndMicroseconds        = 155
	ieFlowStartNanoseconds       = 156
	ieFlowEndNanoseconds         = 157
	ieFlowStartDeltaMicroseconds = 158
	ieFlowEndDeltaMicroseconds   = 159
	ieSystemInitTimeMilliseconds = 160 // systemInitTimeMilliseconds（IPFIX 相对时间锚点）
	ieSamplingPacketInterval     = 305 // PSAMP samplingPacketInterval（dd/01 §4.2）
)

// ieVarlen —— 模板字段长度 65535 = 变长（RFC 7011 §7.1.2）。
const ieVarlen uint16 = 65535

// DecodeStats —— 逐 set/样本解码过程中的非致命异常计数（跳过并继续，
// 绝不 panic、不阻断包内其余数据；引擎折算进 proxy_decode_errors_total）。
type DecodeStats struct {
	SkippedDataSets  int // 模板缺失等原因整体跳过的数据集/样本数
	SkippedRecords   int // 数据集/样本内跳过的记录数（截断/非 IP 等）
	BadSets          int // set/样本头或模板记录非法数
	LearnedTemplates int // 本包新学/刷新模板数
}

// Sum —— 非致命异常合计（引擎打点用）。
func (s DecodeStats) Sum() int {
	return s.SkippedDataSets + s.SkippedRecords + s.BadSets
}

// 解码失败哨兵（小写开头、%w 包裹，docs/11 §3）。
var (
	ErrHeaderTooShort  = errors.New("datagram shorter than flow header")
	ErrSetTruncated    = errors.New("set body truncated")
	ErrBadSetLength    = errors.New("set length invalid")
	ErrTemplateInvalid = errors.New("template record invalid")
)

// timeBase —— 记录时间换算基准（v9/IPFIX 差异见各自解码器）。
type timeBase struct {
	exportMs  int64 // 报文头绝对时间（epoch ms）
	bootMs    int64 // 系统启动时刻（epoch ms）；<0 未知
	uptime    uint32
	hasUptime bool
}

// sysUpToMs —— sys-up 相对毫秒 → epoch ms（boot 已知才有意义）。
func (tb *timeBase) sysUpToMs(offset uint64) (int64, bool) {
	if tb.bootMs < 0 {
		return 0, false
	}
	if tb.hasUptime {
		return flowTimeMs(tb.bootMs, uint32(offset), tb.uptime), true
	}
	return tb.bootMs + int64(offset), true // IPFIX 锚点：无 uptime 无法修正 32bit 回绕（限制见报告）
}

// binCursor —— 大端只读游标（全部带边界检查，解码路径零 panic）。
type binCursor struct {
	b   []byte
	off int
}

func (c *binCursor) remain() int { return len(c.b) - c.off }

func (c *binCursor) u8() (uint8, bool) {
	if c.off+1 > len(c.b) {
		return 0, false
	}
	v := c.b[c.off]
	c.off++
	return v, true
}

func (c *binCursor) u16() (uint16, bool) {
	if c.off+2 > len(c.b) {
		return 0, false
	}
	v := binary.BigEndian.Uint16(c.b[c.off : c.off+2])
	c.off += 2
	return v, true
}

func (c *binCursor) u32() (uint32, bool) {
	if c.off+4 > len(c.b) {
		return 0, false
	}
	v := binary.BigEndian.Uint32(c.b[c.off : c.off+4])
	c.off += 4
	return v, true
}

// take 取 n 字节切片（引用原缓冲，不复制；调用方不滞留）。
func (c *binCursor) take(n int) ([]byte, bool) {
	if n < 0 || c.off+n > len(c.b) {
		return nil, false
	}
	v := c.b[c.off : c.off+n]
	c.off += n
	return v, true
}

// takeVarlen 取变长字段（RFC 7011 §7.1.2：首字节 <255 即长度；255 后跟 2B 大端长度）。
func (c *binCursor) takeVarlen() ([]byte, bool) {
	n, ok := c.u8()
	if !ok {
		return nil, false
	}
	if n == 255 {
		hi, ok := c.u8()
		if !ok {
			return nil, false
		}
		lo, ok := c.u8()
		if !ok {
			return nil, false
		}
		return c.take(int(hi)<<8 | int(lo))
	}
	return c.take(int(n))
}

// beUint 大端取 ≤8B 无符号（不足位左填充 0，reduced-size encoding 兼容，RFC 7011 §6.2）。
func beUint(b []byte) uint64 {
	var v uint64
	for _, x := range b {
		v = v<<8 | uint64(x)
	}
	return v
}

// decodeDataRecord —— 按模板逐字段解码一条数据记录（从游标消费恰好一条）。
// 时间候选优先级：绝对时间 IE(150-159) > sys-up 相对 IE(21/22)；二者皆缺省时
// 回退报文头时间。返回 false = 记录截断（调用方跳过该 set）。
func decodeDataRecord(fields []TemplateField, c *binCursor, tb *timeBase, tc *TemplateCache, key TemplateKey, rec *shared.FlowRecord) bool {
	var startMs, endMs int64
	var startSet, endSet, startAbs, endAbs bool

	for _, f := range fields {
		var val []byte
		var ok bool
		if f.Length == ieVarlen {
			if val, ok = c.takeVarlen(); !ok {
				return false
			}
		} else {
			if val, ok = c.take(int(f.Length)); !ok {
				return false
			}
		}
		if f.Enterprise != 0 || len(val) == 0 {
			continue // vendor 私有 IE 仅消费不映射（docs/00 无私有 IE 表达域）
		}

		switch f.IE {
		case ieOctetDeltaCount:
			if rec.Bytes == 0 {
				rec.Bytes = beUint(val)
			}
		case iePacketDeltaCount:
			if rec.Packets == 0 {
				rec.Packets = beUint(val)
			}
		case ieProtocolIdentifier:
			rec.Proto = uint32(val[0])
		case ieIPClassOfService:
			rec.TOS = uint32(val[0])
		case ieTCPControlBits:
			rec.TCPFlags = uint32(beUint(val) & 0xff)
		case ieSourceTransportPort:
			if len(val) >= 2 {
				rec.SrcPort = uint32(binary.BigEndian.Uint16(val))
			}
		case ieDestinationTransportPort:
			if len(val) >= 2 {
				rec.DstPort = uint32(binary.BigEndian.Uint16(val))
			}
		case ieSourceIPv4Address:
			if len(val) == 16 { // 少数 v9 老实现以 IE 8 + 16B 承载 v6 地址
				copy(rec.SrcIP[:], val)
				rec.IPVersion = 6
			} else if len(val) >= 4 {
				rec.SrcIP = v4Mapped(binary.BigEndian.Uint32(val[:4]))
				rec.IPVersion = 4
			}
		case ieDestinationIPv4Address:
			if len(val) == 16 {
				copy(rec.DstIP[:], val)
				rec.IPVersion = 6
			} else if len(val) >= 4 {
				rec.DstIP = v4Mapped(binary.BigEndian.Uint32(val[:4]))
				rec.IPVersion = 4
			}
		case ieSourceIPv6Address:
			if len(val) >= 16 {
				copy(rec.SrcIP[:], val[:16])
				rec.IPVersion = 6
			}
		case ieDestinationIPv6Address:
			if len(val) >= 16 {
				copy(rec.DstIP[:], val[:16])
				rec.IPVersion = 6
			}
		case ieIngressInterface:
			if rec.InIf == 0 {
				rec.InIf = uint32(beUint(val))
			}
		case ieEgressInterface:
			if rec.OutIf == 0 {
				rec.OutIf = uint32(beUint(val))
			}
		case ieIPNextHopIPv4, ieBGPNextHopIPv4:
			if len(val) >= 4 && rec.BGPNextHop == ([16]byte{}) {
				rec.BGPNextHop = v4Mapped(binary.BigEndian.Uint32(val[:4]))
			}
		case ieIPNextHopIPv6, ieBGPNextHopIPv6:
			if len(val) >= 16 && rec.BGPNextHop == ([16]byte{}) {
				copy(rec.BGPNextHop[:], val[:16])
			}
		case ieBGPSourceASNumber:
			rec.SrcAS = uint32(beUint(val))
		case ieBGPDestinationASNumber:
			rec.DstAS = uint32(beUint(val))
		case ieFlowEndSysUpTime:
			if !endAbs {
				if ms, ok := tb.sysUpToMs(beUint(val)); ok {
					endMs, endSet = ms, true
				}
			}
		case ieFlowStartSysUpTime:
			if !startAbs {
				if ms, ok := tb.sysUpToMs(beUint(val)); ok {
					startMs, startSet = ms, true
				}
			}
		case ieFlowStartSeconds:
			startMs, startSet, startAbs = int64(beUint(val))*1000, true, true
		case ieFlowEndSeconds:
			endMs, endSet, endAbs = int64(beUint(val))*1000, true, true
		case ieFlowStartMilliseconds:
			startMs, startSet, startAbs = int64(beUint(val)), true, true
		case ieFlowEndMilliseconds:
			endMs, endSet, endAbs = int64(beUint(val)), true, true
		case ieFlowStartMicroseconds:
			startMs, startSet, startAbs = int64(beUint(val))/1000, true, true
		case ieFlowEndMicroseconds:
			endMs, endSet, endAbs = int64(beUint(val))/1000, true, true
		case ieFlowStartNanoseconds:
			startMs, startSet, startAbs = int64(beUint(val))/1_000_000, true, true
		case ieFlowEndNanoseconds:
			endMs, endSet, endAbs = int64(beUint(val))/1_000_000, true, true
		case ieFlowStartDeltaMicroseconds: // 相对报文头时间前移
			startMs, startSet, startAbs = tb.exportMs-int64(beUint(val))/1000, true, true
		case ieFlowEndDeltaMicroseconds:
			endMs, endSet, endAbs = tb.exportMs-int64(beUint(val))/1000, true, true
		case ieSystemInitTimeMilliseconds: // options 记录：写回锚点（RFC 7011 §8.4）
			tc.SetAnchor(key.Exporter, key.ObsDomain, int64(beUint(val)))
		case ieSamplingInterval, ieSamplingPacketInterval:
			if v := uint32(beUint(val)); v > 0 && rec.SampleRate == 0 {
				rec.SampleRate = v
			}
		case ieIPVersion:
			if v := uint32(val[0]); v == 4 || v == 6 {
				rec.IPVersion = v
			}
		default:
			// 未映射 IE：数据已按模板长度消费，语义丢弃（边界见最终报告）
		}
	}

	rec.TimeStartMs, rec.TimeEndMs = finalizeFlowTimes(tb, startMs, startSet, endMs, endSet)
	return true
}

// finalizeFlowTimes —— 时间回填：候选就绪用之，皆缺省回退报文头时间；end<start 钳位。
func finalizeFlowTimes(tb *timeBase, startMs int64, startSet bool, endMs int64, endSet bool) (int64, int64) {
	if !startSet {
		startMs = tb.exportMs
	}
	if !endSet {
		endMs = startMs
	}
	if endMs < startMs {
		endMs = startMs
	}
	return startMs, endMs
}
