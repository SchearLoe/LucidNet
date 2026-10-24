package detector

import (
	"container/list"

	"github.com/cespare/xxhash/v2"

	"github.com/SchearLoe/lucidnet/analytics/internal/hll"
	"github.com/SchearLoe/lucidnet/shared"
)

const (
	ring60Len   = 60  // 1s 粒度环形，覆盖 60s（dd/03 §3.1）
	ring5mLen   = 300 // 5m 轻量桶
	secondGrace = 2   // 秒 s 在 s+2s 关闭评估（1s 数据 + 1s 迟到宽限）
)

// SecBucket —— 1s 桶（dd/03 §3.1 字段清单）。
type SecBucket struct {
	Sec      int64 // 该桶所属秒（epoch）；非法值=空槽
	Bps      uint64
	Pps      uint64
	Flows    uint64
	NewFlows uint64
	Syn      uint64 // 纯 SYN 包（SYN 且非 ACK）
	SynAck   uint64 // SYN+ACK
	Ack      uint64 // ACK 且非 SYN
	Rst      uint64
	UDPPkts  uint64
	TCPPkts  uint64
	ICMPPkts uint64
	FragPkts uint64 // TODO(契约缺口)：FlowRecord 无分片标志（MF/offset），恒 0，见 README
	DstEnt   uint32 // 本秒目的 IP 基数（HLL 估计，熵增量件近似）
	SrcCard  uint32 // 本秒源 IP 基数（HLL 估计）

	dstH, srcH *hll.Sketch // p=8 惰性分配
}

// SecBucketLite —— 5m 轻量桶（仅 bps/pps/newflows，供短基线）。
type SecBucketLite struct {
	Sec      int64
	Bps      uint64
	Pps      uint64
	NewFlows uint64
}

// zoneState —— 每 zone 一份（惰性创建，dd/03 §3.1）。
type zoneState struct {
	zoneID     int32
	lastClosed int64 // 已评估关闭的最后秒
	lastAddMs  int64 // 最近记录到达（prune 用）

	srcAggCap int    // 每源统计上限（构造时定格，dd/03 §3.1 默认 50,000）
	overflowN uint64 // 降级进 CMS 桩的追加次数

	ring60 [ring60Len]SecBucket
	ring5m [ring5mLen]SecBucketLite

	// newflows 判定：(src,dst,proto) 分钟级 LRU（dd/03 §3.3 首包近似）
	flowLRU    *flowSeenLRU
	flowMinute int64

	srcAgg      map[uint64]*SrcStats // key=xxhash64(srcIP)
	srcOverflow bool
	cms         CountMinSketch // 超限降级桩（dd/03 §3.1 CM16×65536）

	sweep *sweepTracker // 攻击态惰性分配（dd/03 §3.2 容量预算：常态 0）

	anomaly anomalyState

	synWin [3]bool // 最近 3 个 1s 窗 SYN 规则命中（2/3 确认）
	synN   int     // 环内有效评估数
	synPos int
}

func newZoneState(zoneID int32, firstSec int64, cfg Config) *zoneState {
	return &zoneState{
		zoneID:     zoneID,
		lastClosed: firstSec - 1,
		srcAggCap:  cfg.SrcAggCap,
		srcAgg:     make(map[uint64]*SrcStats),
		cms:        NewCountMinSketchStub(),
	}
}

// add —— 追加式累加（dd/03 §3.3）。
func (z *zoneState) add(rec *shared.FlowRecord, cfg Config) {
	sec := rec.TimeStartMs / 1000
	b := z.bucket(sec)
	b.Flows++
	b.Pps += rec.Packets
	b.Bps += rec.Bytes * 8

	// 每秒源/目的基数（dst_ent / src_card）
	if b.dstH == nil {
		b.dstH = hll.New(8)
		b.srcH = hll.New(8)
	}
	b.dstH.Insert(xxhash.Sum64(rec.DstIP[:]))
	b.srcH.Insert(xxhash.Sum64(rec.SrcIP[:]))

	// newflows：分钟级 (src,dst,proto) LRU 首包近似
	minute := sec / 60
	if minute != z.flowMinute {
		z.flowMinute = minute
		z.flowLRU = nil // 重建（惰性，下一首包触发）
	}
	if z.flowLRU == nil {
		z.flowLRU = newFlowSeenLRU(cfg.FlowLRUCap)
	}
	if z.flowLRU.firstSeen(flowKey(rec)) {
		b.NewFlows++
	}

	// flag/协议计数：流级 flags 近似作用于全流包数（骨架口径）
	pkts := rec.Packets
	switch rec.Proto {
	case protoTCP:
		b.TCPPkts += pkts
		switch {
		case rec.TCPFlags&flagSYN != 0 && rec.TCPFlags&flagACK == 0:
			b.Syn += pkts
		case rec.TCPFlags&flagSYN != 0 && rec.TCPFlags&flagACK != 0:
			b.SynAck += pkts
		case rec.TCPFlags&flagACK != 0:
			b.Ack += pkts
		}
		if rec.TCPFlags&flagRST != 0 {
			b.Rst += pkts
		}
	case protoUDP:
		b.UDPPkts += pkts
	case protoICMP:
		b.ICMPPkts += pkts
	}

	// 每源统计 + 扫段结构
	if z.srcAdd(rec) {
		z.overflowN++
	}
	z.sweepAdd(rec, sec, cfg)
}

// bucket —— 取秒桶（槽复用时重置；惰性建 HLL 由 add 负责）。
func (z *zoneState) bucket(sec int64) *SecBucket {
	b := &z.ring60[sec%ring60Len]
	if b.Sec != sec {
		*b = SecBucket{Sec: sec}
	}
	return b
}

// bucketAt —— 只读取秒桶（未命中返回空桶副本，评估用）。
func (z *zoneState) bucketAt(sec int64) SecBucket {
	b := z.ring60[sec%ring60Len]
	if b.Sec != sec {
		return SecBucket{}
	}
	return b
}

// push5m —— 关闭秒写入 5m 轻量桶。
func (z *zoneState) push5m(sec int64, b SecBucket) {
	l := &z.ring5m[sec%ring5mLen]
	*l = SecBucketLite{Sec: sec, Bps: b.Bps, Pps: b.Pps, NewFlows: b.NewFlows}
}

// shortBaselineBps —— ring5m 均值（短基线参考；M2 基线引擎接入前的回显口径）。
func (z *zoneState) shortBaselineBps() (float64, int) {
	var sum uint64
	n := 0
	for i := range z.ring5m {
		if z.ring5m[i].Sec != 0 {
			sum += z.ring5m[i].Bps
			n++
		}
	}
	if n == 0 {
		return 0, 0
	}
	return float64(sum) / float64(n), n
}

// IP 协议号（命名白名单缩写外须写全，见 docs/11 §1）。
const (
	protoICMP uint32 = 1
	protoTCP  uint32 = 6
	protoUDP  uint32 = 17
)

// flowKey —— newflows 判定键：(src, dst, proto) xxhash64。
func flowKey(rec *shared.FlowRecord) uint64 {
	var buf [36]byte
	copy(buf[:16], rec.SrcIP[:])
	copy(buf[16:32], rec.DstIP[:])
	buf[32] = byte(rec.Proto)
	buf[33] = byte(rec.Proto >> 8)
	buf[34] = byte(rec.Proto >> 16)
	buf[35] = byte(rec.Proto >> 24)
	return xxhash.Sum64(buf[:])
}

// flowSeenLRU —— 定容 LRU 首包判定（dd/03 §3.3：分钟级 8K 近似流表）。
type flowSeenLRU struct {
	cap   int
	m     map[uint64]*list.Element
	order *list.List // front=最近
}

func newFlowSeenLRU(capacity int) *flowSeenLRU {
	return &flowSeenLRU{cap: capacity, m: make(map[uint64]*list.Element, capacity), order: list.New()}
}

func (l *flowSeenLRU) firstSeen(key uint64) bool {
	if el, ok := l.m[key]; ok {
		l.order.MoveToFront(el)
		return false
	}
	if len(l.m) >= l.cap {
		// LRU 淘汰：等价于该老流"遗忘"，后续包可能再次计为新流（容量近似，dd/03 §3.3）
		if back := l.order.Back(); back != nil {
			l.order.Remove(back)
			delete(l.m, back.Value.(uint64))
		}
	}
	l.m[key] = l.order.PushFront(key)
	return true
}

// srcHash / dstHash —— srcAgg 与 HLL 的源/目的散列。
func srcHash(rec *shared.FlowRecord) uint64 { return xxhash.Sum64(rec.SrcIP[:]) }
func dstHash(rec *shared.FlowRecord) uint64 { return xxhash.Sum64(rec.DstIP[:]) }
