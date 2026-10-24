package detector

import (
	"container/list"
	"encoding/json"
	"net"

	"github.com/SchearLoe/lucidnet/analytics/internal/fsm"
	"github.com/SchearLoe/lucidnet/analytics/internal/hll"
	"github.com/SchearLoe/lucidnet/shared"
)

// prefixKey —— 扫段 cell 键：/24(v4) 或 /64(v6) × 协议
// （dd/03 §4.2：ICMP/半开 SYN 扫段按协议维度归类，攻击类型统一 AttackSweep）。
type prefixKey struct {
	v4    bool
	p24   uint32  // v4 /24：高 24bit
	p64   [8]byte // v6 /64：前 8 字节
	proto uint32
}

func prefixKeyOf(rec *shared.FlowRecord) prefixKey {
	k := prefixKey{proto: rec.Proto}
	if rec.IPVersion == 4 {
		k.v4 = true
		k.p24 = uint32(rec.DstIP[12])<<16 | uint32(rec.DstIP[13])<<8 | uint32(rec.DstIP[14])
	} else {
		copy(k.p64[:], rec.DstIP[:8])
	}
	return k
}

// cidr —— 段前缀文本（证据 TargetPrefix）。
func (k prefixKey) cidr() string {
	if k.v4 {
		ip := net.IPv4(byte(k.p24>>16), byte(k.p24>>8), byte(k.p24), 0)
		return ip.String() + "/24"
	}
	var ip [16]byte
	copy(ip[:8], k.p64[:])
	return net.IP(ip[:]).String() + "/64"
}

// sweepTopSrc —— 段内 Top 源（证据输出，cap 64 内近似）。
type sweepTopSrc struct {
	ip   [16]byte
	pkts uint64
}

// sweepWindowResult —— 一个已完结 10s 窗的判定快照。
// 窗口翻转（新窗首条记录到达）先固化快照，秒边界关闭时评估——
// 避免评估滞后（秒关闭 2s 宽限）期间累积被重置丢失。
type sweepWindowResult struct {
	win         int64
	distinct    float64
	srcDistinct float64
	pkts        uint64
	tops        []sweepTopSrc
}

// sweepCell —— 一个 (前缀, 协议) 的 10s 窗累积。
type sweepCell struct {
	key     prefixKey
	win     int64       // 当前累积窗序号（sec/windowSec）
	dst     *hll.Sketch // 2^14 寄存器（dd/03 §4.2）
	src     *hll.Sketch // 源基数 p=6（源集中度条件）
	pkts    uint64
	tops    map[uint64]sweepTopSrc
	pending *sweepWindowResult // 已翻转未评估的窗
	streak  uint32             // 连续命中窗数（第 2 窗确认）
}

const sweepTopSrcCap = 64

func (c *sweepCell) snapshot(win int64) *sweepWindowResult {
	tops := make([]sweepTopSrc, 0, len(c.tops))
	for _, ts := range c.tops {
		tops = append(tops, ts)
	}
	return &sweepWindowResult{
		win:         win,
		distinct:    c.dst.Estimate(),
		srcDistinct: c.src.Estimate(),
		pkts:        c.pkts,
		tops:        tops,
	}
}

func (c *sweepCell) resetFor(win int64) {
	c.win = win
	c.dst.Reset()
	c.src.Reset()
	c.pkts = 0
	c.tops = make(map[uint64]sweepTopSrc, sweepTopSrcCap)
}

// sweepTracker —— 每 zone 扫段结构（LRU 上限 SweepCellsMax=4,096，dd/03 §3.1）。
type sweepTracker struct {
	cells map[prefixKey]*list.Element
	order *list.List // front=最近活跃
	max   int
}

func newSweepTracker(maxCells int) *sweepTracker {
	return &sweepTracker{
		cells: make(map[prefixKey]*list.Element),
		order: list.New(),
		max:   maxCells,
	}
}

// insert —— 记录到达：定位/新建 cell、窗口翻转（固化快照+重置）、HLL 插入。
// stale=true 表示记录属于已评估完成的旧窗（丢弃，dd/03 §8 迟到口径）。
func (t *sweepTracker) insert(rec *shared.FlowRecord, sec int64, winSec int64, lastClosed int64) bool {
	w := sec / winSec
	// 该秒所属窗已整体关闭评估
	if w*winSec+winSec-1 <= lastClosed {
		return true
	}
	key := prefixKeyOf(rec)
	el, ok := t.cells[key]
	var c *sweepCell
	if ok {
		c = el.Value.(*sweepCell)
		t.order.MoveToFront(el)
	} else {
		if len(t.cells) >= t.max {
			if back := t.order.Back(); back != nil {
				t.order.Remove(back)
				delete(t.cells, back.Value.(*sweepCell).key)
			}
		}
		c = &sweepCell{
			key:  key,
			dst:  hll.New(hll.PrecisionDefault),
			src:  hll.New(hll.PrecisionTiny),
			tops: make(map[uint64]sweepTopSrc, sweepTopSrcCap),
		}
		t.cells[key] = t.order.PushFront(c)
	}
	if c.win != w {
		if c.win > w {
			return true // 迟到旧窗
		}
		if c.win > 0 {
			c.pending = c.snapshot(c.win) // 固化已完结窗，待秒边界评估
		}
		c.resetFor(w)
	}
	c.dst.Insert(dstHash(rec))
	c.src.Insert(srcHash(rec))
	c.pkts += rec.Packets
	h := srcHash(rec)
	if ts, ok := c.tops[h]; ok {
		ts.pkts += rec.Packets
		c.tops[h] = ts
	} else if len(c.tops) < sweepTopSrcCap {
		c.tops[h] = sweepTopSrc{ip: rec.SrcIP, pkts: rec.Packets}
	}
	return false
}

// sweepEvidenceJSON —— 扫段证据快照（AttackEvent.evidence_json）。
type sweepEvidenceJSON struct {
	Prefix        string  `json:"prefix"`
	Proto         uint32  `json:"proto"`
	DistinctDst   float64 `json:"distinct_dst"`
	PerDstAvgPkts float64 `json:"per_dst_avg_pkts"`
	SrcDstRatio   float64 `json:"src_dst_ratio"`
	WindowStart   int64   `json:"window_start"`
	NewDstPerSec  float64 `json:"new_dst_per_sec"`
}

// evalWindow —— 窗口完整关闭（该窗最后 1s 已评估）时判定全部 cell：
// 优先消费翻转快照（pending），无新窗记录的 cell 直接评估当前累积。
func (t *sweepTracker) evalWindow(z *zoneState, win int64, winSec int64, d *Detector) {
	for el := t.order.Front(); el != nil; el = el.Next() {
		c := el.Value.(*sweepCell)
		var res *sweepWindowResult
		switch {
		case c.pending != nil && c.pending.win == win:
			res = c.pending
			c.pending = nil
		case c.win == win:
			res = c.snapshot(win)
		case c.win < win:
			c.streak = 0 // 该 cell 未参与刚关闭的窗 → 连击中断
			continue
		default: // c.win > win：未来窗
			continue
		}
		d.judgeSweepWindow(z, c, res, winSec)
	}
}

// judgeSweepWindow —— 单窗判定与状态机驱动。
func (d *Detector) judgeSweepWindow(z *zoneState, c *sweepCell, res *sweepWindowResult, winSec int64) {
	minDistinct := float64(d.cfg.SweepMinDistinct)
	// TODO(dd/03 §4.2)：/24 内活跃 IP 基线×0.3 项待基线引擎（§5，M2）
	perDst := float64(res.pkts) / res.distinct
	ratio := res.srcDistinct / res.distinct
	hit := res.distinct >= minDistinct && res.distinct > 0 &&
		perDst < d.cfg.SweepPerDstAvgMax &&
		ratio < d.cfg.SweepSrcDstRatio
	if hit {
		c.streak++
	} else {
		c.streak = 0
		return
	}
	if d.fsm == nil {
		return
	}
	cidr := c.key.cidr()
	tops := topSrcStrings(res.tops, 5)
	ev := fsm.Evidence{
		PeakPps:      int64(res.pkts / uint64(winSec)),
		TargetPrefix: cidr,
		TopSources:   tops,
	}
	ej, err := json.Marshal(sweepEvidenceJSON{
		Prefix:        cidr,
		Proto:         c.key.proto,
		DistinctDst:   res.distinct,
		PerDstAvgPkts: perDst,
		SrcDstRatio:   ratio,
		WindowStart:   res.win * winSec,
		NewDstPerSec:  res.distinct / float64(winSec),
	})
	if err == nil {
		ev.EvidenceJSON = string(ej)
	}
	switch {
	case c.streak >= 2:
		d.fsm.Confirm(z.zoneID, shared.AttackSweep, ev)
	default:
		d.fsm.Candidate(z.zoneID, shared.AttackSweep, ev)
	}
}

func topSrcStrings(tops []sweepTopSrc, n int) []string {
	all := append([]sweepTopSrc(nil), tops...)
	for i := 0; i < len(all); i++ { // 小 cap 线性选择前 n
		for j := i + 1; j < len(all); j++ {
			if all[j].pkts > all[i].pkts {
				all[i], all[j] = all[j], all[i]
			}
		}
	}
	if len(all) > n {
		all = all[:n]
	}
	out := make([]string, 0, len(all))
	for _, ts := range all {
		out = append(out, net.IP(ts.ip[:]).String())
	}
	return out
}

// sweepAdd —— zone 记录路径的扫段入口（惰性建 tracker，常态无扫段开销为空 map）。
// 迟到旧窗在 insert 内部按 lastClosed 判定丢弃（检测幂等，dd/03 §8）。
func (z *zoneState) sweepAdd(rec *shared.FlowRecord, sec int64, cfg Config) {
	if z.sweep == nil {
		z.sweep = newSweepTracker(cfg.SweepCellsMax)
	}
	_ = z.sweep.insert(rec, sec, int64(cfg.SweepWindow.Seconds()), z.lastClosed)
}

// len —— cell 数（nil 安全，Stats 聚合用）。
func (t *sweepTracker) len() int {
	if t == nil {
		return 0
	}
	return len(t.cells)
}
