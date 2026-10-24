// Package detector —— Zone 秒级检测引擎（dd/03 §3/§4，R2/R7 核心）。
//
// 每 zone 一份 ZoneState（惰性创建）：ring60 1s 环形窗 + ring5m 轻量短基线桶 +
// srcAgg 每源统计（上限 50,000，超限降级 Count-Min Sketch 桩）+ sweep 扫段
// per-/24(v4)、/64(v6) HyperLogLog + entropy/波动状态。规则组（骨架范围）：
// SYN Flood（2/3 窗确认）、SWEEP（10s 窗 HLL distinct-dst）、ANOMALY（EWMA+MAD）。
//
// 单分区单 goroutine（dd/03 §1：同客户全部记录固定同一 goroutine，检测状态无锁），
// 故本包所有类型非并发安全；main 以单事件循环结构保证（见 cmd/lucid-analytics）。
package detector

import (
	"errors"
	"time"

	"github.com/SchearLoe/lucidnet/analytics/internal/fsm"
	"github.com/SchearLoe/lucidnet/shared"
)

// errNilRecord —— Add 收到 nil 记录。
var errNilRecord = errors.New("detector: nil flow record")

// TCP flag 位掩码（IP 标准位序；shared 尚未定义，契约缺口已记录 README）。
const (
	flagFIN uint32 = 1 << 0
	flagSYN uint32 = 1 << 1
	flagRST uint32 = 1 << 2
	flagPSH uint32 = 1 << 3
	flagACK uint32 = 1 << 4
	flagURG uint32 = 1 << 5
)

// Config —— 检测引擎参数（默认值见 DefaultConfig，dd/03 §4；阈值可按 zone 覆盖，TODO etcd）。
type Config struct {
	Clock func() time.Time

	// SYN Flood（dd/03 §4.1）
	SynNewflowsPerSec uint64  // T_syn，默认 5,000/s
	SynRatioThreshold float64 // syn/(syn+synack)，默认 0.7
	SynBaselineRatio  float64 // bps ≥ 基线×3

	// 扫段（dd/03 §4.2）
	SweepWindow       time.Duration // 10s 滑窗（骨架实现为对齐翻转窗，README 有说明）
	SweepMinDistinct  uint32        // distinct_dst 下限 max(32, 基线×0.3)
	SweepPerDstAvgMax float64       // per_dst_avg_pkts < 3
	SweepSrcDstRatio  float64       // 源集中度：distinct_src/distinct_dst < 0.2（少源多点）
	SweepCellsMax     int           // 每 zone 扫段 cell 上限（LRU），默认 4,096

	// 波动（dd/03 §4.3）
	AnomalyAlpha       float64       // EWMA α=0.1
	AnomalyMADMult     float64       // |x−ewma| > 8×MAD
	AnomalyMADFloor    float64       // MAD 下限系数 × ewma（全平窗口防整数噪声误报）
	AnomalyConsecutive int           // 连续 3s
	AnomalySuppress    time.Duration // 同 zone 5 分钟内不重复告警
	AnomalyMinSamples  int           // 历史样本下限（学习保护）

	// 通用
	SrcAggCap     int           // 每源统计上限，默认 50,000（dd/03 §3.1）
	FlowLRUCap    int           // newflows 判定 (src,dst,proto) 分钟 LRU，默认 8,192
	LateDropAge   time.Duration // 迟到丢弃：>60s 只进聚合不进检测（dd/03 §8 的骨架口径）
	ZoneIdlePrune time.Duration // 空闲 zone 回收（默认 10min）

	Baseline BaselineProvider // 基线引擎（M2，dd/03 §5）；nil=无基线（绝对阈值兜底）
}

// DefaultConfig —— dd/03 §4 默认阈值。
func DefaultConfig() Config {
	return Config{
		Clock: time.Now,

		SynNewflowsPerSec: 5000,
		SynRatioThreshold: 0.7,
		SynBaselineRatio:  3.0,

		SweepWindow:       10 * time.Second,
		SweepMinDistinct:  32,
		SweepPerDstAvgMax: 3.0,
		SweepSrcDstRatio:  0.2,
		SweepCellsMax:     4096,

		AnomalyAlpha:       0.1,
		AnomalyMADMult:     8.0,
		AnomalyMADFloor:    0.1,
		AnomalyConsecutive: 3,
		AnomalySuppress:    5 * time.Minute,
		AnomalyMinSamples:  10,

		SrcAggCap:     50000,
		FlowLRUCap:    8192,
		LateDropAge:   60 * time.Second,
		ZoneIdlePrune: 10 * time.Minute,

		Baseline: NoneBaseline{},
	}
}

func (c *Config) fill() {
	d := DefaultConfig()
	if c.Clock == nil {
		c.Clock = d.Clock
	}
	if c.SynNewflowsPerSec == 0 {
		c.SynNewflowsPerSec = d.SynNewflowsPerSec
	}
	if c.SynRatioThreshold == 0 {
		c.SynRatioThreshold = d.SynRatioThreshold
	}
	if c.SynBaselineRatio == 0 {
		c.SynBaselineRatio = d.SynBaselineRatio
	}
	if c.SweepWindow <= 0 {
		c.SweepWindow = d.SweepWindow
	}
	if c.SweepMinDistinct == 0 {
		c.SweepMinDistinct = d.SweepMinDistinct
	}
	if c.SweepPerDstAvgMax == 0 {
		c.SweepPerDstAvgMax = d.SweepPerDstAvgMax
	}
	if c.SweepSrcDstRatio == 0 {
		c.SweepSrcDstRatio = d.SweepSrcDstRatio
	}
	if c.SweepCellsMax <= 0 {
		c.SweepCellsMax = d.SweepCellsMax
	}
	if c.AnomalyAlpha == 0 {
		c.AnomalyAlpha = d.AnomalyAlpha
	}
	if c.AnomalyMADMult == 0 {
		c.AnomalyMADMult = d.AnomalyMADMult
	}
	if c.AnomalyMADFloor == 0 {
		c.AnomalyMADFloor = d.AnomalyMADFloor
	}
	if c.AnomalyConsecutive == 0 {
		c.AnomalyConsecutive = d.AnomalyConsecutive
	}
	if c.AnomalySuppress <= 0 {
		c.AnomalySuppress = d.AnomalySuppress
	}
	if c.AnomalyMinSamples == 0 {
		c.AnomalyMinSamples = d.AnomalyMinSamples
	}
	if c.SrcAggCap <= 0 {
		c.SrcAggCap = d.SrcAggCap
	}
	if c.FlowLRUCap <= 0 {
		c.FlowLRUCap = d.FlowLRUCap
	}
	if c.LateDropAge <= 0 {
		c.LateDropAge = d.LateDropAge
	}
	if c.ZoneIdlePrune <= 0 {
		c.ZoneIdlePrune = d.ZoneIdlePrune
	}
	if c.Baseline == nil {
		c.Baseline = d.Baseline
	}
}

// BaselineProvider —— 基线引擎查询（dd/03 §5，M2）。
// ok=false 表示学习期/无基线：比率条件退化为绝对阈值（dd/03 §5 冷启动兜底）。
type BaselineProvider interface {
	ZoneBps(zoneID int32) (bps float64, ok bool)
}

// NoneBaseline —— 无基线（骨架默认）：所有比率条件走绝对阈值兜底。
type NoneBaseline struct{}

func (NoneBaseline) ZoneBps(int32) (float64, bool) { return 0, false }

// Detector —— Zone 检测引擎（持有全部 ZoneState；非并发安全，见包注释）。
type Detector struct {
	cfg Config
	fsm *fsm.Manager

	zones map[int32]*zoneState

	stats Stats
}

// Stats —— 运行计数（Prometheus 对接 M2，命名见 docs/11 §9）。
type Stats struct {
	RecordsIn      uint64 // 进入 Add 的记录
	NoZone         uint64 // zone_id=0 仅聚合，不进检测（dd/03 §1）
	StaleDrop      uint64 // 迟到 >LateDropAge / 已关闭秒，跳过检测
	SrcAggOverflow uint64 // 每源统计超上限降级次数
	SweepCells     int    // 当前扫段 cell 数峰值（全 zone 合计）
}

// New 构造检测引擎；mgr 为攻击状态机（可为 nil：仅计数不产事件，测试用）。
func New(cfg Config, mgr *fsm.Manager) *Detector {
	cfg.fill()
	return &Detector{
		cfg:   cfg,
		fsm:   mgr,
		zones: make(map[int32]*zoneState),
	}
}

// nowSec —— 当前秒（注入时钟）。
func (d *Detector) nowSec() int64 { return d.cfg.Clock().Unix() }

// Add 处理一条 FlowRecord（检测路径，≤1µs/条目标，dd/03 §3.3）：
// 互联过滤不在检测入口（zone 命中记录天然为客户流量，dd/03 §2.2 仅聚合入口过滤）。
func (d *Detector) Add(rec *shared.FlowRecord) error {
	if rec == nil {
		return errNilRecord
	}
	d.stats.RecordsIn++
	if rec.ZoneID == 0 {
		d.stats.NoZone++
		return nil // 未命中客户域只进全局聚合（dd/03 §1）
	}
	nowSec := d.nowSec()
	recSec := rec.TimeStartMs / 1000
	if recSec <= nowSec-int64(d.cfg.LateDropAge.Seconds()) {
		d.stats.StaleDrop++ // >60s 迟到：只进聚合不进检测（dd/03 §8）
		return nil
	}
	z := d.zones[rec.ZoneID]
	if z == nil {
		z = newZoneState(rec.ZoneID, recSec, d.cfg)
		d.zones[rec.ZoneID] = z
	}
	z.lastAddMs = d.cfg.Clock().UnixMilli()
	if recSec <= z.lastClosed {
		d.stats.StaleDrop++ // 该秒已评估关闭
		return nil
	}
	if recSec > nowSec+5 {
		d.stats.StaleDrop++ // 时钟偏移超前的记录
		return nil
	}
	z.add(rec, d.cfg)
	return nil
}

// Tick 推进秒评估：关闭 now-2 秒（含）之前的全部秒（1s 数据 + 1s 迟到宽限），
// 逐秒喂给各规则与波动状态；扫段窗在秒边界对齐翻转。
func (d *Detector) Tick() {
	target := d.nowSec() - 2
	for id, z := range d.zones {
		for s := z.lastClosed + 1; s <= target; s++ {
			d.evaluateSecond(z, s)
		}
		if target > z.lastClosed {
			z.lastClosed = target
		}
		d.maybePrune(id, z)
	}
}

// ZoneCount —— 当前活跃 zone 数（容量观测）。
func (d *Detector) ZoneCount() int { return len(d.zones) }

// Stats —— 运行计数快照。
func (d *Detector) Stats() Stats {
	st := d.stats
	st.SweepCells = 0
	for _, z := range d.zones {
		st.SweepCells += z.sweep.len()
		st.SrcAggOverflow += z.overflowN
	}
	return st
}

// evaluateSecond —— 关闭秒 sec 的统一评估路径：熵估计固化 → ring5m → 规则组。
func (d *Detector) evaluateSecond(z *zoneState, sec int64) {
	b := z.bucketAt(sec)
	// dst_ent/src_card 固化（HLL 估计写入槽位，供证据/分钟详情读取）
	if slot := &z.ring60[sec%ring60Len]; slot.Sec == sec && slot.dstH != nil {
		slot.DstEnt = uint32(slot.dstH.Estimate())
		slot.SrcCard = uint32(slot.srcH.Estimate())
		b.DstEnt, b.SrcCard = slot.DstEnt, slot.SrcCard
	}
	z.push5m(sec, b)
	d.evalSyn(z, sec, b)
	d.evalAnomaly(z, sec, b)

	winSec := int64(d.cfg.SweepWindow.Seconds())
	if (sec+1)%winSec == 0 { // 10s 窗完整关闭（对齐翻转窗，README 取舍说明）
		z.sweep.evalWindow(z, sec/winSec, winSec, d)
	}
}

// maybePrune —— 空闲且无活跃攻击的 zone 回收（Ring 状态无跨节点复制，dd/03 §8）。
func (d *Detector) maybePrune(zoneID int32, z *zoneState) {
	idle := d.cfg.Clock().UnixMilli() - z.lastAddMs
	if idle < d.cfg.ZoneIdlePrune.Milliseconds() {
		return
	}
	if d.fsm != nil {
		for _, t := range trackedAttackTypes {
			if d.fsm.State(zoneID, t) != fsm.StateNone {
				return // 攻击活跃期不回收
			}
		}
	}
	delete(d.zones, zoneID)
}

// trackedAttackTypes —— 本骨架会产生的攻击类型（prune 检查用）。
var trackedAttackTypes = []shared.AttackType{
	shared.AttackSYNFlood,
	shared.AttackUDPFlood,
	shared.AttackACKFlood,
	shared.AttackICMPFlood,
	shared.AttackReflection,
	shared.AttackSweep,
	shared.AttackAnomaly,
}
