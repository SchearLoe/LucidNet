package detector

import (
	"encoding/json"
	"math"
	"sort"

	"github.com/SchearLoe/lucidnet/analytics/internal/fsm"
	"github.com/SchearLoe/lucidnet/shared"
)

// anomalyState —— 客户总流量波动状态（dd/03 §4.3 秒级通道）：
// zone bps 的 EWMA(α=0.1) + 滑动 60s 历史的 MAD，突变连续 3s → 波动。
type anomalyState struct {
	init      bool
	ewma      float64
	hist      []float64 // 最近 60 个已关闭秒的 bps（环形追加）
	cons      int       // 连续超阈秒数
	spike     bool      // 当前连续段方向：true=暴涨 false=骤降（direction=drop）
	confirmed bool      // 本连续段已确认（段内不重复确认/告警）

	lastRaiseMs int64 // 同 zone 5 分钟抑制（dd/03 §4.3）
}

const anomalyHistCap = 60

// anomalyEvidenceJSON —— 波动证据快照。
type anomalyEvidenceJSON struct {
	Direction     string  `json:"direction"` // spike|drop
	Bps           uint64  `json:"bps"`
	Ewma          float64 `json:"ewma"`
	Mad           float64 `json:"mad"`
	Deviation     float64 `json:"deviation"`
	Threshold     float64 `json:"threshold"`
	Consecutive   int     `json:"consecutive_sec"`
	ShortBaseline float64 `json:"short_baseline_bps"`
}

// evalAnomaly —— 关闭秒评估（dd/03 §4.3：|x−ewma| > 8×MAD 连续 3s）。
func (d *Detector) evalAnomaly(z *zoneState, sec int64, b SecBucket) {
	a := &z.anomaly
	x := float64(b.Bps)

	if !a.init {
		a.init = true
		a.ewma = x
		a.pushHist(x)
		return
	}

	// 阈值以历史（不含当前值）计算，当前突变不稀释 MAD
	mad := medianAbsDev(a.hist)
	floor := d.cfg.AnomalyMADFloor * a.ewma
	thr := d.cfg.AnomalyMADMult * math.Max(mad, floor)
	dev := math.Abs(x - a.ewma)

	if len(a.hist) >= d.cfg.AnomalyMinSamples && a.ewma > 0 {
		if dev > thr {
			dir := x > a.ewma
			if a.cons > 0 && dir != a.spike {
				// 方向翻转（暴涨→回落/骤降→反弹）：上一段终止，新段重计
				// （单秒尖峰后的 EWMA 回落不得续接为"骤降"确认）
				a.cons = 0
				a.confirmed = false
			}
			a.cons++
			a.spike = dir
		} else {
			a.cons = 0
			a.confirmed = false
		}
		d.driveFSM(z, sec, a, x, mad, dev, thr)
	}

	// 先评估后更新：ewma/历史吸收当前值
	a.ewma += d.cfg.AnomalyAlpha * (x - a.ewma)
	a.pushHist(x)
}

// driveFSM —— 按连续超阈秒数驱动状态机（1s 候选 / 3s 确认）。
// 5 分钟抑制仅作用于新一轮候选（cons==1）：同轮内的确认不受抑制窗口影响。
func (d *Detector) driveFSM(z *zoneState, sec int64, a *anomalyState, x, mad, dev, thr float64) {
	if d.fsm == nil || a.cons == 0 {
		return
	}
	if a.cons == 1 {
		nowMs := d.cfg.Clock().UnixMilli()
		if nowMs-a.lastRaiseMs < d.cfg.AnomalySuppress.Milliseconds() {
			a.cons = 0 // 同 zone 5 分钟内不重复告警（dd/03 §4.3 抑制）：本轮静默
			a.confirmed = false
			return
		}
		a.lastRaiseMs = nowMs
	}
	direction := "spike"
	if !a.spike {
		direction = "drop" // 骤降：业务故障/路由切换单独标注
	}
	short, _ := z.shortBaselineBps()
	ej, err := json.Marshal(anomalyEvidenceJSON{
		Direction:     direction,
		Bps:           uint64(x),
		Ewma:          math.Round(a.ewma),
		Mad:           math.Round(mad),
		Deviation:     math.Round(dev),
		Threshold:     math.Round(thr),
		Consecutive:   a.cons,
		ShortBaseline: math.Round(short),
	})
	ev := fsm.Evidence{PeakBps: int64(x)}
	if err == nil {
		ev.EvidenceJSON = string(ej)
	}
	switch {
	case a.cons >= d.cfg.AnomalyConsecutive && !a.confirmed:
		d.fsm.Confirm(z.zoneID, shared.AttackAnomaly, ev)
		a.confirmed = true // 段内只确认一次；后续秒以 Hit 保活
	default:
		if a.cons > 1 || a.confirmed {
			d.fsm.Hit(z.zoneID, shared.AttackAnomaly, ev) // 候选/已确认保活（防静默关闭）
		} else {
			d.fsm.Candidate(z.zoneID, shared.AttackAnomaly, ev)
		}
	}
}

func (a *anomalyState) pushHist(x float64) {
	if len(a.hist) < anomalyHistCap {
		a.hist = append(a.hist, x)
		return
	}
	copy(a.hist, a.hist[1:])
	a.hist[anomalyHistCap-1] = x
}

// medianAbsDev —— 中位数绝对偏差 MAD = median(|x_i − median|)。
func medianAbsDev(xs []float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	med := medianOf(xs)
	devs := make([]float64, len(xs))
	for i, x := range xs {
		devs[i] = math.Abs(x - med)
	}
	return medianOf(devs)
}

// medianOf —— 中位数（排序副本，n≤60）。
func medianOf(xs []float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	tmp := append([]float64(nil), xs...)
	sort.Float64s(tmp)
	n := len(tmp)
	if n%2 == 1 {
		return tmp[n/2]
	}
	return (tmp[n/2-1] + tmp[n/2]) / 2
}
