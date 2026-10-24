package detector

import (
	"encoding/json"
	"net"

	"github.com/SchearLoe/lucidnet/analytics/internal/fsm"
	"github.com/SchearLoe/lucidnet/shared"
)

// synEvidenceJSON —— SYN Flood 证据快照（AttackEvent.evidence_json）。
type synEvidenceJSON struct {
	SynRatio    float64 `json:"syn_ratio"`
	NewFlows    uint64  `json:"newflows_per_sec"`
	Bps         uint64  `json:"bps"`
	BaselineBps float64 `json:"baseline_bps"`
	BaselineOK  bool    `json:"baseline_ok"`
	Syn         uint64  `json:"syn_pkts"`
	SynAck      uint64  `json:"synack_pkts"`
	WindowSec   int64   `json:"window_sec"`
}

// synHit —— 单个 1s 窗 SYN Flood 判定（dd/03 §4.1）：
// syn/(syn+synack) > 0.7 且 newflows > T_syn 且 bps ≥ 基线×3。
// 无基线（学习期）时比率条件退化为绝对阈值（dd/03 §5 冷启动兜底）。
func (d *Detector) synHit(z *zoneState, b SecBucket) (bool, synEvidenceJSON) {
	ej := synEvidenceJSON{
		NewFlows:  b.NewFlows,
		Bps:       b.Bps,
		Syn:       b.Syn,
		SynAck:    b.SynAck,
		WindowSec: b.Sec,
	}
	denom := b.Syn + b.SynAck
	if denom == 0 || b.NewFlows <= d.cfg.SynNewflowsPerSec {
		return false, ej
	}
	ej.SynRatio = float64(b.Syn) / float64(denom)
	if ej.SynRatio <= d.cfg.SynRatioThreshold {
		return false, ej
	}
	baseline, ok := d.cfg.Baseline.ZoneBps(z.zoneID)
	ej.BaselineBps, ej.BaselineOK = baseline, ok
	if ok && float64(b.Bps) < baseline*d.cfg.SynBaselineRatio {
		return false, ej
	}
	return true, ej
}

// evalSyn —— 关闭秒评估：命中压入 3 窗环，2/3 命中 → CONFIRMED（dd/03 §3/§6.1）。
func (d *Detector) evalSyn(z *zoneState, sec int64, b SecBucket) {
	hit, ej := d.synHit(z, b)

	z.synWin[z.synPos] = hit
	z.synPos = (z.synPos + 1) % len(z.synWin)
	if z.synN < len(z.synWin) {
		z.synN++
	}
	hits := 0
	for _, h := range z.synWin {
		if h {
			hits++
		}
	}
	if d.fsm == nil {
		return
	}

	switch {
	case hits >= 2 && hit:
		// 2/3 窗命中：确认（首窗命中已在 Candidate 建档）
		d.fsm.Confirm(z.zoneID, shared.AttackSYNFlood, synEvidence(z, b, ej))
	case hit:
		// 单窗命中：候选/刷新（抖动 1/3 不确认）
		d.fsm.Candidate(z.zoneID, shared.AttackSYNFlood, synEvidence(z, b, ej))
	case hits >= 2:
		// 本窗未命中但 2/3 仍满足：仅保活（空证据不外发、不降峰值）
		d.fsm.Hit(z.zoneID, shared.AttackSYNFlood, fsm.Evidence{})
	}
}

func synEvidence(z *zoneState, b SecBucket, ej synEvidenceJSON) fsm.Evidence {
	tops := z.topSources(10)
	srcs := make([]string, 0, len(tops))
	for _, t := range tops {
		srcs = append(srcs, net.IP(t.IP[:]).String())
	}
	ejJSON, err := json.Marshal(ej)
	ev := fsm.Evidence{
		PeakBps:    int64(b.Bps),
		PeakPps:    int64(b.Pps),
		TopSources: srcs,
	}
	if err == nil {
		ev.EvidenceJSON = string(ejJSON)
	}
	return ev
}
