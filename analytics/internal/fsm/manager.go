// Package fsm —— 攻击状态机（dd/03 §6.1 / §6.3）：
//
//	CANDIDATE ─(2/3 窗确认)─► CONFIRMED ─(连续 120s 无命中)─► RECOVERED ─(展示 60s)─► CLOSED
//	     │                          │
//	     └─(3s 未再命中)─► 关闭(不展示) └─(bgp.mitigations 回执 R9)─► MITIGATING
//	                                        └─(bps ≤ 基线×1.3 维持 60s)─► RESOLVED
//
// 每 (zone, attackType) 一个攻击实例；同 zone 同类型 60s 内合并（取更重证据，
// 重开沿用原 AttackID）。单分区单 goroutine（dd/03 §1），非并发安全。
package fsm

import (
	"time"

	"github.com/SchearLoe/lucidnet/shared"
)

// Config —— 状态机转移参数（dd/03 §6.1 / §6.3）。
type Config struct {
	CandidateCloseAfter time.Duration // CANDIDATE 3s 未再命中 → 关闭（不展示）
	RecoverQuiet        time.Duration // CONFIRMED 连续无命中 → RECOVERED（120s）
	RecoverDisplay      time.Duration // RECOVERED 保持展示 → CLOSED（60s）
	MergeWindow         time.Duration // 同 zone 同类型合并窗（60s）
	ResolveSustained    time.Duration // MITIGATING 速率回落维持 → RESOLVED（60s）
	ResolveRatio        float64       // bps ≤ baseline×1.3 视为回落（dd/03 §6.3）
	Now                 func() time.Time
}

// DefaultConfig —— dd/03 §6.1/§6.3 默认转移条件。
func DefaultConfig() Config {
	return Config{
		CandidateCloseAfter: 3 * time.Second,
		RecoverQuiet:        120 * time.Second,
		RecoverDisplay:      60 * time.Second,
		MergeWindow:         60 * time.Second,
		ResolveSustained:    60 * time.Second,
		ResolveRatio:        1.3,
		Now:                 time.Now,
	}
}

func (c *Config) fill() {
	d := DefaultConfig()
	if c.CandidateCloseAfter <= 0 {
		c.CandidateCloseAfter = d.CandidateCloseAfter
	}
	if c.RecoverQuiet <= 0 {
		c.RecoverQuiet = d.RecoverQuiet
	}
	if c.RecoverDisplay <= 0 {
		c.RecoverDisplay = d.RecoverDisplay
	}
	if c.MergeWindow <= 0 {
		c.MergeWindow = d.MergeWindow
	}
	if c.ResolveSustained <= 0 {
		c.ResolveSustained = d.ResolveSustained
	}
	if c.ResolveRatio <= 0 {
		c.ResolveRatio = d.ResolveRatio
	}
	if c.Now == nil {
		c.Now = d.Now
	}
}

// Emitter —— AttackEvent 发布出口（由 alarm 包实现，Kafka alarms topic，09 §2）。
type Emitter interface {
	EmitAttack(ev *shared.AttackEvent)
}

// Evidence —— 检测规则上报的证据快照（合并时"取更重"以 PeakBps/PeakPps 为准）。
type Evidence struct {
	PeakBps      int64
	PeakPps      int64
	TargetPrefix string
	TopSources   []string
	EvidenceJSON string
}

func (e Evidence) heavierThan(o Evidence) bool {
	return e.PeakBps > o.PeakBps ||
		(e.PeakBps == o.PeakBps && e.PeakPps > o.PeakPps)
}

type attackKey struct {
	zoneID     int32
	attackType shared.AttackType
}

// Attack —— 一个攻击事件的全生命周期（含终态后合并窗登记）。
type Attack struct {
	Event shared.AttackEvent

	state        State
	lastHitMs    int64 // 最近一次规则命中
	recoveredMs  int64 // 进入 RECOVERED 时刻
	underSinceMs int64 // MITIGATING 中速率持续回落的起点
	closedAtMs   int64 // 终态时刻（合并窗计时）
}

func (a *Attack) applyEvidence(ev Evidence) {
	if ev.PeakBps > a.Event.PeakBps {
		a.Event.PeakBps = ev.PeakBps
	}
	if ev.PeakPps > a.Event.PeakPps {
		a.Event.PeakPps = ev.PeakPps
	}
	if ev.TargetPrefix != "" {
		a.Event.TargetPrefix = ev.TargetPrefix
	}
	if ev.EvidenceJSON != "" {
		a.Event.EvidenceJSON = ev.EvidenceJSON
	}
	if len(ev.TopSources) > 0 {
		a.Event.TopSources = ev.TopSources
	}
}

func (a *Attack) peaks() Evidence {
	return Evidence{PeakBps: a.Event.PeakBps, PeakPps: a.Event.PeakPps}
}

// Manager —— 状态机集合（按 zone+attackType 索引）。
type Manager struct {
	cfg    Config
	emit   Emitter
	active map[attackKey]*Attack
	closed map[attackKey]*Attack // 终态合并窗登记
}

// New 构造状态机管理器；emit 可为 nil（无发布，仅测试状态）。
func New(cfg Config, emit Emitter) *Manager {
	cfg.fill()
	return &Manager{
		cfg:    cfg,
		emit:   emit,
		active: make(map[attackKey]*Attack),
		closed: make(map[attackKey]*Attack),
	}
}

func (m *Manager) nowMs() int64 { return m.cfg.Now().UnixMilli() }

// Candidate 上报一次规则命中（未达确认）：新建或刷新候选；同类型终态 60s 内
// 合并 → 重开原 AttackID（dd/03 §6.1）。返回当前事件快照。
func (m *Manager) Candidate(zoneID int32, attackType shared.AttackType, ev Evidence) *shared.AttackEvent {
	k := attackKey{zoneID, attackType}
	ms := m.nowMs()

	if a := m.active[k]; a != nil {
		a.lastHitMs = ms
		if ev.heavierThan(a.peaks()) {
			a.applyEvidence(ev)
			m.emitEv(a)
		}
		return &a.Event
	}
	if c := m.closed[k]; c != nil {
		if ms-c.closedAtMs < m.cfg.MergeWindow.Milliseconds() {
			delete(m.closed, k)
			m.reopen(c, k, ev, ms)
			return &c.Event
		}
		delete(m.closed, k) // 合并窗过期
	}

	a := &Attack{state: StateCandidate, lastHitMs: ms}
	a.Event = shared.AttackEvent{
		AttackID:     NewULID(m.cfg.Now()),
		ZoneID:       zoneID,
		AttackType:   attackType,
		StartMs:      ms,
		PeakBps:      ev.PeakBps,
		PeakPps:      ev.PeakPps,
		Confidence:   0.5,
		TopSources:   ev.TopSources,
		EvidenceJSON: ev.EvidenceJSON,
		Status:       shared.AttackCandidate,
	}
	if ev.TargetPrefix != "" {
		a.Event.TargetPrefix = ev.TargetPrefix
	}
	m.active[k] = a
	m.emitEv(a)
	return &a.Event
}

// reopen —— 合并窗内重开：沿用 AttackID，开启新一轮窗口（证据峰值重置为本轮）。
func (m *Manager) reopen(a *Attack, k attackKey, ev Evidence, ms int64) {
	a.state = StateCandidate
	a.Event.StartMs = ms
	a.Event.EndMs = 0
	a.Event.Status = shared.AttackCandidate
	a.Event.PeakBps = ev.PeakBps
	a.Event.PeakPps = ev.PeakPps
	a.applyEvidence(ev)
	a.lastHitMs = ms
	a.recoveredMs = 0
	a.underSinceMs = 0
	m.active[k] = a
	m.emitEv(a)
}

// Confirm 规则确认（2/3 窗 / 窗口级判定）：CANDIDATE→CONFIRMED。
// 无候选时自动补建候选（同秒内完成，dd/03 首告警 ≤5s 路径）。
func (m *Manager) Confirm(zoneID int32, attackType shared.AttackType, ev Evidence) *shared.AttackEvent {
	k := attackKey{zoneID, attackType}
	if m.active[k] == nil {
		m.Candidate(zoneID, attackType, ev)
	}
	a := m.active[k]
	if a == nil {
		return nil
	}
	if a.state != StateCandidate && a.state != StateConfirmed {
		return &a.Event // MITIGATING 等活跃态不回退
	}
	a.state = StateConfirmed
	a.lastHitMs = m.nowMs()
	a.applyEvidence(ev)
	a.Event.Status = shared.AttackConfirmed
	a.Event.Confidence = 0.95
	m.emitEv(a)
	return &a.Event
}

// Hit 刷新最近命中与证据（活跃态通用，不改变状态）。
func (m *Manager) Hit(zoneID int32, attackType shared.AttackType, ev Evidence) *shared.AttackEvent {
	a := m.active[attackKey{zoneID, attackType}]
	if a == nil {
		return nil
	}
	a.lastHitMs = m.nowMs()
	if ev.heavierThan(a.peaks()) {
		a.applyEvidence(ev)
		m.emitEv(a)
	}
	return &a.Event
}

// Mitigation 处置回执联动（dd/03 §6.3，R9）：
// applied→MITIGATING；withdrawn→回退 CONFIRMED（恢复检测驱动生命周期）；
// failed→忽略。返回是否命中活跃攻击。
func (m *Manager) Mitigation(mev shared.MitigationEvent) bool {
	if mev.Result == "failed" {
		return false
	}
	for _, a := range m.active {
		if a.Event.AttackID != mev.AttackID {
			continue
		}
		switch mev.Result {
		case "applied":
			if a.state == StateConfirmed || a.state == StateMitigating {
				a.state = StateMitigating
				a.Event.MitigationID = mev.MitigationID
				a.Event.Status = shared.AttackMitigating
				a.underSinceMs = 0
				m.emitEv(a)
				return true
			}
		case "withdrawn":
			if a.state == StateMitigating {
				a.state = StateConfirmed
				a.Event.Status = shared.AttackConfirmed
				a.lastHitMs = m.nowMs()
				m.emitEv(a)
				return true
			}
		}
		return false
	}
	return false
}

// Rate —— MITIGATING 中的速率回落评估（dd/03 §6.3）：
// bps ≤ baseline×ResolveRatio 持续 ResolveSustained → RESOLVED；反弹重置计时。
// 仅在 MITIGATING 态生效，其余态原样返回当前状态。
func (m *Manager) Rate(zoneID int32, attackType shared.AttackType, bps, baselineBps float64) State {
	k := attackKey{zoneID, attackType}
	a := m.active[k]
	if a == nil {
		return StateNone
	}
	if a.state != StateMitigating {
		return a.state
	}
	if baselineBps <= 0 {
		return a.state // TODO(dd/03 §6.3): 无基线时回退绝对阈值（M2 基线引擎）
	}
	ms := m.nowMs()
	if bps <= baselineBps*m.cfg.ResolveRatio {
		if a.underSinceMs == 0 {
			a.underSinceMs = ms
		}
		if ms-a.underSinceMs >= m.cfg.ResolveSustained.Milliseconds() {
			a.state = StateResolved
			a.Event.EndMs = ms
			a.Event.Status = shared.AttackMitigated
			m.retire(k, a, ms)
			m.emitEv(a)
		}
	} else {
		a.underSinceMs = 0
	}
	return a.state
}

// Tick 推进超时转移：候选静默关闭 / 确认无命中恢复 / 恢复展示期满关闭。
func (m *Manager) Tick() {
	ms := m.nowMs()
	for k, a := range m.active {
		switch a.state {
		case StateCandidate:
			if ms-a.lastHitMs >= m.cfg.CandidateCloseAfter.Milliseconds() {
				// 关闭（不展示，dd/03 §6.1）：静默退役，仅登记合并窗
				a.state = StateClosed
				m.retire(k, a, ms)
			}
		case StateConfirmed:
			if ms-a.lastHitMs >= m.cfg.RecoverQuiet.Milliseconds() {
				a.state = StateRecovered
				a.recoveredMs = ms
				a.Event.EndMs = ms
			}
		case StateRecovered:
			if ms-a.recoveredMs >= m.cfg.RecoverDisplay.Milliseconds() {
				a.state = StateClosed
				a.Event.Status = shared.AttackClosed
				m.retire(k, a, ms)
				m.emitEv(a)
			}
		}
	}
}

// retire —— 终态出 active 表，登记合并窗并惰性清理过期项。
func (m *Manager) retire(k attackKey, a *Attack, ms int64) {
	delete(m.active, k)
	a.closedAtMs = ms
	m.closed[k] = a
	for ck, ca := range m.closed {
		if ms-ca.closedAtMs >= m.cfg.MergeWindow.Milliseconds() {
			delete(m.closed, ck)
		}
	}
}

func (m *Manager) emitEv(a *Attack) {
	if m.emit == nil {
		return
	}
	ev := a.Event // 快照副本，下游不可改内部状态
	m.emit.EmitAttack(&ev)
}

// State 查询当前状态（无活跃攻击返回 StateNone）。
func (m *Manager) State(zoneID int32, attackType shared.AttackType) State {
	if a := m.active[attackKey{zoneID, attackType}]; a != nil {
		return a.state
	}
	return StateNone
}

// Event 查询当前事件快照。
func (m *Manager) Event(zoneID int32, attackType shared.AttackType) (shared.AttackEvent, bool) {
	if a := m.active[attackKey{zoneID, attackType}]; a != nil {
		return a.Event, true
	}
	return shared.AttackEvent{}, false
}

// ActiveCount 活跃攻击数。
func (m *Manager) ActiveCount() int { return len(m.active) }
