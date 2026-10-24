// Package store —— 网关内存近端缓存（M1）：消费 alarms（gateway.ws 组）维护
// 攻击注册表 + 告警环形缓冲 + 客户域实时快照，支撑实时列表/总览 API。
// 容量受 config.RecentAttacksCap/RecentAlarmsCap 限制；重启后为空（历史数据属
// Storage，docs/09 §6/§7）。并发安全。
package store

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/SchearLoe/lucidnet/shared"

	"github.com/SchearLoe/lucidnet/console/internal/query"
)

// Memory —— 内存近端缓存（query.AttackReader / query.AlarmReader / query.RealtimeReader）。
type Memory struct {
	mu       sync.RWMutex
	attacks  map[string]*shared.AttackEvent // attack_id → 最新快照
	order    []string                       // 插入序（新在后）
	attackCap int                              // 注册表上限（构造参数）
	alarms   []*shared.Alarm                // 环形缓冲（新在后，满则淘汰最旧）
	alarmCap int
	zones    map[int32]*zoneState
	now      func() time.Time
}

type zoneState struct {
	name     string
	bpsIn    float64
	bpsOut   float64
	ppsIn    float64
	ppsOut   float64
	sample   uint32
	tsMs     int64
}

// NewMemory 构造；attackCap/alarmCap 为容量上限。
func NewMemory(attackCap, alarmCap int) *Memory {
	if attackCap <= 0 {
		attackCap = 1000
	}
	if alarmCap <= 0 {
		alarmCap = 10000
	}
	return &Memory{
		attacks:   make(map[string]*shared.AttackEvent, attackCap),
		attackCap: attackCap,
		alarmCap:  alarmCap,
		zones:     make(map[int32]*zoneState),
		now:       time.Now,
	}
}

// WithClock 注入时间源（确定性单测）。
func (m *Memory) WithClock(now func() time.Time) *Memory {
	m.now = now
	return m
}

// UpsertAttack 应用攻击事件快照（alarms topic AttackEvent 载荷；状态机推进覆盖写）。
func (m *Memory) UpsertAttack(a *shared.AttackEvent) {
	if a == nil || a.AttackID == "" {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.attacks[a.AttackID]; !exists {
		m.order = append(m.order, a.AttackID)
		// 超容量淘汰最旧（内存近端缓存语义，历史查询走 Storage）。
		for len(m.order) > m.attackCap {
			evict := m.order[0]
			m.order = m.order[1:]
			delete(m.attacks, evict)
		}
	}
	cp := *a
	m.attacks[a.AttackID] = &cp
	m.applyZoneLocked(a)
}

// AppendAlarm 追加通用告警（环形缓冲）。
func (m *Memory) AppendAlarm(a *shared.Alarm) {
	if a == nil || a.AlarmID == "" {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := *a
	m.alarms = append(m.alarms, &cp)
	if len(m.alarms) > m.alarmCap {
		m.alarms = m.alarms[len(m.alarms)-m.alarmCap:]
	}
}

// UpdateZone 刷新客户域实时速率（生产源=Redis rt:*；M1 由聚合/桩注入）。
func (m *Memory) UpdateZone(zoneID int32, name string, bpsIn, bpsOut, ppsIn, ppsOut float64, sample uint32, tsMs int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	z, ok := m.zones[zoneID]
	if !ok {
		z = &zoneState{}
		m.zones[zoneID] = z
	}
	z.name, z.bpsIn, z.bpsOut, z.ppsIn, z.ppsOut, z.sample, z.tsMs =
		name, bpsIn, bpsOut, ppsIn, ppsOut, sample, tsMs
}

// ListAttacks 实现 query.AttackReader：攻击中置顶（状态未关闭/未缓解），
// 再按峰值 bps 降序、置信度降序（docs/dd/05 §3.1）。
func (m *Memory) ListAttacks(_ context.Context, f query.AttackFilter) (query.Page[*shared.AttackEvent], error) {
	m.mu.RLock()
	rows := make([]*shared.AttackEvent, 0, len(m.attacks))
	for _, id := range m.order {
		a := m.attacks[id]
		if !matchAttack(a, f) {
			continue
		}
		rows = append(rows, a)
	}
	total := len(rows)
	m.mu.RUnlock()

	sort.SliceStable(rows, func(i, j int) bool {
		oi, oj := ongoing(rows[i]), ongoing(rows[j])
		if oi != oj {
			return oi // 攻击中置顶
		}
		if rows[i].PeakBps != rows[j].PeakBps {
			return rows[i].PeakBps > rows[j].PeakBps
		}
		return rows[i].Confidence > rows[j].Confidence
	})
	rows = paginatePtr(rows, f.Page, f.PageSize)
	return query.Page[*shared.AttackEvent]{Rows: rows, Total: total}, nil
}

// GetAttack 实现 query.AttackReader。
func (m *Memory) GetAttack(_ context.Context, id string) (*shared.AttackEvent, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if a, ok := m.attacks[id]; ok {
		cp := *a
		return &cp, nil
	}
	return nil, query.ErrUpstreamUnavailable
}

// AttackMinutes —— M1 不在网关内存实现（attack_minutes 属 CH，提供方 Storage，
// docs/09 §8）：交由 upstream 客户端；此方法仅满足接口组合，见 httpapi 装配。
func (m *Memory) AttackMinutes(context.Context, string, int64, int64) ([]shared.AttackMinute, error) {
	return nil, query.ErrUpstreamUnavailable
}

// ListAlarms 实现 query.AlarmReader（新在前）。
func (m *Memory) ListAlarms(_ context.Context, f query.AlarmFilter) (query.Page[*shared.Alarm], error) {
	m.mu.RLock()
	rows := make([]*shared.Alarm, 0, len(m.alarms))
	for i := len(m.alarms) - 1; i >= 0; i-- {
		a := m.alarms[i]
		if !matchAlarm(a, f) {
			continue
		}
		rows = append(rows, a)
	}
	total := len(rows)
	m.mu.RUnlock()

	rows = paginatePtr(rows, f.Page, f.PageSize)
	return query.Page[*shared.Alarm]{Rows: rows, Total: total}, nil
}

// ZoneRealtime 实现 query.RealtimeReader（按 zone_id 升序，稳定输出）。
func (m *Memory) ZoneRealtime(_ context.Context) ([]query.ZoneTraffic, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]query.ZoneTraffic, 0, len(m.zones))
	for id, z := range m.zones {
		ongoingN, totalN := m.zoneAttackCountLocked(id)
		out = append(out, query.ZoneTraffic{
			ZoneID:      id,
			ZoneName:    z.name,
			BpsIn:       z.bpsIn,
			BpsOut:      z.bpsOut,
			PpsIn:       z.ppsIn,
			PpsOut:      z.ppsOut,
			AttackCount: totalN,
			Ongoing:     ongoingN,
			SampleRate:  z.sample,
			TsMs:        z.tsMs,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ZoneID < out[j].ZoneID })
	return out, nil
}

func (m *Memory) applyZoneLocked(a *shared.AttackEvent) {
	z, ok := m.zones[a.ZoneID]
	if !ok {
		z = &zoneState{}
		m.zones[a.ZoneID] = z
	}
	if z.name == "" {
		z.name = a.ZoneName
	}
}

func (m *Memory) zoneAttackCountLocked(zoneID int32) (ongoing, total int) {
	for _, id := range m.order {
		a := m.attacks[id]
		if a.ZoneID != zoneID {
			continue
		}
		total++
		if ongoingStatus(a.Status) {
			ongoing++
		}
	}
	return ongoing, total
}

func matchAttack(a *shared.AttackEvent, f query.AttackFilter) bool {
	if f.ZoneID != 0 && a.ZoneID != f.ZoneID {
		return false
	}
	if len(f.Types) > 0 && !containsType(f.Types, a.AttackType) {
		return false
	}
	if len(f.Statuses) > 0 && !containsStatus(f.Statuses, a.Status) {
		return false
	}
	if f.FromMs != 0 && a.StartMs < f.FromMs {
		return false
	}
	if f.ToMs != 0 && a.StartMs > f.ToMs {
		return false
	}
	return true
}

func matchAlarm(a *shared.Alarm, f query.AlarmFilter) bool {
	if f.ZoneID != 0 && a.ZoneID != f.ZoneID {
		return false
	}
	if len(f.Severities) > 0 && !containsSeverity(f.Severities, a.Severity) {
		return false
	}
	if len(f.Categories) > 0 && !containsCategory(f.Categories, a.Category) {
		return false
	}
	if f.FromMs != 0 && a.RaiseMs < f.FromMs {
		return false
	}
	if f.ToMs != 0 && a.RaiseMs > f.ToMs {
		return false
	}
	return true
}

func ongoingStatus(s shared.AttackStatus) bool {
	return s == shared.AttackCandidate || s == shared.AttackConfirmed || s == shared.AttackMitigating
}

func ongoing(a *shared.AttackEvent) bool {
	return ongoingStatus(a.Status) && a.EndMs == 0
}

func containsType(list []shared.AttackType, v shared.AttackType) bool {
	for _, item := range list {
		if item == v {
			return true
		}
	}
	return false
}

func containsStatus(list []shared.AttackStatus, v shared.AttackStatus) bool {
	for _, item := range list {
		if item == v {
			return true
		}
	}
	return false
}

func containsSeverity(list []shared.AlarmSeverity, v shared.AlarmSeverity) bool {
	for _, item := range list {
		if item == v {
			return true
		}
	}
	return false
}

func containsCategory(list []shared.AlarmCategory, v shared.AlarmCategory) bool {
	for _, item := range list {
		if item == v {
			return true
		}
	}
	return false
}

// paginatePtr 统一分页裁剪（docs/00 §6 ?page=&page_size=；page 从 1 起）。
func paginatePtr[T any](rows []T, page, pageSize int) []T {
	if pageSize <= 0 {
		pageSize = 20
	}
	if page <= 0 {
		page = 1
	}
	start := (page - 1) * pageSize
	if start >= len(rows) {
		return nil
	}
	end := start + pageSize
	if end > len(rows) {
		end = len(rows)
	}
	return rows[start:end]
}
