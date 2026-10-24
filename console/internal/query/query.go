// Package query —— Console 展示层读模型接口（docs/09 §6：/api/v1/attacks*、topn、
// baseline 提供方为 Storage（读 CH/Redis）+ Analytics（实时状态）；网关是聚合消费方）。
//
// M1 取舍：实时近端数据（攻击列表/告警列表/客户域实时视图）由网关自身消费
// alarms（消费组 gateway.ws）维护内存近端缓存实现；历史与分钟明细走 upstream
// 客户端（Storage QueryService，未部署时降级桩）。接口边界即切换点。
package query

import (
	"context"
	"errors"
	"time"

	"github.com/SchearLoe/lucidnet/shared"
)

// ErrUpstreamUnavailable —— 上游（Storage/Analytics）不可用或未配置。
var ErrUpstreamUnavailable = errors.New("upstream unavailable")

// AttackFilter —— 攻击列表过滤（docs/dd/05 §3.1：客户域/类型/时间段/状态）。
type AttackFilter struct {
	ZoneID    int32             // 0=全部
	Types     []shared.AttackType
	Statuses  []shared.AttackStatus
	FromMs    int64
	ToMs      int64
	Page      int
	PageSize  int
}

// 过滤器构造辅助（测试/调用方少写样板）。

// All 返回不过滤、不分页的过滤器。
func All() AttackFilter { return AttackFilter{} }

// FilterZone 按客户域过滤。
func FilterZone(zoneID int32) AttackFilter { return AttackFilter{ZoneID: zoneID} }

// FilterTypes 按攻击类型过滤。
func FilterTypes(types ...shared.AttackType) AttackFilter { return AttackFilter{Types: types} }

// WithPage 设置分页。
func WithPage(page, pageSize int) AttackFilter { return AttackFilter{Page: page, PageSize: pageSize} }

// AlarmFilter —— 告警列表过滤（R7）。
type AlarmFilter struct {
	ZoneID     int32
	Severities []shared.AlarmSeverity
	Categories []shared.AlarmCategory
	FromMs     int64
	ToMs       int64
	Page       int
	PageSize   int
}

// Page —— 统一分页结果（docs/00 §6：?page=&page_size=）。
type Page[T any] struct {
	Rows  []T `json:"rows"`
	Total int `json:"total"`
}

// AttackReader —— 攻击读模型（R2 实时列表 / R5 详情）。
type AttackReader interface {
	// ListAttacks 实时列表：攻击中置顶，按峰值速率/置信度降序（docs/dd/05 §3.1）。
	ListAttacks(ctx context.Context, f AttackFilter) (Page[*shared.AttackEvent], error)
	// GetAttack 攻击详情头部（含 evidence_json 特征快照）。
	GetAttack(ctx context.Context, id string) (*shared.AttackEvent, error)
	// AttackMinutes 分钟明细（R5 ★核心，CH attack_minutes 点查，docs/dd/04 §3）。
	AttackMinutes(ctx context.Context, id string, fromMs, toMs int64) ([]shared.AttackMinute, error)
}

// AlarmReader —— 告警历史读模型（R7）。
type AlarmReader interface {
	ListAlarms(ctx context.Context, f AlarmFilter) (Page[*shared.Alarm], error)
}

// ZoneTraffic —— 客户域实时流量视图行（R2；采样加权还原后的估算值由前端标注 ※）。
type ZoneTraffic struct {
	ZoneID       int32   `json:"zone_id"`
	ZoneName     string  `json:"zone_name"`
	BpsIn        float64 `json:"bps_in"`
	BpsOut       float64 `json:"bps_out"`
	PpsIn        float64 `json:"pps_in"`
	PpsOut       float64 `json:"pps_out"`
	AttackCount  int     `json:"attack_count"`
	Ongoing      int     `json:"ongoing"`
	SampleRate   uint32  `json:"sample_rate"`
	TsMs         int64   `json:"ts_ms"`
}

// Staleness —— 快照数据年龄（0 表示实时；前端超阈值显示“数据时间戳”，doc10 §6）。
func (z ZoneTraffic) Staleness(now time.Time) time.Duration {
	return now.Sub(time.UnixMilli(z.TsMs))
}

// RealtimeReader —— 客户域实时视图（R2；生产数据源=Redis rt:* 实时键，docs/00 §6）。
type RealtimeReader interface {
	ZoneRealtime(ctx context.Context) ([]ZoneTraffic, error)
}
