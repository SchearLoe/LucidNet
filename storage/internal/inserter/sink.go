package inserter

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// CH 数据面表名（docs/11 §7：单数 + 语义后缀；DDL 见 internal/ddl/migrations/ch/）。
const (
	TableFlowsRaw      = "flows_raw"
	TableAggrMinute    = "aggr_minute"
	TableAggrHour      = "aggr_hour" // 由 mv_aggr_hour_aggr_minute 上卷，Inserter 不直写
	TableAttackMinutes = "attack_minutes"
	TableAttacks       = "attacks"
	TableAlarmHistory  = "alarm_history" // 契约缺口：docs/00 §4 / docs/09 §8 未定义该表 DDL，见模块 README
)

// FlowsRawRow —— flows_raw 表行（列序 docs/00 §4 DDL）。
//
// 16B IP → CH IPv6 语义：ClickHouse IPv6 列按 16B 网络序原样存储；IPv4 记录
// 以 ::ffff:a.b.c.d 映射形式写入（docs/00 §1），v4-mapped 在 CH 中不膨胀、
// 无需转换函数。映射与校验见 MapFlowRecord。
type FlowsRawRow struct {
	TimeSecond time.Time // 流开始时间秒级截断（DateTime）
	TimeMs     uint16    // 毫秒余数 0-999
	Exporter   string
	DeviceID   uint32
	InIf       uint32
	OutIf      uint32
	SrcIP      [16]byte
	DstIP      [16]byte
	SrcPort    uint16
	DstPort    uint16
	Proto      uint8
	IPVersion  uint8
	Packets    uint64
	Bytes      uint64
	TCPFlags   uint8 // DDL UInt8；proto 位掩码 uint32 >0xFF 截断（契约缺口见模块 README）
	TOS        uint8
	SampleRate uint32
	SrcAS      uint32
	DstAS      uint32
	AppID      uint32
	ZoneID     int32
	IfRole     uint8
}

// AggrMinuteRow —— aggr_minute 表行（docs/00 §4）。
// Bytes/Packets/Flows 为该 (minute, 维度组) 的聚合原值；写入端包
// sumState()/countState() 生成 AggregateFunction 中间态（docs/09 §2：
// AggrRow = aggr_minute 表列 + -State 聚合中间态）。
type AggrMinuteRow struct {
	Minute    time.Time // epoch 秒，分钟对齐（DateTime）
	Exporter  string
	DeviceID  uint32
	InIf      uint32
	OutIf     uint32
	Direction uint8 // 客户视角方向（shared.Direction，docs/09 §3）
	ZoneID    int32
	SrcAS     uint32
	DstAS     uint32
	Proto     uint8
	DstPort   uint16
	AppID     uint32
	Bytes     uint64
	Packets   uint64
	Flows     uint64
}

// AttackMinuteRow —— attack_minutes 表行（docs/00 §2.3/§4）。
type AttackMinuteRow struct {
	AttackID   string
	Minute     time.Time // minute_epoch 秒（DateTime）
	BpsIn      int64
	PpsIn      int64
	BpsOut     int64
	PpsOut     int64
	NewFlows   uint64
	SynRatio   float32
	UdpRatio   float32
	TopSources []string
	TopPorts   []uint32
}

// AttackEventRow —— attacks 表行（AlarmEnvelope.Attack 子集，docs/09 §8）。
type AttackEventRow struct {
	AttackID     string
	ZoneID       int32
	ZoneName     string
	AttackType   uint32
	TargetPrefix string
	StartMs      int64
	EndMs        int64
	PeakBps      int64
	PeakPps      int64
	Confidence   float32
	TopSources   []string
	EvidenceJSON string
	Status       uint32
	MitigationID string
}

// AlarmHistoryRow —— 告警历史行（Alarm 子集）。
// 契约缺口：docs/dd/04 §1.3 要求 alarms → “attacks 与告警历史”，但
// docs/00 §4 / docs/09 §8 均无告警历史表 DDL，本结构仅为落库面占位，
// 见模块 README 契约问题清单。
type AlarmHistoryRow struct {
	AlarmID    string
	Source     string
	Severity   uint32
	Category   uint32
	RaiseMs    int64
	ClearMs    int64
	Subject    string
	DetailJSON string
	ZoneID     int32
	AttackID   string
}

// Sink —— 批量写接口（CH 写入唯一通道的落库面，docs/09 §8：写入方唯一 = Inserter）。
// shard 为 Router 的路由结果，写各分片本地表（native batch，不用 HTTP INSERT，
// docs/dd/04 §1.3）；同一表内各分片调用相互独立。
type Sink interface {
	WriteFlowsRaw(ctx context.Context, shard uint64, rows []FlowsRawRow) error
	WriteAggrMinute(ctx context.Context, shard uint64, rows []AggrMinuteRow) error
	WriteAttackMinutes(ctx context.Context, shard uint64, rows []AttackMinuteRow) error
	WriteAttacks(ctx context.Context, shard uint64, rows []AttackEventRow) error
	WriteAlarmHistory(ctx context.Context, shard uint64, rows []AlarmHistoryRow) error
}

// CHSink —— clickhouse-go 批量写实现桩（walking skeleton）。
// 真实实现应使用 clickhouse-go/v2 的 native batch 直写各分片本地表，
// 列序与 internal/ddl/migrations/ch/0001_flows_raw.sql 一致，并接入
// insert_quorum=1 吞吐优先参数（docs/dd/04 §1.2）。当前仅计数并回调日志，
// 供空跑与拓扑验证。
type CHSink struct {
	dsn  string
	logf func(string, ...any)
}

// NewCHSink 构造 CH 写入桩；logf 为 nil 时静默。
func NewCHSink(dsn string, logf func(string, ...any)) *CHSink {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	return &CHSink{dsn: dsn, logf: logf}
}

// DSN 返回配置的 ClickHouse 连接串（诊断用）。
func (s *CHSink) DSN() string { return s.dsn }

// WriteFlowsRaw 批量写 flows_raw（桩：仅日志计数）。
func (s *CHSink) WriteFlowsRaw(_ context.Context, shard uint64, rows []FlowsRawRow) error {
	s.logf("chsink stub: write %s shard=%d rows=%d", TableFlowsRaw, shard, len(rows))
	return nil
}

// WriteAggrMinute 批量写 aggr_minute（桩）。
func (s *CHSink) WriteAggrMinute(_ context.Context, shard uint64, rows []AggrMinuteRow) error {
	s.logf("chsink stub: write %s shard=%d rows=%d", TableAggrMinute, shard, len(rows))
	return nil
}

// WriteAttackMinutes 批量写 attack_minutes（桩）。
func (s *CHSink) WriteAttackMinutes(_ context.Context, shard uint64, rows []AttackMinuteRow) error {
	s.logf("chsink stub: write %s shard=%d rows=%d", TableAttackMinutes, shard, len(rows))
	return nil
}

// WriteAttacks 批量写 attacks（桩）。
func (s *CHSink) WriteAttacks(_ context.Context, shard uint64, rows []AttackEventRow) error {
	s.logf("chsink stub: write %s shard=%d rows=%d", TableAttacks, shard, len(rows))
	return nil
}

// WriteAlarmHistory 批量写告警历史（桩；目标表 DDL 缺口见模块 README）。
func (s *CHSink) WriteAlarmHistory(_ context.Context, shard uint64, rows []AlarmHistoryRow) error {
	s.logf("chsink stub: write %s shard=%d rows=%d", TableAlarmHistory, shard, len(rows))
	return nil
}

// MemorySink —— 内存假 Sink（单测/联调）：按 表#分片 记录全部行。
type MemorySink struct {
	mu      sync.Mutex
	batches map[string]int
	rows    map[string][]any
}

// NewMemorySink 构造内存 Sink。
func NewMemorySink() *MemorySink {
	return &MemorySink{
		batches: make(map[string]int),
		rows:    make(map[string][]any),
	}
}

func sinkKey(table string, shard uint64) string { return fmt.Sprintf("%s#%d", table, shard) }

func storeRows[T any](m *MemorySink, table string, shard uint64, rows []T) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := sinkKey(table, shard)
	m.batches[key]++
	for i := range rows {
		m.rows[key] = append(m.rows[key], rows[i])
	}
}

// WriteFlowsRaw 记录 flows_raw 批次。
func (m *MemorySink) WriteFlowsRaw(_ context.Context, shard uint64, rows []FlowsRawRow) error {
	storeRows(m, TableFlowsRaw, shard, rows)
	return nil
}

// WriteAggrMinute 记录 aggr_minute 批次。
func (m *MemorySink) WriteAggrMinute(_ context.Context, shard uint64, rows []AggrMinuteRow) error {
	storeRows(m, TableAggrMinute, shard, rows)
	return nil
}

// WriteAttackMinutes 记录 attack_minutes 批次。
func (m *MemorySink) WriteAttackMinutes(_ context.Context, shard uint64, rows []AttackMinuteRow) error {
	storeRows(m, TableAttackMinutes, shard, rows)
	return nil
}

// WriteAttacks 记录 attacks 批次。
func (m *MemorySink) WriteAttacks(_ context.Context, shard uint64, rows []AttackEventRow) error {
	storeRows(m, TableAttacks, shard, rows)
	return nil
}

// WriteAlarmHistory 记录告警历史批次。
func (m *MemorySink) WriteAlarmHistory(_ context.Context, shard uint64, rows []AlarmHistoryRow) error {
	storeRows(m, TableAlarmHistory, shard, rows)
	return nil
}

// Count 返回指定 表#分片 累计行数。
func (m *MemorySink) Count(table string, shard uint64) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.rows[sinkKey(table, shard)])
}

// BatchCount 返回指定 表#分片 累计批次次数。
func (m *MemorySink) BatchCount(table string, shard uint64) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.batches[sinkKey(table, shard)]
}

// Rows 返回指定 表#分片 的行快照（元素为对应 Row 结构体值）。
func (m *MemorySink) Rows(table string, shard uint64) []any {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]any, len(m.rows[sinkKey(table, shard)]))
	copy(out, m.rows[sinkKey(table, shard)])
	return out
}
