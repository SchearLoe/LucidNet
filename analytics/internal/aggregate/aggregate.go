// Package aggregate —— 分钟多维聚合器（dd/03 §2）：
// 维度键 xxhash64 哈希 → map 累加 → 分钟翻转（:00+90s grace 收迟到记录、过期丢弃）
// → 批量发布 flows.aggr.minute（key=exporter，由 Storage Inserter 落 CH，09 §2）。
//
// 聚合入口统一执行 shared.InternalFilterDrop 互联过滤（dd/03 §2.2 / 09 §9-④）；
// 方向仅由 zone_side 推导（09 §3，禁用 ifIndex 二次推断）。
// 并行单元 = Kafka 分区，单 goroutine 无锁（dd/03 §1），故本类型非并发安全。
package aggregate

import (
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/cespare/xxhash/v2"

	"github.com/SchearLoe/lucidnet/shared"
)

const (
	minuteLen    = time.Minute
	defaultGrace = 90 * time.Second // dd/03 §2.1：:00+90s grace
)

// Publisher —— flows.aggr.minute 发布接口（09 §2；生产实现为 Kafka，测试用内存记录器）。
type Publisher interface {
	PublishMinuteBatch(batch *shared.AggrMinuteBatch) error
}

// Aggregator —— 分钟聚合器（每分区一份，dd/03 §1）。
type Aggregator struct {
	grace           time.Duration
	internalExclude bool // dd/03 §2.2：默认 true；false 为全局视图旁路（成本 ×1.3，仅全局维度）
	now             func() time.Time
	pub             Publisher

	minutes map[int64]map[uint64]*cell // 分钟(epoch 秒) → 维度键 xxhash64 → 累加格
	batchID uint64

	records          uint64
	droppedInternal  uint64
	droppedExpired   uint64
	publishedBatches uint64
	publishedRows    uint64
}

// Option —— 构造选项（docs/11 §3 配置 Option 模式）。
type Option func(*Aggregator)

// WithClock 注入时间源（确定性单测）。
func WithClock(now func() time.Time) Option {
	return func(a *Aggregator) { a.now = now }
}

// WithGrace 覆盖迟到宽限期（默认 90s，dd/03 §2.1）。
func WithGrace(d time.Duration) Option {
	return func(a *Aggregator) {
		if d > 0 {
			a.grace = d
		}
	}
}

// WithInternalExclude 覆盖互联过滤开关（默认 true，dd/03 §2.2 / etcd
// /lucid/config/analytics 的 internal_exclude；false 走全局视图旁路）。
func WithInternalExclude(enabled bool) Option {
	return func(a *Aggregator) { a.internalExclude = enabled }
}

// NewAggregator 构造聚合器；pub 为 flows.aggr.minute 下游。
func NewAggregator(pub Publisher, opts ...Option) (*Aggregator, error) {
	if pub == nil {
		return nil, errors.New("aggregate: publisher required")
	}
	a := &Aggregator{
		grace:           defaultGrace,
		internalExclude: true,
		now:             time.Now,
		pub:             pub,
		minutes:         make(map[int64]map[uint64]*cell),
	}
	for _, opt := range opts {
		opt(a)
	}
	return a, nil
}

// dimKey —— aggr_minute 聚合维度（00 §4 DDL 列 + 客户视角方向）。
type dimKey struct {
	Exporter  string
	DeviceID  uint32
	InIf      uint32
	OutIf     uint32
	Direction shared.Direction
	ZoneID    int32
	SrcAS     uint32
	DstAS     uint32
	Proto     uint32
	DstPort   uint32
	AppID     uint32
}

func dimKeyOf(rec *shared.FlowRecord) dimKey {
	return dimKey{
		Exporter:  rec.Exporter,
		DeviceID:  rec.DeviceID,
		InIf:      rec.InIf,
		OutIf:     rec.OutIf,
		Direction: shared.DirectionFromZoneSide(shared.ZoneSide(rec.ZoneSide)),
		ZoneID:    rec.ZoneID,
		SrcAS:     rec.SrcAS,
		DstAS:     rec.DstAS,
		Proto:     rec.Proto,
		DstPort:   rec.DstPort,
		AppID:     rec.AppID,
	}
}

// hash —— 分组键 xxhash64（dd/03 §2.1）。
func (k dimKey) hash() uint64 {
	var buf [40]byte
	binary.BigEndian.PutUint32(buf[0:4], k.DeviceID)
	binary.BigEndian.PutUint32(buf[4:8], k.InIf)
	binary.BigEndian.PutUint32(buf[8:12], k.OutIf)
	binary.BigEndian.PutUint32(buf[12:16], uint32(k.Direction))
	binary.BigEndian.PutUint32(buf[16:20], uint32(k.ZoneID))
	binary.BigEndian.PutUint32(buf[20:24], k.SrcAS)
	binary.BigEndian.PutUint32(buf[24:28], k.DstAS)
	binary.BigEndian.PutUint32(buf[28:32], k.Proto)
	binary.BigEndian.PutUint32(buf[32:36], k.DstPort)
	binary.BigEndian.PutUint32(buf[36:40], k.AppID)
	return xxhash.Sum64(append(buf[:], k.Exporter...))
}

// cell —— 同维度同分钟的累加格。
type cell struct {
	key        dimKey
	bytesSum   uint64
	packetsSum uint64
	flows      uint64
}

func (c *cell) row(minute int64) shared.AggrRow {
	return shared.AggrRow{
		Minute:     minute,
		Exporter:   c.key.Exporter,
		DeviceID:   c.key.DeviceID,
		InIf:       c.key.InIf,
		OutIf:      c.key.OutIf,
		Direction:  c.key.Direction,
		ZoneID:     c.key.ZoneID,
		SrcAS:      c.key.SrcAS,
		DstAS:      c.key.DstAS,
		Proto:      c.key.Proto,
		DstPort:    c.key.DstPort,
		AppID:      c.key.AppID,
		BytesSum:   c.bytesSum,
		PacketsSum: c.packetsSum,
		FlowsCount: c.flows,
	}
}

// Add 处理一条 FlowRecord：互联过滤 → 迟到判定 → 维度累加。
// sample_rate 不在此加权（展示侧还原，09 §3）。
func (a *Aggregator) Add(rec *shared.FlowRecord) error {
	if rec == nil {
		return errors.New("aggregate: nil flow record")
	}
	now := a.now()
	if err := a.flip(now); err != nil {
		return err
	}
	// 互联过滤（dd/03 §2.2）：仅 in 与 out 均为 internal 才丢弃；
	// internal_exclude=false 为全局视图旁路，不过滤。
	if a.internalExclude && shared.InternalFilterDrop(rec.IfRole) {
		a.droppedInternal++
		return nil
	}
	minute := floorMinute(rec.TimeStartMs)
	closeAt := time.Unix(minute, 0).Add(minuteLen + a.grace)
	if !now.Before(closeAt) {
		a.droppedExpired++ // 迟到超 grace，过期丢弃
		return nil
	}
	m := a.minutes[minute]
	if m == nil {
		m = make(map[uint64]*cell)
		a.minutes[minute] = m
	}
	k := dimKeyOf(rec)
	h := k.hash()
	c := m[h]
	if c == nil {
		c = &cell{key: k}
		m[h] = c
	}
	c.bytesSum += rec.Bytes
	c.packetsSum += rec.Packets
	c.flows++
	a.records++
	return nil
}

// flip 发布所有已过 grace 期的分钟并清格。
func (a *Aggregator) flip(now time.Time) error {
	for minute, cells := range a.minutes {
		closeAt := time.Unix(minute, 0).Add(minuteLen + a.grace)
		if now.Before(closeAt) {
			continue
		}
		if err := a.publish(minute, cells); err != nil {
			return err
		}
		delete(a.minutes, minute)
	}
	return nil
}

// Flush 立即发布全部未到期分钟（关停/测试用），返回发布的行数。
func (a *Aggregator) Flush() (int, error) {
	before := a.publishedRows
	for minute, cells := range a.minutes {
		if err := a.publish(minute, cells); err != nil {
			return int(a.publishedRows - before), err
		}
		delete(a.minutes, minute)
	}
	return int(a.publishedRows - before), nil
}

func (a *Aggregator) publish(minute int64, cells map[uint64]*cell) error {
	rows := make([]shared.AggrRow, 0, len(cells))
	for _, c := range cells {
		rows = append(rows, c.row(minute))
	}
	sortRows(rows) // map 遍历无序，排序保证批次输出稳定
	a.batchID++
	batch := &shared.AggrMinuteBatch{Rows: rows, BatchID: a.batchID}
	if err := a.pub.PublishMinuteBatch(batch); err != nil {
		return fmt.Errorf("publish aggr batch for minute %d: %w", minute, err)
	}
	a.publishedBatches++
	a.publishedRows += uint64(len(rows))
	return nil
}

// Stats —— 聚合器运行统计（Prometheus 指标对接 M2）。
type Stats struct {
	Records          uint64
	DroppedInternal  uint64
	DroppedExpired   uint64
	PublishedBatches uint64
	PublishedRows    uint64
}

func (a *Aggregator) Stats() Stats {
	return Stats{
		Records:          a.records,
		DroppedInternal:  a.droppedInternal,
		DroppedExpired:   a.droppedExpired,
		PublishedBatches: a.publishedBatches,
		PublishedRows:    a.publishedRows,
	}
}

// floorMinute —— TimeStartMs → 分钟对齐 epoch 秒。
func floorMinute(timeStartMs int64) int64 {
	return timeStartMs / 1000 / 60 * 60
}

// sortRows —— 按全维度排序，保证批次行序稳定（可复现测试/幂等对账）。
func sortRows(rows []shared.AggrRow) {
	sort.Slice(rows, func(i, j int) bool {
		a, b := rows[i], rows[j]
		if a.Minute != b.Minute {
			return a.Minute < b.Minute
		}
		if a.Exporter != b.Exporter {
			return a.Exporter < b.Exporter
		}
		if a.DeviceID != b.DeviceID {
			return a.DeviceID < b.DeviceID
		}
		if a.InIf != b.InIf {
			return a.InIf < b.InIf
		}
		if a.OutIf != b.OutIf {
			return a.OutIf < b.OutIf
		}
		if a.Direction != b.Direction {
			return a.Direction < b.Direction
		}
		if a.ZoneID != b.ZoneID {
			return a.ZoneID < b.ZoneID
		}
		if a.SrcAS != b.SrcAS {
			return a.SrcAS < b.SrcAS
		}
		if a.DstAS != b.DstAS {
			return a.DstAS < b.DstAS
		}
		if a.Proto != b.Proto {
			return a.Proto < b.Proto
		}
		if a.DstPort != b.DstPort {
			return a.DstPort < b.DstPort
		}
		return a.AppID < b.AppID
	})
}
