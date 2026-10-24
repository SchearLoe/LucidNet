package inserter

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/SchearLoe/lucidnet/shared"
)

// Pipeline —— 消费流水组装：Consumer → Codec →（Dedup）→ Map → Router →
// Batcher → Sink（docs/09 §2、docs/dd/04 §1.3）。
//
// 语义：
//   - 解码失败/映射校验失败：计数 + 跳过（毒丸不入库、不阻塞整批）；
//   - flush 失败：handle 返回错误 → 整批不提交位点，重发兜底（幂等由
//     batch_id + export_batches 去重，docs/09 §2）；
//   - batch_id 去重仅在入批前检查（flush 前崩溃窗口内的重放去重为 TODO，
//     见模块 README dd/04 §1.3 条目）。
type Pipeline struct {
	consumer Consumer
	codec    Codec
	sink     Sink
	dedup    Deduper // 可 nil（跳过 batch_id 去重）
	router   *Router
	clock    Clock
	maxRows  int
	interval time.Duration
	onBad    func(err error) // 毒丸消息钩子（日志/告警），可 nil

	shards   uint64
	flows    []*Batcher[FlowsRawRow]
	aggr     []*Batcher[AggrMinuteRow]
	atkMin   []*Batcher[AttackMinuteRow]
	attackEv []*Batcher[AttackEventRow]
	alarmHis []*Batcher[AlarmHistoryRow]
	wg       sync.WaitGroup

	stats Stats
}

// Stats —— 消费流水计数（Prometheus 接入见模块 README TODO，命名遵循 docs/11 §9）。
type Stats struct {
	messages   atomic.Int64
	rowsMapped atomic.Int64
	deduped    atomic.Int64
	badRows    atomic.Int64
	flushErrs  atomic.Int64
}

// StatsSnapshot 返回计数快照：messages / rowsMapped / deduped / badRows / flushErrs。
func (p *Pipeline) StatsSnapshot() (messages, rowsMapped, deduped, badRows, flushErrs int64) {
	return p.stats.messages.Load(),
		p.stats.rowsMapped.Load(),
		p.stats.deduped.Load(),
		p.stats.badRows.Load(),
		p.stats.flushErrs.Load()
}

// PipelineOption —— Pipeline 配置项（docs/11 §3：配置用 Option 模式）。
type PipelineOption func(*Pipeline)

// WithDeduper 注入批次幂等去重器（nil 表示不启用）。
func WithDeduper(d Deduper) PipelineOption { return func(p *Pipeline) { p.dedup = d } }

// WithClock 注入时钟（单测）。
func WithClock(c Clock) PipelineOption { return func(p *Pipeline) { p.clock = c } }

// WithBatchParams 覆盖批量参数（默认 50,000 行 / 2s，docs/dd/04 §1.3）。
func WithBatchParams(maxRows int, interval time.Duration) PipelineOption {
	return func(p *Pipeline) { p.maxRows, p.interval = maxRows, interval }
}

// WithBadMessageHook 注册毒丸消息钩子（解码失败/映射校验失败时回调）。
func WithBadMessageHook(fn func(err error)) PipelineOption {
	return func(p *Pipeline) { p.onBad = fn }
}

// NewPipeline 组装流水线；按分片数预建各表批量器（分片数小，懒创建为 TODO）。
func NewPipeline(consumer Consumer, codec Codec, sink Sink, router *Router, opts ...PipelineOption) (*Pipeline, error) {
	switch {
	case consumer == nil:
		return nil, fmt.Errorf("new pipeline: nil consumer")
	case codec == nil:
		return nil, fmt.Errorf("new pipeline: nil codec")
	case sink == nil:
		return nil, fmt.Errorf("new pipeline: nil sink")
	case router == nil:
		return nil, fmt.Errorf("new pipeline: nil router")
	}
	p := &Pipeline{
		consumer: consumer,
		codec:    codec,
		sink:     sink,
		router:   router,
		clock:    SystemClock{},
		maxRows:  DefaultBatchMaxRows,
		interval: DefaultFlushInterval,
	}
	for _, o := range opts {
		o(p)
	}
	if p.maxRows <= 0 {
		return nil, fmt.Errorf("new pipeline: batch max rows %d must be positive", p.maxRows)
	}
	if p.interval <= 0 {
		return nil, fmt.Errorf("new pipeline: flush interval %s must be positive", p.interval)
	}
	n := int(router.Shards())
	p.shards = router.Shards()
	p.flows = newBatchers(n, p.maxRows, p.interval, p.clock,
		func(ctx context.Context, shard int, rows []FlowsRawRow) error {
			return p.sink.WriteFlowsRaw(ctx, uint64(shard), rows)
		}, &p.stats.flushErrs)
	p.aggr = newBatchers(n, p.maxRows, p.interval, p.clock,
		func(ctx context.Context, shard int, rows []AggrMinuteRow) error {
			return p.sink.WriteAggrMinute(ctx, uint64(shard), rows)
		}, &p.stats.flushErrs)
	p.atkMin = newBatchers(n, p.maxRows, p.interval, p.clock,
		func(ctx context.Context, shard int, rows []AttackMinuteRow) error {
			return p.sink.WriteAttackMinutes(ctx, uint64(shard), rows)
		}, &p.stats.flushErrs)
	p.attackEv = newBatchers(n, p.maxRows, p.interval, p.clock,
		func(ctx context.Context, shard int, rows []AttackEventRow) error {
			return p.sink.WriteAttacks(ctx, uint64(shard), rows)
		}, &p.stats.flushErrs)
	p.alarmHis = newBatchers(n, p.maxRows, p.interval, p.clock,
		func(ctx context.Context, shard int, rows []AlarmHistoryRow) error {
			return p.sink.WriteAlarmHistory(ctx, uint64(shard), rows)
		}, &p.stats.flushErrs)
	return p, nil
}

// newBatchers 为每分片构造一个批量器（泛型辅助）。
func newBatchers[T any](n, maxRows int, interval time.Duration, clock Clock,
	sinkFn func(ctx context.Context, shard int, rows []T) error, flushErrs *atomic.Int64,
) []*Batcher[T] {
	out := make([]*Batcher[T], n)
	for i := range n {
		shard := i
		b, err := NewBatcher[T](maxRows, interval, clock,
			func(ctx context.Context, rows []T) error { return sinkFn(ctx, shard, rows) },
			func(error) { flushErrs.Add(1) })
		if err != nil {
			panic(fmt.Sprintf("inserter: build batcher for shard %d: %v", shard, err)) // 参数已在上游校验，不可达
		}
		out[i] = b
	}
	return out
}

// Run 消费主循环：Fetch → 逐条处理 → Commit；退出时（ctx 取消或消费通道关闭）
// 先停各分片批量器 goroutine、再尾刷积压，最后等待全部退出。
func (p *Pipeline) Run(ctx context.Context) error {
	runCtx, cancel := context.WithCancel(ctx)
	defer func() {
		cancel()                         // 停批量器 Run goroutine（含各自尾刷）
		p.flushAll(context.Background()) // 兜底尾刷（幂等，空积压 no-op）
		p.wg.Wait()
	}()
	for i := range p.flows {
		p.wg.Add(1)
		go func() { defer p.wg.Done(); p.flows[i].Run(runCtx) }()
	}
	for i := range p.aggr {
		p.wg.Add(1)
		go func() { defer p.wg.Done(); p.aggr[i].Run(runCtx) }()
	}
	for i := range p.atkMin {
		p.wg.Add(1)
		go func() { defer p.wg.Done(); p.atkMin[i].Run(runCtx) }()
	}
	for i := range p.attackEv {
		p.wg.Add(1)
		go func() { defer p.wg.Done(); p.attackEv[i].Run(runCtx) }()
	}
	for i := range p.alarmHis {
		p.wg.Add(1)
		go func() { defer p.wg.Done(); p.alarmHis[i].Run(runCtx) }()
	}
	for {
		msgs, err := p.consumer.Fetch(ctx)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, ErrConsumerClosed) {
				return nil
			}
			return fmt.Errorf("inserter fetch: %w", err)
		}
		for i := range msgs {
			if err := p.handle(ctx, &msgs[i]); err != nil {
				// 不提交本批位点：整批重发（docs/dd/04 §1.3 幂等重放）
				return fmt.Errorf("inserter handle message: %w", err)
			}
		}
		if err := p.consumer.Commit(ctx, msgs); err != nil {
			return fmt.Errorf("inserter commit: %w", err)
		}
	}
}

// flushAll 尾刷全部分片批量器（关停路径；错误经 onErr 计数）。
func (p *Pipeline) flushAll(ctx context.Context) {
	for _, b := range p.flows {
		_ = b.Flush(ctx)
	}
	for _, b := range p.aggr {
		_ = b.Flush(ctx)
	}
	for _, b := range p.atkMin {
		_ = b.Flush(ctx)
	}
	for _, b := range p.attackEv {
		_ = b.Flush(ctx)
	}
	for _, b := range p.alarmHis {
		_ = b.Flush(ctx)
	}
}

func (p *Pipeline) badRow(err error) {
	p.stats.badRows.Add(1)
	if p.onBad != nil {
		p.onBad(err)
	}
}

// handle 处理单条消息（按 topic 分发，docs/00 §3 topic 表）。
func (p *Pipeline) handle(ctx context.Context, m *Message) error {
	p.stats.messages.Add(1)
	switch m.Topic {
	case shared.TopicFlowsRaw:
		return p.handleFlowsRaw(ctx, m)
	case shared.TopicFlowsAggrMinute:
		return p.handleAggrMinute(ctx, m)
	case shared.TopicAttacksMinutes:
		return p.handleAttackMinutes(ctx, m)
	case shared.TopicAlarms:
		return p.handleAlarms(ctx, m)
	default:
		// 消费组只订阅契约登记 topic（docs/09 §2）；未登记 topic 跳过计数
		p.badRow(fmt.Errorf("unregistered topic %q for inserter consumer", m.Topic))
		return nil
	}
}

func (p *Pipeline) handleFlowsRaw(_ context.Context, m *Message) error {
	recs, err := p.codec.DecodeFlowsRaw(m.Value)
	if err != nil {
		p.badRow(fmt.Errorf("decode flows.raw: %w", err))
		return nil
	}
	for _, rec := range recs {
		row, err := MapFlowRecord(rec)
		if err != nil {
			p.badRow(err)
			continue
		}
		day := DayOfUnixSec(rec.TimeStartMs / 1000)
		shard := p.router.ShardFor(day, rec.Exporter)
		if err := p.flows[int(shard)].Add(row); err != nil {
			return fmt.Errorf("enqueue flows_raw shard %d: %w", shard, err)
		}
		p.stats.rowsMapped.Add(1)
	}
	return nil
}

func (p *Pipeline) handleAggrMinute(ctx context.Context, m *Message) error {
	batch, err := p.codec.DecodeAggrMinuteBatch(m.Value)
	if err != nil {
		p.badRow(fmt.Errorf("decode flows.aggr.minute: %w", err))
		return nil
	}
	skip, err := p.dedupCheck(ctx, batch.BatchID)
	if err != nil {
		return err
	}
	if skip {
		return nil
	}
	for _, r := range batch.Rows {
		row, err := MapAggrMinuteRow(r)
		if err != nil {
			p.badRow(err)
			continue
		}
		day := DayOfUnixSec(r.Minute)
		shard := p.router.ShardFor(day, r.Exporter)
		if err := p.aggr[int(shard)].Add(row); err != nil {
			return fmt.Errorf("enqueue aggr_minute shard %d: %w", shard, err)
		}
		p.stats.rowsMapped.Add(1)
	}
	return p.dedupMark(ctx, batch.BatchID)
}

func (p *Pipeline) handleAttackMinutes(ctx context.Context, m *Message) error {
	batch, err := p.codec.DecodeAttackMinuteBatch(m.Value)
	if err != nil {
		p.badRow(fmt.Errorf("decode attacks.minutes: %w", err))
		return nil
	}
	skip, err := p.dedupCheck(ctx, batch.BatchID)
	if err != nil {
		return err
	}
	if skip {
		return nil
	}
	for _, r := range batch.Rows {
		row, err := MapAttackMinuteRow(r)
		if err != nil {
			p.badRow(err)
			continue
		}
		day := DayOfUnixSec(r.MinuteEpoch)
		// attacks.minutes 消息无 exporter（key=attack_id），以 attack_id 作路由键
		// （契约缺口见模块 README）
		shard := p.router.ShardFor(day, r.AttackID)
		if err := p.atkMin[int(shard)].Add(row); err != nil {
			return fmt.Errorf("enqueue attack_minutes shard %d: %w", shard, err)
		}
		p.stats.rowsMapped.Add(1)
	}
	return p.dedupMark(ctx, batch.BatchID)
}

func (p *Pipeline) handleAlarms(ctx context.Context, m *Message) error {
	env, err := p.codec.DecodeAlarmEnvelope(m.Value)
	if err != nil {
		p.badRow(fmt.Errorf("decode alarms: %w", err))
		return nil
	}
	attacks, alarms, err := MapAlarmEnvelope(env)
	if err != nil {
		p.badRow(err)
		return nil
	}
	for _, r := range attacks {
		day := DayOfUnixSec(r.StartMs / 1000)
		shard := p.router.ShardFor(day, "attack:"+r.AttackID)
		if err := p.attackEv[int(shard)].Add(r); err != nil {
			return fmt.Errorf("enqueue attacks shard %d: %w", shard, err)
		}
		p.stats.rowsMapped.Add(1)
	}
	for _, r := range alarms {
		day := DayOfUnixSec(r.RaiseMs / 1000)
		shard := p.router.ShardFor(day, fmt.Sprintf("alarm:%d", r.ZoneID))
		if err := p.alarmHis[int(shard)].Add(r); err != nil {
			return fmt.Errorf("enqueue alarm_history shard %d: %w", shard, err)
		}
		p.stats.rowsMapped.Add(1)
	}
	return nil
}

func (p *Pipeline) dedupCheck(ctx context.Context, batchID uint64) (bool, error) {
	if p.dedup == nil || batchID == 0 {
		return false, nil
	}
	seen, err := p.dedup.Seen(ctx, batchID)
	if err != nil {
		return false, fmt.Errorf("dedup check batch %d: %w", batchID, err)
	}
	if seen {
		p.stats.deduped.Add(1)
		return true, nil
	}
	return false, nil
}

func (p *Pipeline) dedupMark(ctx context.Context, batchID uint64) error {
	if p.dedup == nil || batchID == 0 {
		return nil
	}
	// 简化语义：入批即标记（flush 前崩溃窗口内的重放去重 TODO，dd/04 §1.3）
	if err := p.dedup.MarkDone(ctx, batchID); err != nil {
		return fmt.Errorf("mark batch %d done: %w", batchID, err)
	}
	return nil
}
