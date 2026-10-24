package inserter

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/SchearLoe/lucidnet/shared"
)

// fakeCodec —— 可编程假解码器（按 topic 返回预置负载或错误）。
type fakeCodec struct {
	mu       sync.Mutex
	flows    map[string][]shared.FlowRecord
	aggr     map[string]shared.AggrMinuteBatch
	atkMin   map[string]shared.AttackMinuteBatch
	alarms   map[string]shared.AlarmEnvelope
	flowsErr map[string]error
}

func (f *fakeCodec) DecodeFlowsRaw(b []byte) ([]shared.FlowRecord, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err, ok := f.flowsErr[string(b)]; ok {
		return nil, err
	}
	return f.flows[string(b)], nil
}
func (f *fakeCodec) DecodeAggrMinuteBatch(b []byte) (shared.AggrMinuteBatch, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.aggr[string(b)], nil
}
func (f *fakeCodec) DecodeAttackMinuteBatch(b []byte) (shared.AttackMinuteBatch, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.atkMin[string(b)], nil
}
func (f *fakeCodec) DecodeAlarmEnvelope(b []byte) (shared.AlarmEnvelope, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.alarms[string(b)], nil
}

// flowMsg —— 构造合法 flows.raw 记录（v4 映射）。
func flowMsg(exporter string, startMs int64) shared.FlowRecord {
	return shared.FlowRecord{
		TimeStartMs: startMs, TimeEndMs: startMs + 100,
		Exporter: exporter, InIf: 1, OutIf: 2,
		SrcIP: v4Mapped(1, 1, 1, 1), DstIP: v4Mapped(2, 2, 2, 2),
		SrcPort: 1, DstPort: 80, Proto: 6, IPVersion: 4,
		Packets: 1, Bytes: 100, ZoneID: 101,
	}
}

// newPipeline —— 组装小阈值流水线（maxRows=2 触发即时 flush）。
func newPipeline(t *testing.T, codec Codec, sink Sink, opts ...PipelineOption) (*Pipeline, *ChannelConsumer, *Router) {
	t.Helper()
	router, err := NewRouter(2)
	if err != nil {
		t.Fatalf("new router: %v", err)
	}
	consumer := NewChannelConsumer(64)
	p, err := NewPipeline(consumer, codec, sink, router,
		append([]PipelineOption{WithBatchParams(2, time.Hour)}, opts...)...)
	if err != nil {
		t.Fatalf("new pipeline: %v", err)
	}
	return p, consumer, router
}

// TestPipelineFlowsRaw —— flows.raw → 映射 → 分片路由 → 批量落 Sink。
func TestPipelineFlowsRaw(t *testing.T) {
	codec := &fakeCodec{flows: map[string][]shared.FlowRecord{
		"m1": {flowMsg("10.0.0.1", 1771901100123), flowMsg("10.0.0.1", 1771901102000)},
		"m2": {flowMsg("10.0.0.9", 1771901103000)},
	}}
	sink := NewMemorySink()
	p, consumer, router := newPipeline(t, codec, sink)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- p.Run(ctx) }()

	consumer.Inject(Message{Topic: shared.TopicFlowsRaw, Value: []byte("m1")})
	consumer.Inject(Message{Topic: shared.TopicFlowsRaw, Value: []byte("m2")})
	waitFor(t, func() bool { return sink.Count(TableFlowsRaw, 0)+sink.Count(TableFlowsRaw, 1) == 2 })
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("run: %v", err)
	}
	if got := sink.Count(TableFlowsRaw, 0) + sink.Count(TableFlowsRaw, 1); got != 3 {
		t.Errorf("total rows = %d, want 3 (2 flushed + 1 tail)", got)
	}
	if got := consumer.Committed(); got != 2 {
		t.Errorf("committed = %d, want 2", got)
	}
	// 分片路由一致性：每行实际落库分片 == Router 对 (day, exporter) 的计算结果
	for shard := uint64(0); shard < router.Shards(); shard++ {
		for _, any := range sink.Rows(TableFlowsRaw, shard) {
			row := any.(FlowsRawRow)
			if want := router.ShardFor(DayOfUnixSec(row.TimeSecond.Unix()), row.Exporter); want != shard {
				t.Errorf("row exporter=%s ts=%v landed shard %d, router says %d",
					row.Exporter, row.TimeSecond, shard, want)
			}
		}
	}
	_, rows, _, bad, _ := p.StatsSnapshot()
	if rows != 3 || bad != 0 {
		t.Errorf("stats rows=%d bad=%d", rows, bad)
	}
}

// TestPipelineAllTopics —— 四个契约 topic 全链路 + 未知 topic 跳过。
func TestPipelineAllTopics(t *testing.T) {
	codec := &fakeCodec{
		aggr: map[string]shared.AggrMinuteBatch{
			"a1": {Rows: []shared.AggrRow{{
				Minute: 1771901100, Exporter: "10.0.0.1", Direction: shared.DirIn, ZoneID: 1,
				BytesSum: 10, PacketsSum: 1, FlowsCount: 1,
			}}, BatchID: 9001},
		},
		atkMin: map[string]shared.AttackMinuteBatch{
			"k1": {Rows: []shared.AttackMinute{{AttackID: "01J", MinuteEpoch: 1771901100}}, BatchID: 9002},
		},
		alarms: map[string]shared.AlarmEnvelope{
			"env-atk": {Attack: &shared.AttackEvent{AttackID: "01J", StartMs: 1771901100000, ZoneID: 1}},
			"env-alm": {Alarm: &shared.Alarm{AlarmID: "alm", RaiseMs: 1771901100000, ZoneID: 1}},
		},
	}
	sink := NewMemorySink()
	p, consumer, _ := newPipeline(t, codec, sink)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- p.Run(ctx) }()

	consumer.Inject(Message{Topic: shared.TopicFlowsAggrMinute, Value: []byte("a1")})
	consumer.Inject(Message{Topic: shared.TopicAttacksMinutes, Key: []byte("01J"), Value: []byte("k1")})
	consumer.Inject(Message{Topic: shared.TopicAlarms, Value: []byte("env-atk")})
	consumer.Inject(Message{Topic: shared.TopicAlarms, Value: []byte("env-alm")})
	consumer.Inject(Message{Topic: "syslogs.raw", Value: []byte("x")}) // 未登记 topic：跳过
	waitFor(t, func() bool { return consumer.Committed() == 5 })
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("run: %v", err)
	}
	total := func(table string) int { return sink.Count(table, 0) + sink.Count(table, 1) }
	if total(TableAggrMinute) != 1 || total(TableAttackMinutes) != 1 ||
		total(TableAttacks) != 1 || total(TableAlarmHistory) != 1 {
		t.Errorf("tail flush rows: aggr=%d atkmin=%d atk=%d alm=%d",
			total(TableAggrMinute), total(TableAttackMinutes), total(TableAttacks), total(TableAlarmHistory))
	}
	msgs, rows, deduped, bad, _ := p.StatsSnapshot()
	if msgs != 5 || rows != 4 || deduped != 0 || bad != 1 {
		t.Errorf("stats msgs=%d rows=%d deduped=%d bad=%d", msgs, rows, deduped, bad)
	}
	if got := consumer.Committed(); got != 5 {
		t.Errorf("committed = %d, want 5", got)
	}
}

// TestPipelineDedup —— batch_id 重复批次整批跳过（幂等，09 §2）。
// 批内 2 行同维度 → 同分片达阈值即时 flush；重放批次整批去重。
func TestPipelineDedup(t *testing.T) {
	row := shared.AggrRow{Minute: 1771901100, Exporter: "e", BytesSum: 1}
	codec := &fakeCodec{aggr: map[string]shared.AggrMinuteBatch{
		"dup": {Rows: []shared.AggrRow{row, row}, BatchID: 42},
	}}
	sink := NewMemorySink()
	dedup := NewMemoryDeduper(16)
	p, consumer, _ := newPipeline(t, codec, sink, WithDeduper(dedup))

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- p.Run(ctx) }()

	consumer.Inject(Message{Topic: shared.TopicFlowsAggrMinute, Value: []byte("dup")})
	waitFor(t, func() bool { return sink.Count(TableAggrMinute, 0)+sink.Count(TableAggrMinute, 1) == 2 })
	consumer.Inject(Message{Topic: shared.TopicFlowsAggrMinute, Value: []byte("dup")}) // 重放
	waitFor(t, func() bool {
		_, _, deduped, _, _ := p.StatsSnapshot()
		return deduped == 1
	})

	cancel()
	if err := <-done; err != nil {
		t.Fatalf("run: %v", err)
	}
	if got := sink.Count(TableAggrMinute, 0) + sink.Count(TableAggrMinute, 1); got != 2 {
		t.Errorf("rows written = %d, want 2 (replay deduped)", got)
	}
	if got := consumer.Committed(); got != 2 {
		t.Errorf("committed = %d, want 2", got)
	}
}

// TestPipelineBadMessages —— 解码失败/映射非法：计数跳过，不阻塞整批。
func TestPipelineBadMessages(t *testing.T) {
	codec := &fakeCodec{
		flows: map[string][]shared.FlowRecord{
			"ok":  {flowMsg("10.0.0.1", 1771901100000)},
			"bad": {func() shared.FlowRecord { r := flowMsg("10.0.0.1", 1); r.IPVersion = 9; return r }()},
		},
		flowsErr: map[string]error{"poison": errors.New("lz4 corrupt")},
	}
	sink := NewMemorySink()
	var badErrs []string
	p, consumer, _ := newPipeline(t, codec, sink,
		WithBadMessageHook(func(err error) { badErrs = append(badErrs, err.Error()) }))

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- p.Run(ctx) }()

	consumer.Inject(Message{Topic: shared.TopicFlowsRaw, Value: []byte("poison")})
	consumer.Inject(Message{Topic: shared.TopicFlowsRaw, Value: []byte("bad")})
	consumer.Inject(Message{Topic: shared.TopicFlowsRaw, Value: []byte("ok")})
	waitFor(t, func() bool { return consumer.Committed() == 3 })
	// 单行不足阈值：靠 ctx 取消尾刷
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("run: %v (bad rows must not abort)", err)
	}
	if got := sink.Count(TableFlowsRaw, 0) + sink.Count(TableFlowsRaw, 1); got != 1 {
		t.Errorf("good rows written = %d, want 1", got)
	}
	_, _, _, bad, _ := p.StatsSnapshot()
	if bad != 2 {
		t.Errorf("bad = %d, want 2", bad)
	}
	if len(badErrs) != 2 {
		t.Errorf("hook calls = %d, want 2 (%v)", len(badErrs), badErrs)
	}
	joined := strings.Join(badErrs, "|")
	if !strings.Contains(joined, "ip_version") || !strings.Contains(joined, "lz4 corrupt") {
		t.Errorf("hook payloads wrong: %v", badErrs)
	}
}

// TestPipelineFlushErrorNoCommit —— flush 失败：不提交位点（整批重发语义）。
// 两行同 exporter → 同分片 → 达到阈值 2 触发同步 flush 失败。
func TestPipelineFlushErrorNoCommit(t *testing.T) {
	codec := &fakeCodec{flows: map[string][]shared.FlowRecord{
		"m": {flowMsg("10.0.0.1", 1771901100000), flowMsg("10.0.0.1", 1771901101000)},
	}}
	sink := newFailSink(0, errors.New("ch node down"))
	p, consumer, _ := newPipeline(t, codec, sink)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- p.Run(ctx) }()
	consumer.Inject(Message{Topic: shared.TopicFlowsRaw, Value: []byte("m")})

	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "ch node down") {
			t.Fatalf("run err = %v, want wrapped sink error", err)
		}
	case <-time.After(2 * time.Second):
		cancel()
		t.Fatal("pipeline did not stop on flush error")
	}
	cancel()
	if got := consumer.Committed(); got != 0 {
		t.Errorf("committed = %d, want 0 (no commit on flush failure)", got)
	}
	_, _, _, _, flushErrs := p.StatsSnapshot()
	if flushErrs < 1 {
		t.Errorf("flushErrs = %d, want >=1", flushErrs)
	}
}

// TestPipelineConsumerClosed —— 消费通道关闭：尾刷后干净退出。
func TestPipelineConsumerClosed(t *testing.T) {
	codec := &fakeCodec{flows: map[string][]shared.FlowRecord{
		"m": {flowMsg("10.0.0.1", 1771901100000)}, // 1 行 < 阈值：靠尾刷
	}}
	sink := NewMemorySink()
	p, consumer, _ := newPipeline(t, codec, sink)

	done := make(chan error, 1)
	go func() { done <- p.Run(context.Background()) }()
	consumer.Inject(Message{Topic: shared.TopicFlowsRaw, Value: []byte("m")})
	time.Sleep(50 * time.Millisecond)
	_ = consumer.Close()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("run err = %v, want nil on consumer close", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("pipeline did not stop on consumer close")
	}
	if got := sink.Count(TableFlowsRaw, 0) + sink.Count(TableFlowsRaw, 1); got != 1 {
		t.Errorf("tail flush rows = %d, want 1", got)
	}
}

// TestNewPipelineValidation —— 组装参数校验。
func TestNewPipelineValidation(t *testing.T) {
	codec := &fakeCodec{}
	sink := NewMemorySink()
	router, _ := NewRouter(2)
	consumer := NewChannelConsumer(1)
	if _, err := NewPipeline(nil, codec, sink, router); err == nil {
		t.Error("nil consumer must fail")
	}
	if _, err := NewPipeline(consumer, nil, sink, router); err == nil {
		t.Error("nil codec must fail")
	}
	if _, err := NewPipeline(consumer, codec, nil, router); err == nil {
		t.Error("nil sink must fail")
	}
	if _, err := NewPipeline(consumer, codec, sink, nil); err == nil {
		t.Error("nil router must fail")
	}
	if _, err := NewPipeline(consumer, codec, sink, router, WithBatchParams(0, time.Second)); err == nil {
		t.Error("bad batch params must fail")
	}
}

// waitFor —— 轮询断言辅助（50ms 间隔，2s 超时）。
func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("condition not met within 2s")
}
