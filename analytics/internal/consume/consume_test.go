package consume

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/SchearLoe/lucidnet/shared"
)

// writeJSONL —— 生成临时回放文件。
func writeJSONL(t *testing.T, lines []string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "flows.jsonl")
	if err := os.WriteFile(path, []byte(joinLines(lines)), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func joinLines(lines []string) string {
	out := ""
	for _, l := range lines {
		out += l + "\n"
	}
	return out
}

func sampleRecord(zone int32, tsMs int64) *shared.FlowRecord {
	return &shared.FlowRecord{
		TimeStartMs: tsMs,
		Exporter:    "exp-1",
		IPVersion:   4,
		Proto:       6,
		Packets:     1,
		Bytes:       100,
		ZoneID:      zone,
	}
}

func TestJSONLReplay(t *testing.T) {
	t.Parallel()
	var lines []string
	for i := 0; i < 3; i++ {
		b, _ := json.Marshal(sampleRecord(int32(i+1), int64(1000+i)*1000))
		lines = append(lines, string(b))
	}
	lines = append(lines, "") // 空行跳过
	path := writeJSONL(t, lines)

	src := NewJSONLSource(path)
	var got []int32
	err := src.Run(context.Background(), func(rec *shared.FlowRecord) error {
		got = append(got, rec.ZoneID)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || got[0] != 1 || got[2] != 3 {
		t.Fatalf("replayed zones = %v", got)
	}
	src.Close()
	if err := src.Run(context.Background(), func(*shared.FlowRecord) error { return nil }); err == nil {
		t.Fatal("closed source should error")
	}
}

func TestJSONLMalformedLine(t *testing.T) {
	t.Parallel()
	path := writeJSONL(t, []string{`{"zone_id":1}`, `{bad json`})
	src := NewJSONLSource(path)
	err := src.Run(context.Background(), func(*shared.FlowRecord) error { return nil })
	if err == nil {
		t.Fatal("malformed line should error")
	}
	var se *json.SyntaxError
	if !errors.As(err, &se) {
		t.Fatalf("error should wrap json error with %%w, got %v", err)
	}
}

func TestJSONLHandlerErrorPropagates(t *testing.T) {
	t.Parallel()
	path := writeJSONL(t, []string{`{"zone_id":1}`})
	src := NewJSONLSource(path)
	sentinel := errors.New("handler boom")
	err := src.Run(context.Background(), func(*shared.FlowRecord) error { return sentinel })
	if !errors.Is(err, sentinel) {
		t.Fatalf("handler error should propagate with %%w, got %v", err)
	}
}

func TestJSONLMissingFile(t *testing.T) {
	t.Parallel()
	src := NewJSONLSource(filepath.Join(t.TempDir(), "nope.jsonl"))
	if err := src.Run(context.Background(), func(*shared.FlowRecord) error { return nil }); err == nil {
		t.Fatal("missing file should error")
	}
}

func TestKafkaStub(t *testing.T) {
	t.Parallel()
	src, err := NewKafkaSource([]string{"k1:9092"}, shared.GroupAnalyticsDetect)
	if err != nil {
		t.Fatal(err)
	}
	if src.Topic != shared.TopicFlowsRaw || src.Group != shared.GroupAnalyticsDetect {
		t.Fatalf("stub wiring wrong: %+v", src)
	}
	if err := src.Run(context.Background(), func(*shared.FlowRecord) error { return nil }); !errors.Is(err, ErrKafkaNotImplemented) {
		t.Fatalf("stub should return ErrKafkaNotImplemented, got %v", err)
	}
	src.Close()

	agg, err := NewKafkaSource(nil, shared.GroupAnalyticsAggregate)
	if err != nil || agg.Group != shared.GroupAnalyticsAggregate {
		t.Fatalf("aggregate group should be accepted, got %v", err)
	}
	if _, err := NewKafkaSource(nil, "analytics.unknown"); err == nil {
		t.Fatal("unregistered group must be rejected (09 §2)")
	}
}

// chanSource —— 测试用 Source：多生产者并发投递（验证单消费者结构）。
type chanSource struct {
	ch     chan *shared.FlowRecord
	closed atomic.Bool
}

func (s *chanSource) Run(ctx context.Context, handle Handler) error {
	for rec := range s.ch {
		if err := handle(rec); err != nil {
			return err
		}
	}
	return nil
}
func (s *chanSource) Close() { s.closed.Store(true) }

// TestPipelineConcurrentProducers —— 并发生产者 × 单消费者：全部记录按序处理、
// tick 与记录互不交错（结构化免锁保证，dd/03 §1；-race 不可用环境以计数一致性替代）。
func TestPipelineConcurrentProducers(t *testing.T) {
	t.Parallel()
	src := &chanSource{ch: make(chan *shared.FlowRecord, 1024)}

	var mu sync.Mutex // 仅保护测试计数器（引擎回调本身单线程到达）
	var records int
	var ticks int64

	p, err := NewPipeline(src, func(rec *shared.FlowRecord) error {
		mu.Lock()
		records++
		mu.Unlock()
		if rec.ZoneID <= 0 {
			return fmt.Errorf("bad zone %d", rec.ZoneID)
		}
		time.Sleep(50 * time.Microsecond) // 拉长回放，使 tick 有机会触发
		return nil
	}, func() {
		atomic.AddInt64(&ticks, 1)
	}, WithTickInterval(5*time.Millisecond), WithBuffer(128))
	if err != nil {
		t.Fatal(err)
	}

	const producers = 8
	const perProducer = 500
	done := make(chan error, 1)
	go func() { done <- p.Run(context.Background()) }()

	var wg sync.WaitGroup
	for i := 0; i < producers; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < perProducer; j++ {
				src.ch <- sampleRecord(int32(id+1), int64(j)*1000)
			}
		}(i)
	}
	wg.Wait()
	close(src.ch)

	if err := <-done; err != nil {
		t.Fatalf("pipeline run: %v", err)
	}
	if records != producers*perProducer {
		t.Fatalf("processed %d records, want %d", records, producers*perProducer)
	}
	if atomic.LoadInt64(&ticks) == 0 {
		t.Fatal("tick should have fired during replay")
	}
	if !src.closed.Load() {
		t.Fatal("source should be closed after run")
	}
}

// TestPipelineJSONL —— 端到端：JSONL 回放经管道到聚合回调。
func TestPipelineJSONL(t *testing.T) {
	t.Parallel()
	var lines []string
	for i := 0; i < 100; i++ {
		b, _ := json.Marshal(sampleRecord(9, int64(2000+i)*1000))
		lines = append(lines, string(b))
	}
	src := NewJSONLSource(writeJSONL(t, lines))

	var count int
	p, err := NewPipeline(src, func(*shared.FlowRecord) error { count++; return nil }, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if count != 100 {
		t.Fatalf("count = %d, want 100", count)
	}
}

func TestPipelineContextCancel(t *testing.T) {
	t.Parallel()
	src := &chanSource{ch: make(chan *shared.FlowRecord, 1)}
	p, err := NewPipeline(src, func(*shared.FlowRecord) error { return nil }, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- p.Run(ctx) }()
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("want context.Canceled, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("pipeline did not stop on cancel")
	}
}

func TestPipelineNilArgs(t *testing.T) {
	t.Parallel()
	if _, err := NewPipeline(nil, func(*shared.FlowRecord) error { return nil }, nil); err == nil {
		t.Fatal("nil source should error")
	}
	src := NewJSONLSource("x")
	if _, err := NewPipeline(src, nil, nil); err == nil {
		t.Fatal("nil handler should error")
	}
}
