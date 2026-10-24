package inserter

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// fakeClock —— 确定性注入时钟（批量器周期单测）。
type fakeClock struct {
	mu   sync.Mutex
	now  time.Time
	tick chan time.Time
}

func newFakeClock(start time.Time) *fakeClock {
	// tick 带缓冲：advance 在无 Run 消费者时也不阻塞
	return &fakeClock{now: start, tick: make(chan time.Time, 64)}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
	c.tick <- c.now
}

// newTicker —— fakeClock 的周期信号源：advance 即触发。
func (c *fakeClock) NewTicker(time.Duration) Ticker { return fakeTicker{c: c.tick} }

type fakeTicker struct {
	c <-chan time.Time
}

func (t fakeTicker) C() <-chan time.Time { return t.c }
func (t fakeTicker) Stop()               {}

// TestBatcherFlushAtMaxRows —— 行数阈值（≥50,000 默认；此处用小阈值）同步 flush。
func TestBatcherFlushAtMaxRows(t *testing.T) {
	clk := newFakeClock(time.Unix(1771900000, 0))
	var flushed [][]int
	b, err := NewBatcher(3, time.Hour, clk,
		func(_ context.Context, rows []int) error {
			flushed = append(flushed, rows)
			return nil
		}, nil)
	if err != nil {
		t.Fatalf("new batcher: %v", err)
	}
	for i := 1; i <= 5; i++ {
		if err := b.Add(i); err != nil {
			t.Fatalf("add %d: %v", i, err)
		}
	}
	if len(flushed) != 1 || len(flushed[0]) != 3 {
		t.Fatalf("flushed = %v, want single batch of 3", flushed)
	}
	if b.Pending() != 2 {
		t.Errorf("pending = %d, want 2", b.Pending())
	}
}

// TestBatcherFlushOnInterval —— 时间阈值（注入时钟推进 2s）触发 flush。
func TestBatcherFlushOnInterval(t *testing.T) {
	clk := newFakeClock(time.Unix(1771900000, 0))
	var mu sync.Mutex
	var flushed int
	b, err := NewBatcher(100, 2*time.Second, clk,
		func(_ context.Context, rows []int) error {
			mu.Lock()
			flushed++
			mu.Unlock()
			return nil
		}, nil)
	if err != nil {
		t.Fatalf("new batcher: %v", err)
	}
	_ = b.Add(1)

	clk.advance(time.Second)
	_ = b.FlushIfDue() // 未到 interval：不刷
	mu.Lock()
	if flushed != 0 {
		t.Fatalf("premature flush: %d", flushed)
	}
	mu.Unlock()

	clk.advance(2 * time.Second)
	if err := b.FlushIfDue(); err != nil {
		t.Fatalf("flush if due: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if flushed != 1 {
		t.Fatalf("flushed = %d, want 1", flushed)
	}
	if b.Pending() != 0 {
		t.Errorf("pending = %d", b.Pending())
	}
}

// TestBatcherFlushIfDueEmpty —— 空积压时不产生空批次。
func TestBatcherFlushIfDueEmpty(t *testing.T) {
	clk := newFakeClock(time.Unix(0, 0))
	calls := 0
	b, _ := NewBatcher(10, time.Second, clk,
		func(_ context.Context, rows []int) error {
			calls++
			return nil
		}, nil)
	clk.advance(10 * time.Second)
	if err := b.FlushIfDue(); err != nil {
		t.Fatalf("flush if due: %v", err)
	}
	if calls != 0 {
		t.Errorf("empty flush calls = %d", calls)
	}
}

// TestBatcherManualFlush —— Flush 立即刷出；空时 no-op。
func TestBatcherManualFlush(t *testing.T) {
	var got [][]string
	b, _ := NewBatcher(10, time.Hour, newFakeClock(time.Unix(0, 0)),
		func(_ context.Context, rows []string) error {
			got = append(got, rows)
			return nil
		}, nil)
	if err := b.Flush(context.Background()); err != nil {
		t.Fatalf("empty flush: %v", err)
	}
	_ = b.Add("a")
	_ = b.Add("b")
	if err := b.Flush(context.Background()); err != nil {
		t.Fatalf("flush: %v", err)
	}
	if len(got) != 1 || len(got[0]) != 2 {
		t.Fatalf("got = %v", got)
	}
}

// TestBatcherFlushError —— flush 错误上抛（含 %w）。
func TestBatcherFlushError(t *testing.T) {
	sentinel := errors.New("ch down")
	b, err := NewBatcher(1, time.Hour, newFakeClock(time.Unix(0, 0)),
		func(_ context.Context, rows []int) error { return sentinel }, nil)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	err = b.Add(1)
	if !errors.Is(err, sentinel) {
		t.Fatalf("add err = %v, want wrapped sentinel", err)
	}
	if b.Pending() != 0 { // 失败批次已出队（整批重发由上层消费位点兜底）
		t.Errorf("pending = %d", b.Pending())
	}
}

// TestBatcherConstructor —— 非法构造参数。
func TestBatcherConstructor(t *testing.T) {
	fn := func(context.Context, []int) error { return nil }
	if _, err := NewBatcher(0, time.Second, nil, fn, nil); err == nil {
		t.Error("maxRows=0 must fail")
	}
	if _, err := NewBatcher(1, 0, nil, fn, nil); err == nil {
		t.Error("interval=0 must fail")
	}
	if _, err := NewBatcher[[]int](1, time.Second, nil, nil, nil); err == nil {
		t.Error("nil flushFn must fail")
	}
	if _, err := NewBatcher(1, time.Second, nil, fn, nil); err != nil {
		t.Errorf("nil clock defaults to SystemClock: %v", err)
	}
}

// TestBatcherRunShutdownTailFlush —— Run 关停尾刷（ctx 取消）。
func TestBatcherRunShutdownTailFlush(t *testing.T) {
	clk := newFakeClock(time.Unix(0, 0))
	done := make(chan []int, 1)
	b, _ := NewBatcher(100, time.Hour, clk,
		func(_ context.Context, rows []int) error {
			done <- rows
			return nil
		}, nil)
	ctx, cancel := context.WithCancel(context.Background())
	go b.Run(ctx)
	_ = b.Add(7)
	cancel()
	select {
	case rows := <-done:
		if len(rows) != 1 || rows[0] != 7 {
			t.Fatalf("tail flush = %v", rows)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no tail flush after cancel")
	}
}

// TestBatcherDefaults —— 批量参数常量与 dd/04 §1.3 一致。
func TestBatcherDefaults(t *testing.T) {
	if DefaultBatchMaxRows != 50_000 {
		t.Errorf("DefaultBatchMaxRows = %d, want 50000 (docs/dd/04 §1.3)", DefaultBatchMaxRows)
	}
	if DefaultFlushInterval != 2*time.Second {
		t.Errorf("DefaultFlushInterval = %s, want 2s", DefaultFlushInterval)
	}
}

// TestSystemClock —— 真实时钟基础行为。
func TestSystemClock(t *testing.T) {
	if (SystemClock{}).Now().IsZero() {
		t.Fatal("system clock now is zero")
	}
	tk := SystemClock{}.NewTicker(5 * time.Millisecond)
	defer tk.Stop()
	select {
	case <-tk.C():
	case <-time.After(time.Second):
		t.Fatal("system ticker did not fire")
	}
}
