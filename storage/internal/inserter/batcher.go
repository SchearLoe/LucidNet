package inserter

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// 批量参数（docs/dd/04 §1.3：≥50,000 行或 2s flush；单分片 <10 并发 insert）。
const (
	DefaultBatchMaxRows  = 50_000
	DefaultFlushInterval = 2 * time.Second
)

// Batcher —— 泛型批量器：行数达到阈值或距上次 flush 超过 interval 即刷出。
// 可注入 Clock 做确定性单测（docs/11 §3 表驱动测试）。
// 并发安全：Add / Flush / FlushIfDue / Run 可跨 goroutine 调用。
type Batcher[T any] struct {
	maxRows  int
	interval time.Duration
	clock    Clock
	flushFn  func(context.Context, []T) error
	onErr    func(error)

	mu        sync.Mutex
	buf       []T
	lastFlush time.Time
	ctx       context.Context
}

// NewBatcher 构造批量器；maxRows/interval 必须为正，clock 为 nil 时用 SystemClock。
func NewBatcher[T any](maxRows int, interval time.Duration, clock Clock,
	flushFn func(context.Context, []T) error, onErr func(error),
) (*Batcher[T], error) {
	if maxRows <= 0 {
		return nil, fmt.Errorf("new batcher: max rows %d must be positive", maxRows)
	}
	if interval <= 0 {
		return nil, fmt.Errorf("new batcher: flush interval %s must be positive", interval)
	}
	if flushFn == nil {
		return nil, fmt.Errorf("new batcher: flush func required")
	}
	if clock == nil {
		clock = SystemClock{}
	}
	return &Batcher[T]{
		maxRows:   maxRows,
		interval:  interval,
		clock:     clock,
		flushFn:   flushFn,
		onErr:     onErr,
		buf:       make([]T, 0, min(maxRows, 1024)),
		lastFlush: clock.Now(),
	}, nil
}

// MaxRows 返回行数阈值。
func (b *Batcher[T]) MaxRows() int { return b.maxRows }

// Interval 返回 flush 周期。
func (b *Batcher[T]) Interval() time.Duration { return b.interval }

// Pending 返回当前积压行数。
func (b *Batcher[T]) Pending() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.buf)
}

// Add 追加一行；达到行数阈值时同步 flush（背压语义，docs/dd/04 §1.3）。
// 返回 flush 错误（含 %w 包裹），调用方据此整批重发。
func (b *Batcher[T]) Add(row T) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.buf = append(b.buf, row)
	if len(b.buf) >= b.maxRows {
		return b.flushLocked()
	}
	return nil
}

// FlushIfDue —— 距上次 flush 超过 interval 且有积压时刷出。
// 由 Run 循环周期驱动，也可由测试用注入时钟手动驱动。
func (b *Batcher[T]) FlushIfDue() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.buf) == 0 {
		return nil
	}
	if b.clock.Now().Sub(b.lastFlush) < b.interval {
		return nil
	}
	return b.flushLocked()
}

// Flush 立即刷出积压（关停/检查点用）；无积压时返回 nil。
func (b *Batcher[T]) Flush(ctx context.Context) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.buf) == 0 {
		return nil
	}
	if ctx != nil {
		b.ctx = ctx
	}
	return b.flushLocked()
}

// Run 周期驱动 FlushIfDue；ctx 取消时尾刷积压并返回。
func (b *Batcher[T]) Run(ctx context.Context) {
	b.mu.Lock()
	b.ctx = ctx
	b.mu.Unlock()
	tk := b.clock.NewTicker(b.interval)
	defer tk.Stop()
	for {
		select {
		case <-tk.C():
			if err := b.FlushIfDue(); err != nil && b.onErr != nil {
				b.onErr(err)
			}
		case <-ctx.Done():
			_ = b.Flush(context.Background()) // 关停尾刷不受已取消 ctx 影响
			return
		}
	}
}

func (b *Batcher[T]) flushLocked() error {
	rows := b.buf
	b.buf = make([]T, 0, min(b.maxRows, 1024))
	b.lastFlush = b.clock.Now()
	ctx := b.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	// flush 回调不得持有已取消的 ctx（关停尾刷场景）
	ctx = context.WithoutCancel(ctx)
	if err := b.flushFn(ctx, rows); err != nil {
		if b.onErr != nil {
			b.onErr(err)
		}
		return fmt.Errorf("batcher flush %d rows: %w", len(rows), err)
	}
	return nil
}
