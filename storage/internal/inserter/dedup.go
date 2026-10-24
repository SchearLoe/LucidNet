package inserter

import (
	"context"
	"errors"
	"fmt"
	"sync"
)

// ErrNotImplemented —— walking-skeleton 桩占位错误（真实实现就绪前的方法兜底）。
var ErrNotImplemented = errors.New("not implemented: walking-skeleton stub")

// Deduper —— 批次幂等去重接口（PG export_batches 批次追踪表，docs/09 §2/§7；
// 表 DDL 属主为 Master，见 docs/00 §5）。
type Deduper interface {
	// Seen 报告 batch_id 是否已处理过。
	Seen(ctx context.Context, batchID uint64) (bool, error)
	// MarkDone 标记批次完成（真实实现须与数据落库同事务语义）。
	MarkDone(ctx context.Context, batchID uint64) error
}

// MemoryDeduper —— 内存假实现（单测/联调）：固定容量 FIFO 淘汰。
type MemoryDeduper struct {
	mu    sync.Mutex
	cap   int
	seen  map[uint64]struct{}
	queue []uint64
}

// NewMemoryDeduper 构造内存去重器；capacity <= 0 时取 1024。
func NewMemoryDeduper(capacity int) *MemoryDeduper {
	if capacity <= 0 {
		capacity = 1024
	}
	return &MemoryDeduper{
		cap:  capacity,
		seen: make(map[uint64]struct{}, capacity),
	}
}

// Seen 报告 batch_id 是否已标记完成。
func (m *MemoryDeduper) Seen(_ context.Context, batchID uint64) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.seen[batchID]
	return ok, nil
}

// MarkDone 标记批次完成；重复标记幂等。
func (m *MemoryDeduper) MarkDone(_ context.Context, batchID uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.seen[batchID]; ok {
		return nil
	}
	m.seen[batchID] = struct{}{}
	m.queue = append(m.queue, batchID)
	for len(m.queue) > m.cap {
		delete(m.seen, m.queue[0])
		m.queue = m.queue[1:]
	}
	return nil
}

// PGDeduper —— PG export_batches 实现桩（pgx 接入后替换；docs/09 §2 幂等语义）。
type PGDeduper struct {
	dsn string
}

// NewPGDeduper 构造 PG 去重桩。
func NewPGDeduper(dsn string) *PGDeduper { return &PGDeduper{dsn: dsn} }

// Seen 查询批次是否已处理（桩）。
func (p *PGDeduper) Seen(_ context.Context, _ uint64) (bool, error) {
	return false, fmt.Errorf("pg deduper seen: %w", ErrNotImplemented)
}

// MarkDone 标记批次完成（桩）。
func (p *PGDeduper) MarkDone(_ context.Context, _ uint64) error {
	return fmt.Errorf("pg deduper mark done: %w", ErrNotImplemented)
}
