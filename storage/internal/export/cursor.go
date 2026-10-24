package export

import (
	"context"
	"fmt"
	"sync"
)

// CursorStore —— 导出游标持久化接口（dd/04 §5.2：任务中断可续，游标持久化；
// 真实实现落 Redis db2 / PG export_batches，TODO）。游标语义由 RowSource 定义。
type CursorStore interface {
	// Save 保存任务游标（"" 表示已耗尽，语义上等同清空）。
	Save(ctx context.Context, jobID, cursor string) error
	// Load 读取任务游标（"" = 从头开始）。
	Load(ctx context.Context, jobID string) (string, error)
	// Clear 清除游标（任务终态后回收）。
	Clear(ctx context.Context, jobID string) error
}

// MemoryCursorStore —— 内存假实现（游标续跑桩）。
type MemoryCursorStore struct {
	mu      sync.Mutex
	cursors map[string]string
}

// NewMemoryCursorStore 构造内存游标桩。
func NewMemoryCursorStore() *MemoryCursorStore {
	return &MemoryCursorStore{cursors: make(map[string]string)}
}

// Save 保存游标。
func (m *MemoryCursorStore) Save(_ context.Context, jobID, cursor string) error {
	if jobID == "" {
		return fmt.Errorf("memory cursor save: empty job id")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cursors[jobID] = cursor
	return nil
}

// Load 读取游标（无记录返回 ""）。
func (m *MemoryCursorStore) Load(_ context.Context, jobID string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.cursors[jobID], nil
}

// Clear 清除游标（幂等）。
func (m *MemoryCursorStore) Clear(_ context.Context, jobID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.cursors, jobID)
	return nil
}
