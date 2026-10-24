package export

import (
	"context"
	"fmt"
	"sync"
)

// ProgressStore —— 导出进度接口（Redis db2 任务状态，docs/dd/04 §4/§5.2：
// 进度 = 已完成切片/总切片，Redis HINCRBY；本接口以行计数为骨架口径，
// 真实实现接 go-redis，键位规划见模块 README TODO）。
type ProgressStore interface {
	// Set 记录任务已处理行数与总行数估计（total=0 表示未知）。
	Set(ctx context.Context, jobID string, doneRows, totalRows int64) error
	// Get 读取进度（无记录返回 0,0,nil）。
	Get(ctx context.Context, jobID string) (doneRows, totalRows int64, err error)
}

// MemoryProgressStore —— 内存假实现（Redis 桩）。
type MemoryProgressStore struct {
	mu    sync.Mutex
	state map[string][2]int64
}

// NewMemoryProgressStore 构造内存进度桩。
func NewMemoryProgressStore() *MemoryProgressStore {
	return &MemoryProgressStore{state: make(map[string][2]int64)}
}

// Set 记录 (doneRows, totalRows)。
func (m *MemoryProgressStore) Set(_ context.Context, jobID string, doneRows, totalRows int64) error {
	if jobID == "" {
		return fmt.Errorf("memory progress set: empty job id")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.state[jobID] = [2]int64{doneRows, totalRows}
	return nil
}

// Get 读取进度。
func (m *MemoryProgressStore) Get(_ context.Context, jobID string) (int64, int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v := m.state[jobID]
	return v[0], v[1], nil
}
