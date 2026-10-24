package export

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// Store —— 导出任务持久化接口（真实实现落 PG export_jobs，docs/09 §7：
// 表 DDL 属主 = Master，Storage 为数据属主写、Console 只读；pgx 接入 TODO）。
type Store interface {
	// Create 新建任务（校验 ValidateNewJob；ID 冲突返回 ErrDuplicateJobID）。
	Create(ctx context.Context, j Job) error
	// Get 按 ID 读取（未找到返回 ErrJobNotFound）。
	Get(ctx context.Context, id string) (Job, error)
	// Update 保存任务快照；状态变化须满足状态机（CanTransition），
	// 同状态原地更新（进度/URL 等字段）允许。
	Update(ctx context.Context, j Job) error
}

// MemoryStore —— 内存假实现（单测/联调/cmd 空跑）；深拷贝防外部别名。
type MemoryStore struct {
	mu   sync.Mutex
	jobs map[string]Job
	now  func() int64
}

// NewMemoryStore 构造内存任务库；now 为秒级时钟（默认 time.Now）。
func NewMemoryStore(now func() int64) *MemoryStore {
	if now == nil {
		now = func() int64 { return time.Now().Unix() }
	}
	return &MemoryStore{jobs: make(map[string]Job), now: now}
}

func cloneJob(j Job) Job {
	j.Fields = append([]string(nil), j.Fields...)
	return j
}

// Create 保存新任务。
func (m *MemoryStore) Create(_ context.Context, j Job) error {
	if err := ValidateNewJob(j); err != nil {
		return err
	}
	if j.Status != StatusQueued {
		return fmt.Errorf("memory store create job %s: initial status must be queued, got %s: %w", j.ID, j.Status, ErrInvalidJob)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.jobs[j.ID]; ok {
		return fmt.Errorf("memory store create job %s: %w", j.ID, ErrDuplicateJobID)
	}
	if j.CreatedAt == 0 {
		j.CreatedAt = m.now()
	}
	if j.UpdatedAt == 0 {
		j.UpdatedAt = j.CreatedAt
	}
	m.jobs[j.ID] = cloneJob(j)
	return nil
}

// Get 读取任务快照。
func (m *MemoryStore) Get(_ context.Context, id string) (Job, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	j, ok := m.jobs[id]
	if !ok {
		return Job{}, fmt.Errorf("memory store get job %s: %w", id, ErrJobNotFound)
	}
	return cloneJob(j), nil
}

// Update 校验状态机后保存。
func (m *MemoryStore) Update(_ context.Context, j Job) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	old, ok := m.jobs[j.ID]
	if !ok {
		return fmt.Errorf("memory store update job %s: %w", j.ID, ErrJobNotFound)
	}
	if old.Status != j.Status && !CanTransition(old.Status, j.Status) {
		return fmt.Errorf("memory store update job %s: %s→%s: %w", j.ID, old.Status, j.Status, ErrInvalidTransition)
	}
	j.UpdatedAt = m.now()
	m.jobs[j.ID] = cloneJob(j)
	return nil
}
