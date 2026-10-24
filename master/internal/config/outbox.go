package config

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// 持久化发布补偿队列（docs/dd/07 §1 "PG 权威 → 事务后发 etcd 增量，失败补偿重试队列"）。
//
// 语义：etcd 发布失败 → 版本标 failed（集群只读保护，调用方收到错误）+ 落 outbox；
// 后台按指数退避重投 etcd → 成功关单（版本转 published 并恢复 ACK 跟踪/reload 下发），
// 或人工取消关单（版本保持 failed，经重发新版本恢复）。Master 重启后扫描 pending 继续
// 补偿（PG 权威，内存队列丢失不漏发）。

// OutboxStatus —— 补偿单状态。
type OutboxStatus string

const (
	OutboxPending   OutboxStatus = "pending"   // 待重试
	OutboxDone      OutboxStatus = "done"      // 发布成功关单
	OutboxCancelled OutboxStatus = "cancelled" // 人工取消关单
)

// OutboxEntry —— 补偿单（config_outbox 行）。
type OutboxEntry struct {
	ID        int64        `json:"id"`
	Scope     string       `json:"scope"`
	Version   uint64       `json:"version"`
	Payload   []byte       `json:"-"` // 配置快照（Envelope.Data 原文）
	Required  []string     `json:"required"`
	Status    OutboxStatus `json:"status"`
	Attempt   int          `json:"attempt"`
	NextRetry time.Time    `json:"next_retry"`
	LastError string       `json:"last_error,omitempty"`
	CreatedAt time.Time    `json:"created_at"`
	UpdatedAt time.Time    `json:"updated_at"`
}

// ErrOutboxNotFound —— 补偿单不存在（或已关单）。
var ErrOutboxNotFound = errors.New("config: outbox entry not found")

// OutboxStore —— 补偿队列存储抽象（PG 权威 + 内存桩）。
type OutboxStore interface {
	// Enqueue 落队（写入 ID/created_at；同 scope+version 已有 pending 单时报错）。
	Enqueue(ctx context.Context, e *OutboxEntry) error
	// PendingDue 到期待重试条目（按 next_retry 升序，上限 limit）。
	PendingDue(ctx context.Context, now time.Time, limit int) ([]OutboxEntry, error)
	// ListPending 全部 pending（运维查询，按 ID 升序）。
	ListPending(ctx context.Context) ([]OutboxEntry, error)
	// PendingCount pending 深度（Prometheus gauge 采样）。
	PendingCount(ctx context.Context) (int, error)
	// MarkAttempt 重试失败：attempt++、顺延 next_retry、记录 last_error。
	MarkAttempt(ctx context.Context, id int64, nextRetry time.Time, lastErr string) error
	// MarkDone 成功关单。
	MarkDone(ctx context.Context, id int64) error
	// Cancel 人工取消（scope+version 定位 pending 单）。
	Cancel(ctx context.Context, scope string, version uint64) error
	Close() error
}

// ---------- 内存实现（开发模式 / 单测桩） ----------

// MemOutbox —— 内存补偿队列（Master 重启即丢，仅开发模式）。
type MemOutbox struct {
	mu      sync.Mutex
	nextID  int64
	entries map[int64]*OutboxEntry
}

// NewMemOutbox 构造。
func NewMemOutbox() *MemOutbox { return &MemOutbox{entries: map[int64]*OutboxEntry{}} }

// Enqueue 实现 OutboxStore。
func (m *MemOutbox) Enqueue(_ context.Context, e *OutboxEntry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, cur := range m.entries {
		if cur.Scope == e.Scope && cur.Version == e.Version && cur.Status == OutboxPending {
			return fmt.Errorf("outbox entry %s v%d already pending", e.Scope, e.Version)
		}
	}
	m.nextID++
	now := time.Now()
	saved := *e
	saved.ID = m.nextID
	saved.Status = OutboxPending
	saved.CreatedAt, saved.UpdatedAt = now, now
	m.entries[saved.ID] = &saved
	e.ID, e.Status, e.CreatedAt, e.UpdatedAt = saved.ID, saved.Status, now, now
	return nil
}

// PendingDue 实现 OutboxStore。
func (m *MemOutbox) PendingDue(_ context.Context, now time.Time, limit int) ([]OutboxEntry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []OutboxEntry
	for _, e := range m.entries {
		if e.Status == OutboxPending && !e.NextRetry.After(now) {
			out = append(out, *e)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].NextRetry.Before(out[j].NextRetry) })
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// ListPending 实现 OutboxStore。
func (m *MemOutbox) ListPending(_ context.Context) ([]OutboxEntry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []OutboxEntry
	for _, e := range m.entries {
		if e.Status == OutboxPending {
			out = append(out, *e)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// PendingCount 实现 OutboxStore。
func (m *MemOutbox) PendingCount(_ context.Context) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, e := range m.entries {
		if e.Status == OutboxPending {
			n++
		}
	}
	return n, nil
}

// MarkAttempt 实现 OutboxStore。
func (m *MemOutbox) MarkAttempt(_ context.Context, id int64, nextRetry time.Time, lastErr string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.entries[id]
	if !ok || e.Status != OutboxPending {
		return ErrOutboxNotFound
	}
	e.Attempt++
	e.NextRetry = nextRetry
	e.LastError = lastErr
	e.UpdatedAt = time.Now()
	return nil
}

// MarkDone 实现 OutboxStore。
func (m *MemOutbox) MarkDone(_ context.Context, id int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.entries[id]
	if !ok || e.Status != OutboxPending {
		return ErrOutboxNotFound
	}
	e.Status = OutboxDone
	e.LastError = ""
	e.UpdatedAt = time.Now()
	return nil
}

// Cancel 实现 OutboxStore。
func (m *MemOutbox) Cancel(_ context.Context, scope string, version uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, e := range m.entries {
		if e.Scope == scope && e.Version == version && e.Status == OutboxPending {
			e.Status = OutboxCancelled
			e.UpdatedAt = time.Now()
			return nil
		}
	}
	return ErrOutboxNotFound
}

// Close 实现 OutboxStore（内存实现为空）。
func (m *MemOutbox) Close() error { return nil }

var _ OutboxStore = (*MemOutbox)(nil)

// ---------- PG 实现（config_outbox 表，migration 0002；权威） ----------

// PGOutbox —— PostgreSQL 补偿队列（Master 重启扫描 pending 继续）。
type PGOutbox struct{ pool *pgxpool.Pool }

// NewPGOutbox 构造。
func NewPGOutbox(pool *pgxpool.Pool) *PGOutbox { return &PGOutbox{pool: pool} }

// Enqueue 实现 OutboxStore。
func (p *PGOutbox) Enqueue(ctx context.Context, e *OutboxEntry) error {
	required, err := json.Marshal(e.Required)
	if err != nil {
		return fmt.Errorf("marshal outbox required: %w", err)
	}
	now := time.Now()
	next := e.NextRetry
	if next.IsZero() {
		next = now
	}
	err = p.pool.QueryRow(ctx, `
INSERT INTO config_outbox(scope, version, payload, required, status, attempt, next_retry, created_at, updated_at)
VALUES($1,$2,$3::jsonb,$4::jsonb,$5,$6,$7,$8,$8)
RETURNING id, created_at, updated_at`,
		e.Scope, e.Version, string(e.Payload), string(required), string(OutboxPending),
		e.Attempt, next, now).Scan(&e.ID, &e.CreatedAt, &e.UpdatedAt)
	if err != nil {
		return fmt.Errorf("enqueue outbox %s v%d: %w", e.Scope, e.Version, err)
	}
	e.Status, e.NextRetry = OutboxPending, next
	return nil
}

// PendingDue 实现 OutboxStore。
func (p *PGOutbox) PendingDue(ctx context.Context, now time.Time, limit int) ([]OutboxEntry, error) {
	rows, err := p.pool.Query(ctx, `
SELECT id, scope, version, payload::text, required::text, attempt, next_retry
FROM config_outbox WHERE status=$1 AND next_retry<=$2 ORDER BY next_retry, id LIMIT $3`,
		string(OutboxPending), now, limit)
	if err != nil {
		return nil, fmt.Errorf("query due outbox: %w", err)
	}
	defer rows.Close()
	return scanOutboxRows(rows, false)
}

// ListPending 实现 OutboxStore。
func (p *PGOutbox) ListPending(ctx context.Context) ([]OutboxEntry, error) {
	rows, err := p.pool.Query(ctx, `
SELECT id, scope, version, payload::text, required::text, attempt, next_retry, last_error, created_at, updated_at
FROM config_outbox WHERE status=$1 ORDER BY id`, string(OutboxPending))
	if err != nil {
		return nil, fmt.Errorf("query pending outbox: %w", err)
	}
	defer rows.Close()
	return scanOutboxRows(rows, true)
}

func scanOutboxRows(rows pgx.Rows, full bool) ([]OutboxEntry, error) {
	var out []OutboxEntry
	for rows.Next() {
		var e OutboxEntry
		var required string
		if full {
			if err := rows.Scan(&e.ID, &e.Scope, &e.Version, &e.Payload, &required,
				&e.Attempt, &e.NextRetry, &e.LastError, &e.CreatedAt, &e.UpdatedAt); err != nil {
				return nil, fmt.Errorf("scan outbox entry: %w", err)
			}
		} else {
			if err := rows.Scan(&e.ID, &e.Scope, &e.Version, &e.Payload, &required,
				&e.Attempt, &e.NextRetry); err != nil {
				return nil, fmt.Errorf("scan outbox entry: %w", err)
			}
		}
		e.Status = OutboxPending
		_ = json.Unmarshal([]byte(required), &e.Required)
		out = append(out, e)
	}
	return out, rows.Err()
}

// PendingCount 实现 OutboxStore。
func (p *PGOutbox) PendingCount(ctx context.Context) (int, error) {
	var n int
	err := p.pool.QueryRow(ctx,
		`SELECT count(*) FROM config_outbox WHERE status=$1`, string(OutboxPending)).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("count pending outbox: %w", err)
	}
	return n, nil
}

// MarkAttempt 实现 OutboxStore。
func (p *PGOutbox) MarkAttempt(ctx context.Context, id int64, nextRetry time.Time, lastErr string) error {
	tag, err := p.pool.Exec(ctx, `
UPDATE config_outbox SET attempt=attempt+1, next_retry=$2, last_error=$3, updated_at=$4
WHERE id=$1 AND status=$5`, id, nextRetry, lastErr, time.Now(), string(OutboxPending))
	if err != nil {
		return fmt.Errorf("mark outbox attempt %d: %w", id, err)
	}
	if tag.RowsAffected() == 0 {
		return ErrOutboxNotFound
	}
	return nil
}

// MarkDone 实现 OutboxStore。
func (p *PGOutbox) MarkDone(ctx context.Context, id int64) error {
	tag, err := p.pool.Exec(ctx, `
UPDATE config_outbox SET status=$2, last_error='', updated_at=$3 WHERE id=$1 AND status=$4`,
		id, string(OutboxDone), time.Now(), string(OutboxPending))
	if err != nil {
		return fmt.Errorf("mark outbox done %d: %w", id, err)
	}
	if tag.RowsAffected() == 0 {
		return ErrOutboxNotFound
	}
	return nil
}

// Cancel 实现 OutboxStore。
func (p *PGOutbox) Cancel(ctx context.Context, scope string, version uint64) error {
	tag, err := p.pool.Exec(ctx, `
UPDATE config_outbox SET status=$3, updated_at=$4
WHERE scope=$1 AND version=$2 AND status=$5`,
		scope, version, string(OutboxCancelled), time.Now(), string(OutboxPending))
	if err != nil {
		return fmt.Errorf("cancel outbox %s v%d: %w", scope, version, err)
	}
	if tag.RowsAffected() == 0 {
		return ErrOutboxNotFound
	}
	return nil
}

// Close 实现 OutboxStore（连接池由装配层统一关闭，空实现）。
func (p *PGOutbox) Close() error { return nil }

var _ OutboxStore = (*PGOutbox)(nil)
