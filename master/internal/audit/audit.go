package audit

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// 审计（docs/hld/07 §4）：全部写操作（who/when/diff/ip）入 PG audit_log，Console 可查。
// 系统级事件（节点故障、配置版本 partial ACK）也经此留痕（category=system），
// 独立告警通道（docs/00 §2.4 Alarm, source=system）为契约缺口，见模块 TODO。

// Entry —— 一条审计记录。
type Entry struct {
	ID        int64
	Ts        time.Time
	User      string // 操作者（"system" 表示系统自动事件）
	Tenant    string
	Action    string // 如 node.drain / config.publish / auth.login / system.alarm
	Resource  string // 如 node:collector-1 / scope:/lucid/zones
	DiffJSON  string
	IP        string
	Category  string // user|system
	DetailMsg string // 人读摘要
}

// Filter —— 查询过滤。
type Filter struct {
	User     string
	Action   string
	From     time.Time
	To       time.Time
	Page     int
	PageSize int
}

// Store —— 审计存储抽象。
type Store interface {
	Append(ctx context.Context, e Entry) (int64, error)
	Query(ctx context.Context, f Filter) ([]Entry, int, error)
	Close() error
}

// MemStore —— 内存环形存储（开发/联调）。
type MemStore struct {
	mu      sync.Mutex
	entries []Entry
	nextID  int64
	max     int
}

// NewMemStore 构造内存存储（max ≤0 取 10000）。
func NewMemStore(max int) *MemStore {
	if max <= 0 {
		max = 10000
	}
	return &MemStore{max: max}
}

// Append 追加记录。
func (m *MemStore) Append(_ context.Context, e Entry) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.nextID++
	e.ID = m.nextID
	if e.Ts.IsZero() {
		e.Ts = time.Now()
	}
	m.entries = append(m.entries, e)
	if len(m.entries) > m.max {
		m.entries = m.entries[len(m.entries)-m.max:]
	}
	return e.ID, nil
}

// Query 查询（返回匹配总数 + 页数据，按 id 倒序）。
func (m *MemStore) Query(_ context.Context, f Filter) ([]Entry, int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var matched []Entry
	for _, e := range m.entries {
		if f.User != "" && e.User != f.User {
			continue
		}
		if f.Action != "" && e.Action != f.Action {
			continue
		}
		if !f.From.IsZero() && e.Ts.Before(f.From) {
			continue
		}
		if !f.To.IsZero() && e.Ts.After(f.To) {
			continue
		}
		matched = append(matched, e)
	}
	sort.Slice(matched, func(i, j int) bool { return matched[i].ID > matched[j].ID })
	total := len(matched)
	page, size := normalizePage(f)
	lo := page * size
	if lo >= total {
		return []Entry{}, total, nil
	}
	hi := lo + size
	if hi > total {
		hi = total
	}
	return append([]Entry(nil), matched[lo:hi]...), total, nil
}

// Close 关闭（内存实现为空）。
func (m *MemStore) Close() error { return nil }

// PGStore —— PostgreSQL audit_log 存储（DDL 属主 Master，docs/09 §7）。
type PGStore struct {
	pool *pgxpool.Pool
}

// NewPGStore 构造 PG 存储。
func NewPGStore(pool *pgxpool.Pool) *PGStore { return &PGStore{pool: pool} }

// Append 追加记录。
func (p *PGStore) Append(ctx context.Context, e Entry) (int64, error) {
	var ts any
	if !e.Ts.IsZero() {
		ts = e.Ts
	}
	var id int64
	err := p.pool.QueryRow(ctx, `
INSERT INTO audit_log(ts, user_name, tenant, action, resource, diff, ip, category, detail)
VALUES(COALESCE($1::timestamptz, now()), $2,$3,$4,$5,$6::jsonb,$7,$8,$9)
RETURNING id`,
		ts, e.User, e.Tenant, e.Action, e.Resource, emptyJSON(e.DiffJSON),
		e.IP, e.Category, e.DetailMsg).Scan(&id)
	if err != nil {
		return 0, fmt.Errorf("insert audit entry: %w", err)
	}
	return id, nil
}

// Query 查询。
func (p *PGStore) Query(ctx context.Context, f Filter) ([]Entry, int, error) {
	page, size := normalizePage(f)
	where := "WHERE TRUE"
	args := []any{}
	if f.User != "" {
		args = append(args, f.User)
		where += fmt.Sprintf(" AND user_name=$%d", len(args))
	}
	if f.Action != "" {
		args = append(args, f.Action)
		where += fmt.Sprintf(" AND action=$%d", len(args))
	}
	if !f.From.IsZero() {
		args = append(args, f.From)
		where += fmt.Sprintf(" AND ts >= $%d", len(args))
	}
	if !f.To.IsZero() {
		args = append(args, f.To)
		where += fmt.Sprintf(" AND ts <= $%d", len(args))
	}
	var total int
	if err := p.pool.QueryRow(ctx, `SELECT count(*) FROM audit_log `+where, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count audit: %w", err)
	}
	q := `SELECT id, ts, user_name, tenant, action, resource, COALESCE(diff::text,'{}'),
	             ip, category, COALESCE(detail,'')
	      FROM audit_log ` + where +
		fmt.Sprintf(` ORDER BY id DESC LIMIT $%d OFFSET $%d`, len(args)+1, len(args)+2)
	args = append(args, size, page*size)
	rows, err := p.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("query audit: %w", err)
	}
	defer rows.Close()
	var out []Entry
	for rows.Next() {
		var e Entry
		if err := rows.Scan(&e.ID, &e.Ts, &e.User, &e.Tenant, &e.Action, &e.Resource,
			&e.DiffJSON, &e.IP, &e.Category, &e.DetailMsg); err != nil {
			return nil, 0, fmt.Errorf("scan audit: %w", err)
		}
		out = append(out, e)
	}
	return out, total, rows.Err()
}

// Close 关闭连接池。
func (p *PGStore) Close() error { p.pool.Close(); return nil }

func normalizePage(f Filter) (page, size int) {
	page, size = f.Page, f.PageSize
	if page < 0 {
		page = 0
	}
	if size <= 0 || size > 500 {
		size = 50
	}
	return page, size
}

func emptyJSON(s string) string {
	if s == "" {
		return "{}"
	}
	return s
}
