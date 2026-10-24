package config

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"sync"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ---------- 内存版本台账（开发/联调/单测） ----------

// MemVersions —— 内存版本台账。
type MemVersions struct {
	mu        sync.Mutex
	byScope   map[string][]Version
	summaries map[string]map[uint64]AckSummary
}

// NewMemVersions 构造。
func NewMemVersions() *MemVersions {
	return &MemVersions{byScope: map[string][]Version{}, summaries: map[string]map[uint64]AckSummary{}}
}

// SaveVersion 保存版本（按 version 升序维护）。
func (m *MemVersions) SaveVersion(_ context.Context, v Version, summary AckSummary) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	list := m.byScope[v.Scope]
	for _, old := range list {
		if old.Version == v.Version {
			return fmt.Errorf("version %d already exists for %s", v.Version, v.Scope)
		}
	}
	list = append(list, v)
	sort.Slice(list, func(i, j int) bool { return list[i].Version < list[j].Version })
	m.byScope[v.Scope] = list
	if m.summaries[v.Scope] == nil {
		m.summaries[v.Scope] = map[uint64]AckSummary{}
	}
	m.summaries[v.Scope][v.Version] = summary
	return nil
}

// GetVersion 查询版本。
func (m *MemVersions) GetVersion(_ context.Context, scope string, version uint64) (Version, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, v := range m.byScope[scope] {
		if v.Version == version {
			return v, nil
		}
	}
	return Version{}, ErrNotFound
}

// LatestVersion 最新版本。
func (m *MemVersions) LatestVersion(_ context.Context, scope string) (Version, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	list := m.byScope[scope]
	if len(list) == 0 {
		return Version{}, ErrNotFound
	}
	return list[len(list)-1], nil
}

// ListVersions 版本历史（新→旧）。
func (m *MemVersions) ListVersions(_ context.Context, scope string, limit int) ([]Version, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	list := append([]Version(nil), m.byScope[scope]...)
	out := make([]Version, 0, len(list))
	for i := len(list) - 1; i >= 0 && len(out) < limit; i-- {
		out = append(out, list[i])
	}
	return out, nil
}

// SetVersionState 更新版本状态。
func (m *MemVersions) SetVersionState(_ context.Context, scope string, version uint64, st VersionState, summary AckSummary) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := range m.byScope[scope] {
		if m.byScope[scope][i].Version == version {
			m.byScope[scope][i].State = st
			m.summaries[scope][version] = summary
			return nil
		}
	}
	return ErrNotFound
}

// TrimVersions 保留最近 keep 个版本。
func (m *MemVersions) TrimVersions(_ context.Context, scope string, keep int) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	list := m.byScope[scope]
	if len(list) > keep {
		list = append([]Version(nil), list[len(list)-keep:]...)
		m.byScope[scope] = list
	}
	return nil
}

// Close 关闭（内存实现为空）。
func (m *MemVersions) Close() error { return nil }

var _ VersionsStore = (*MemVersions)(nil)

// ---------- PG 版本台账（config_versions 表，权威） ----------

// PGVersions —— PostgreSQL 版本台账。
type PGVersions struct {
	pool *pgxpool.Pool
}

// NewPGVersions 构造。
func NewPGVersions(pool *pgxpool.Pool) *PGVersions { return &PGVersions{pool: pool} }

// SaveVersion 保存版本记录。
func (p *PGVersions) SaveVersion(ctx context.Context, v Version, summary AckSummary) error {
	summaryJSON, err := json.Marshal(summary)
	if err != nil {
		return fmt.Errorf("marshal ack summary: %w", err)
	}
	_, err = p.pool.Exec(ctx, `
INSERT INTO config_versions(scope, version, state, data, created_by, created_at, ack_summary, rollback_of)
VALUES($1,$2,$3,$4::jsonb,$5,$6,$7::jsonb,$8)`,
		v.Scope, v.Version, string(v.State), string(v.DataJSON), v.CreatedBy, v.CreatedAt,
		string(summaryJSON), v.RollbackOf)
	if err != nil {
		return fmt.Errorf("insert config version %s v%d: %w", v.Scope, v.Version, err)
	}
	return nil
}

// GetVersion 查询版本。
func (p *PGVersions) GetVersion(ctx context.Context, scope string, version uint64) (Version, error) {
	var v Version
	var state, data, summary string
	var createdBy string
	var rollbackOf *uint64
	err := p.pool.QueryRow(ctx, `
SELECT scope, version, state, data::text, created_by, created_at, ack_summary::text, rollback_of
FROM config_versions WHERE scope=$1 AND version=$2`, scope, version).
		Scan(&v.Scope, &v.Version, &state, &data, &createdBy, &v.CreatedAt, &summary, &rollbackOf)
	if errors.Is(err, pgx.ErrNoRows) {
		return Version{}, ErrNotFound
	}
	if err != nil {
		return Version{}, fmt.Errorf("query config version %s v%d: %w", scope, version, err)
	}
	v.State, v.DataJSON, v.CreatedBy = VersionState(state), []byte(data), createdBy
	if rollbackOf != nil {
		v.RollbackOf = *rollbackOf
	}
	_ = json.Unmarshal([]byte(summary), new(AckSummary)) // summary 仅为展示辅助
	return v, nil
}

// LatestVersion 最新版本。
func (p *PGVersions) LatestVersion(ctx context.Context, scope string) (Version, error) {
	var v Version
	var state, data string
	var createdBy string
	var summary string
	var rollbackOf *uint64
	err := p.pool.QueryRow(ctx, `
SELECT scope, version, state, data::text, created_by, created_at, ack_summary::text, rollback_of
FROM config_versions WHERE scope=$1 ORDER BY version DESC LIMIT 1`, scope).
		Scan(&v.Scope, &v.Version, &state, &data, &createdBy, &v.CreatedAt, &summary, &rollbackOf)
	if errors.Is(err, pgx.ErrNoRows) {
		return Version{}, ErrNotFound
	}
	if err != nil {
		return Version{}, fmt.Errorf("query latest config version %s: %w", scope, err)
	}
	v.State, v.DataJSON, v.CreatedBy = VersionState(state), []byte(data), createdBy
	if rollbackOf != nil {
		v.RollbackOf = *rollbackOf
	}
	return v, nil
}

// ListVersions 版本历史（新→旧）。
func (p *PGVersions) ListVersions(ctx context.Context, scope string, limit int) ([]Version, error) {
	rows, err := p.pool.Query(ctx, `
SELECT scope, version, state, data::text, created_by, created_at, rollback_of
FROM config_versions WHERE scope=$1 ORDER BY version DESC LIMIT $2`, scope, limit)
	if err != nil {
		return nil, fmt.Errorf("query config versions %s: %w", scope, err)
	}
	defer rows.Close()
	var out []Version
	for rows.Next() {
		var v Version
		var rollbackOf *uint64
		if err := rows.Scan(&v.Scope, &v.Version, &v.State, &v.DataJSON,
			&v.CreatedBy, &v.CreatedAt, &rollbackOf); err != nil {
			return nil, fmt.Errorf("scan config version: %w", err)
		}
		if rollbackOf != nil {
			v.RollbackOf = *rollbackOf
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// SetVersionState 更新版本状态与 ACK 汇总。
func (p *PGVersions) SetVersionState(ctx context.Context, scope string, version uint64, st VersionState, summary AckSummary) error {
	summaryJSON, err := json.Marshal(summary)
	if err != nil {
		return fmt.Errorf("marshal ack summary: %w", err)
	}
	tag, err := p.pool.Exec(ctx,
		`UPDATE config_versions SET state=$3, ack_summary=$4::jsonb WHERE scope=$1 AND version=$2`,
		scope, version, string(st), string(summaryJSON))
	if err != nil {
		return fmt.Errorf("update config version %s v%d: %w", scope, version, err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// TrimVersions 保留最近 keep 个版本（低水位裁剪）。
func (p *PGVersions) TrimVersions(ctx context.Context, scope string, keep int) error {
	_, err := p.pool.Exec(ctx, `
DELETE FROM config_versions
WHERE scope=$1 AND version <= (
  SELECT COALESCE(MIN(version),0) FROM (
    SELECT version FROM config_versions WHERE scope=$1 ORDER BY version DESC LIMIT $2
  ) recent)`, scope, keep)
	if err != nil {
		return fmt.Errorf("trim config versions %s: %w", scope, err)
	}
	return nil
}

// Close 关闭连接池。
func (p *PGVersions) Close() error { p.pool.Close(); return nil }

var _ VersionsStore = (*PGVersions)(nil)
