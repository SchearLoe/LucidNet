package registry

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PGStore —— PostgreSQL 台账（nodes/exporters 表；DDL 见模块 migrations）。
type PGStore struct {
	pool *pgxpool.Pool
}

// NewPGStore 构造 PG 台账。
func NewPGStore(pool *pgxpool.Pool) *PGStore { return &PGStore{pool: pool} }

// UpsertNode 写入节点档案（保留 joined_at/last_hb 等运行时列）。
func (p *PGStore) UpsertNode(ctx context.Context, n Node) (bool, error) {
	nics, err := json.Marshal(n.NICs)
	if err != nil {
		return false, fmt.Errorf("marshal nics for %s: %w", n.ID, err)
	}
	var created bool
	err = p.pool.QueryRow(ctx, `
INSERT INTO nodes(id, role, host, cores, mem_gb, nics, state, weight_override)
VALUES($1,$2,$3,$4,$5,$6::jsonb,$7,$8)
ON CONFLICT (id) DO UPDATE SET
  role=EXCLUDED.role, host=EXCLUDED.host, cores=EXCLUDED.cores, mem_gb=EXCLUDED.mem_gb,
  nics=EXCLUDED.nics, weight_override=EXCLUDED.weight_override
RETURNING (xmax = 0) AS created`,
		n.ID, string(n.Role), n.Host, n.Cores, n.MemGB, string(nics),
		string(StateOnline), n.WeightOverride).Scan(&created)
	if err != nil {
		return false, fmt.Errorf("upsert node %s: %w", n.ID, err)
	}
	return created, nil
}

// GetNode 读取节点。
func (p *PGStore) GetNode(ctx context.Context, id string) (Node, error) {
	var n Node
	if err := scanNode(p.pool.QueryRow(ctx, nodeSelect+` WHERE id=$1`, id), &n); err != nil {
		return Node{}, err
	}
	return n, nil
}

const nodeSelect = `
SELECT id, role, host, cores, mem_gb, COALESCE(nics::text,'[]'), state, degraded,
       version, weight_override, COALESCE(joined_at,'epoch'::timestamptz), COALESCE(last_hb,'epoch'::timestamptz)
FROM nodes`

// ListNodes 列出节点。
func (p *PGStore) ListNodes(ctx context.Context) ([]Node, error) {
	rows, err := p.pool.Query(ctx, nodeSelect+` ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("query nodes: %w", err)
	}
	defer rows.Close()
	var out []Node
	for rows.Next() {
		var n Node
		if err := scanNode(rows, &n); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

type rowScanner interface{ Scan(dest ...any) error }

func scanNode(r rowScanner, n *Node) error {
	var role, state, nics string
	var joined, lastHB time.Time
	if err := r.Scan(&n.ID, &role, &n.Host, &n.Cores, &n.MemGB, &nics, &state, &n.Degraded,
		&n.Version, &n.WeightOverride, &joined, &lastHB); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		return fmt.Errorf("scan node: %w", err)
	}
	n.Role, n.State = Role(role), State(state)
	if err := json.Unmarshal([]byte(nics), &n.NICs); err != nil {
		return fmt.Errorf("decode nics for %s: %w", n.ID, err)
	}
	if !joined.IsZero() && joined.Unix() != 0 {
		n.JoinedAt = joined
	}
	if !lastHB.IsZero() && lastHB.Unix() != 0 {
		n.LastHB = lastHB
	}
	return nil
}

// SetNodeState 状态迁移。
func (p *PGStore) SetNodeState(ctx context.Context, id string, st State) error {
	tag, err := p.pool.Exec(ctx, `UPDATE nodes SET state=$2 WHERE id=$1`, id, string(st))
	if err != nil {
		return fmt.Errorf("set node %s state: %w", id, err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// SetNodeHB 心跳落账。
func (p *PGStore) SetNodeHB(ctx context.Context, id string, ts time.Time, degraded bool, version string) error {
	tag, err := p.pool.Exec(ctx, `
UPDATE nodes SET last_hb=$2, degraded=$3,
                 version=CASE WHEN $4<>'' THEN $4 ELSE version END
WHERE id=$1`, id, ts, degraded, version)
	if err != nil {
		return fmt.Errorf("set node %s hb: %w", id, err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// SetNodeWeightOverride 设置权重覆盖。
func (p *PGStore) SetNodeWeightOverride(ctx context.Context, id string, w float64) error {
	tag, err := p.pool.Exec(ctx, `UPDATE nodes SET weight_override=$2 WHERE id=$1`, id, w)
	if err != nil {
		return fmt.Errorf("set node %s weight: %w", id, err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// UpsertExporter 写入 exporter 档案。
func (p *PGStore) UpsertExporter(ctx context.Context, e Exporter) error {
	_, err := p.pool.Exec(ctx, `
INSERT INTO exporters(ip, device_id, last_seen, rate_fps, pinned_collector, active_set)
VALUES($1,$2,$3,$4,$5,$6)
ON CONFLICT (ip) DO UPDATE SET
  device_id=EXCLUDED.device_id, pinned_collector=EXCLUDED.pinned_collector,
  active_set=EXCLUDED.active_set`,
		e.IP, e.DeviceID, nullableTime(e.LastSeen), e.RateFPS, e.PinnedTo, e.ActiveSet)
	if err != nil {
		return fmt.Errorf("upsert exporter %s: %w", e.IP, err)
	}
	return nil
}

// GetExporter 读取 exporter。
func (p *PGStore) GetExporter(ctx context.Context, ip string) (Exporter, error) {
	var e Exporter
	var seen *time.Time
	err := p.pool.QueryRow(ctx, `
SELECT ip, device_id, last_seen, rate_fps, pinned_collector, active_set
FROM exporters WHERE ip=$1`, ip).
		Scan(&e.IP, &e.DeviceID, &seen, &e.RateFPS, &e.PinnedTo, &e.ActiveSet)
	if errors.Is(err, pgx.ErrNoRows) {
		return Exporter{}, ErrNotFound
	}
	if err != nil {
		return Exporter{}, fmt.Errorf("query exporter %s: %w", ip, err)
	}
	if seen != nil {
		e.LastSeen = *seen
	}
	return e, nil
}

// ListExporters 列出全部 exporter。
func (p *PGStore) ListExporters(ctx context.Context) ([]Exporter, error) {
	rows, err := p.pool.Query(ctx, `
SELECT ip, device_id, last_seen, rate_fps, pinned_collector, active_set
FROM exporters ORDER BY ip`)
	if err != nil {
		return nil, fmt.Errorf("query exporters: %w", err)
	}
	defer rows.Close()
	var out []Exporter
	for rows.Next() {
		var e Exporter
		var seen *time.Time
		if err := rows.Scan(&e.IP, &e.DeviceID, &seen, &e.RateFPS, &e.PinnedTo, &e.ActiveSet); err != nil {
			return nil, fmt.Errorf("scan exporter: %w", err)
		}
		if seen != nil {
			e.LastSeen = *seen
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// MarkExporterSeen 观测更新（保留 pin/active_set/device_id）。
func (p *PGStore) MarkExporterSeen(ctx context.Context, ip string, ts time.Time, fps float64) error {
	_, err := p.pool.Exec(ctx, `
INSERT INTO exporters(ip, last_seen, rate_fps) VALUES($1,$2,$3)
ON CONFLICT (ip) DO UPDATE SET last_seen=EXCLUDED.last_seen, rate_fps=EXCLUDED.rate_fps`,
		ip, ts, fps)
	if err != nil {
		return fmt.Errorf("mark exporter %s seen: %w", ip, err)
	}
	return nil
}

// SetExporterPin 设置/清除 pin。
func (p *PGStore) SetExporterPin(ctx context.Context, ip, collectorNodeID string) error {
	tag, err := p.pool.Exec(ctx,
		`UPDATE exporters SET pinned_collector=$2 WHERE ip=$1`, ip, collectorNodeID)
	if err != nil {
		return fmt.Errorf("pin exporter %s: %w", ip, err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// Close 关闭连接池。
func (p *PGStore) Close() error { p.pool.Close(); return nil }

func nullableTime(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t
}

// CompileAssert PG 实现满足接口。
var _ Store = (*PGStore)(nil)
