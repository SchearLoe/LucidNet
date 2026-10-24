package rbac

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrNotFound —— 资源不存在。
var ErrNotFound = errors.New("rbac: not found")

// Store —— 用户/租户/角色存储抽象（内存实现为开发/联调桩；PG 为生产权威）。
type Store interface {
	SeedDefaults(ctx context.Context, adminUser, adminPassHash string) error
	GetUserByName(ctx context.Context, name string) (User, error)
	ListUsers(ctx context.Context) ([]User, error)
	CreateUser(ctx context.Context, u User, passHash string) (User, error)
	DeleteUser(ctx context.Context, name string) error
	ListTenants(ctx context.Context) ([]Tenant, error)
	CreateTenant(ctx context.Context, name string) (Tenant, error)
	DeleteTenant(ctx context.Context, name string) error
	ListRoles(ctx context.Context) ([]Role, error)
	UpsertRole(ctx context.Context, r Role) (Role, error)
	Close() error
}

// ---------- 内存实现（开发模式 / 单测） ----------

// MemStore —— 内存存储。
type MemStore struct {
	mu      sync.RWMutex
	tenants map[string]Tenant
	users   map[string]User
	roles   map[string]Role
	nextID  int64
}

// NewMemStore 构造内存存储。
func NewMemStore() *MemStore {
	return &MemStore{
		tenants: map[string]Tenant{},
		users:   map[string]User{},
		roles:   map[string]Role{},
	}
}

func (m *MemStore) allocID() int64 {
	m.nextID++
	return m.nextID
}

// SeedDefaults 预置角色与平台管理员（幂等：已存在则跳过）。
func (m *MemStore) SeedDefaults(_ context.Context, adminUser, adminPassHash string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, r := range PresetRoles() {
		if _, ok := m.roles[r.Name]; !ok {
			r.TenantID = PresetTenantID
			r.CreatedAt = time.Now()
			m.roles[r.Name] = r
		}
	}
	if _, ok := m.users[adminUser]; !ok {
		m.users[adminUser] = User{
			ID: m.allocID(), TenantID: 0, Tenant: PlatformTenantLabel,
			Name: adminUser, PassHash: adminPassHash, PlatformAdmin: true,
			Roles: []string{RolePlatformAdmin}, CreatedAt: time.Now(),
		}
	}
	return nil
}

// GetUserByName 按用户名取用户。
func (m *MemStore) GetUserByName(_ context.Context, name string) (User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	u, ok := m.users[name]
	if !ok {
		return User{}, ErrNotFound
	}
	return u, nil
}

// ListUsers 列出全部用户。
func (m *MemStore) ListUsers(_ context.Context) ([]User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]User, 0, len(m.users))
	for _, u := range m.users {
		u.PassHash = ""
		out = append(out, u)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// CreateUser 创建用户。
func (m *MemStore) CreateUser(_ context.Context, u User, passHash string) (User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.users[u.Name]; ok {
		return User{}, fmt.Errorf("user %q already exists", u.Name)
	}
	u.ID = m.allocID()
	u.PassHash = passHash
	u.CreatedAt = time.Now()
	m.users[u.Name] = u
	u.PassHash = ""
	return u, nil
}

// DeleteUser 删除用户。
func (m *MemStore) DeleteUser(_ context.Context, name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.users[name]; !ok {
		return ErrNotFound
	}
	delete(m.users, name)
	return nil
}

// ListTenants 列出租户。
func (m *MemStore) ListTenants(_ context.Context) ([]Tenant, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]Tenant, 0, len(m.tenants))
	for _, t := range m.tenants {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// CreateTenant 创建租户。
func (m *MemStore) CreateTenant(_ context.Context, name string) (Tenant, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.tenants[name]; ok {
		return Tenant{}, fmt.Errorf("tenant %q already exists", name)
	}
	t := Tenant{ID: m.allocID(), Name: name, CreatedAt: time.Now()}
	m.tenants[name] = t
	return t, nil
}

// DeleteTenant 删除租户。
func (m *MemStore) DeleteTenant(_ context.Context, name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.tenants[name]; !ok {
		return ErrNotFound
	}
	delete(m.tenants, name)
	return nil
}

// ListRoles 列出角色。
func (m *MemStore) ListRoles(_ context.Context) ([]Role, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]Role, 0, len(m.roles))
	for _, r := range m.roles {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// UpsertRole 创建/更新角色。
func (m *MemStore) UpsertRole(_ context.Context, r Role) (Role, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if old, ok := m.roles[r.Name]; ok && old.Preset {
		return Role{}, fmt.Errorf("role %q is preset and immutable", r.Name)
	}
	r.CreatedAt = time.Now()
	m.roles[r.Name] = r
	return r, nil
}

// Close 关闭（内存实现为空）。
func (m *MemStore) Close() error { return nil }

// ---------- PG 实现（生产权威） ----------

// PGStore —— PostgreSQL 存储（DDL 见模块 migrations/0001_master_mvp.sql）。
type PGStore struct {
	pool *pgxpool.Pool
}

// NewPGStore 基于 pgxpool 构造。
func NewPGStore(pool *pgxpool.Pool) *PGStore {
	return &PGStore{pool: pool}
}

// SeedDefaults 预置角色与平台管理员（幂等）。
func (p *PGStore) SeedDefaults(ctx context.Context, adminUser, adminPassHash string) error {
	for _, r := range PresetRoles() {
		perms, err := jsonMarshal(r.Perms)
		if err != nil {
			return fmt.Errorf("marshal perms for %s: %w", r.Name, err)
		}
		if _, err := p.pool.Exec(ctx, `
INSERT INTO roles(tenant_id, name, perms, preset) VALUES($1,$2,$3,TRUE)
ON CONFLICT (tenant_id, name) DO NOTHING`, PresetTenantID, r.Name, perms); err != nil {
			return fmt.Errorf("seed role %s: %w", r.Name, err)
		}
	}
	var uid int64
	err := p.pool.QueryRow(ctx, `SELECT id FROM users WHERE name=$1`, adminUser).Scan(&uid)
	if errors.Is(err, pgx.ErrNoRows) {
		err = p.pool.QueryRow(ctx, `
INSERT INTO users(tenant_id, name, passwd_hash, is_platform_admin)
VALUES(0,$1,$2,TRUE) RETURNING id`, adminUser, adminPassHash).Scan(&uid)
		if err != nil {
			return fmt.Errorf("seed admin user: %w", err)
		}
		var rid int64
		if err := p.pool.QueryRow(ctx,
			`SELECT id FROM roles WHERE tenant_id=0 AND name=$1`, RolePlatformAdmin).Scan(&rid); err != nil {
			return fmt.Errorf("seed admin role lookup: %w", err)
		}
		if _, err := p.pool.Exec(ctx,
			`INSERT INTO user_roles(user_id, role_id) VALUES($1,$2) ON CONFLICT DO NOTHING`, uid, rid); err != nil {
			return fmt.Errorf("seed admin user_roles: %w", err)
		}
	} else if err != nil {
		return fmt.Errorf("lookup admin user: %w", err)
	}
	return nil
}

// GetUserByName 按用户名取用户（含角色名列表）。
func (p *PGStore) GetUserByName(ctx context.Context, name string) (User, error) {
	var u User
	var roles []byte
	err := p.pool.QueryRow(ctx, `
SELECT u.id, u.tenant_id, COALESCE(t.name,''), u.name, u.passwd_hash, u.is_platform_admin,
       COALESCE((SELECT json_agg(r.name) FROM user_roles ur JOIN roles r ON r.id=ur.role_id
                 WHERE ur.user_id=u.id), '[]'::jsonb)
FROM users u LEFT JOIN tenants t ON t.id=u.tenant_id
WHERE u.name=$1`, name).Scan(
		&u.ID, &u.TenantID, &u.Tenant, &u.Name, &u.PassHash, &u.PlatformAdmin, &roles)
	if errors.Is(err, pgx.ErrNoRows) {
		return User{}, ErrNotFound
	}
	if err != nil {
		return User{}, fmt.Errorf("query user %s: %w", name, err)
	}
	u.Roles, err = jsonUnmarshalStrings(roles)
	if err != nil {
		return User{}, fmt.Errorf("decode roles for %s: %w", name, err)
	}
	if u.PlatformAdmin && u.Tenant == "" {
		u.Tenant = PlatformTenantLabel
	}
	return u, nil
}

// ListUsers 列出用户。
func (p *PGStore) ListUsers(ctx context.Context) ([]User, error) {
	rows, err := p.pool.Query(ctx, `
SELECT u.id, u.tenant_id, COALESCE(t.name,''), u.name, u.is_platform_admin, u.created_at,
       COALESCE((SELECT json_agg(r.name) FROM user_roles ur JOIN roles r ON r.id=ur.role_id
                 WHERE ur.user_id=u.id), '[]'::jsonb)
FROM users u LEFT JOIN tenants t ON t.id=u.tenant_id
ORDER BY u.id`)
	if err != nil {
		return nil, fmt.Errorf("query users: %w", err)
	}
	defer rows.Close()
	var out []User
	for rows.Next() {
		var u User
		var roles []byte
		if err := rows.Scan(&u.ID, &u.TenantID, &u.Tenant, &u.Name, &u.PlatformAdmin,
			&u.CreatedAt, &roles); err != nil {
			return nil, fmt.Errorf("scan user: %w", err)
		}
		if u.Roles, err = jsonUnmarshalStrings(roles); err != nil {
			return nil, fmt.Errorf("decode roles: %w", err)
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// CreateUser 创建用户（含角色绑定）。
func (p *PGStore) CreateUser(ctx context.Context, u User, passHash string) (User, error) {
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return User{}, fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	err = tx.QueryRow(ctx, `
INSERT INTO users(tenant_id, name, passwd_hash, is_platform_admin)
VALUES($1,$2,$3,$4) RETURNING id, created_at`,
		u.TenantID, u.Name, passHash, u.PlatformAdmin).Scan(&u.ID, &u.CreatedAt)
	if err != nil {
		return User{}, fmt.Errorf("insert user: %w", err)
	}
	for _, rn := range u.Roles {
		if _, err := tx.Exec(ctx, `
INSERT INTO user_roles(user_id, role_id)
SELECT $1, r.id FROM roles r WHERE r.name=$2 AND (r.tenant_id=0 OR r.tenant_id=$1)
ON CONFLICT DO NOTHING`, u.ID, rn); err != nil {
			return User{}, fmt.Errorf("bind role %s: %w", rn, err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return User{}, fmt.Errorf("commit: %w", err)
	}
	u.PassHash = ""
	return u, nil
}

// DeleteUser 删除用户。
func (p *PGStore) DeleteUser(ctx context.Context, name string) error {
	tag, err := p.pool.Exec(ctx, `DELETE FROM users WHERE name=$1`, name)
	if err != nil {
		return fmt.Errorf("delete user: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ListTenants 列出租户。
func (p *PGStore) ListTenants(ctx context.Context) ([]Tenant, error) {
	rows, err := p.pool.Query(ctx, `SELECT id, name, created_at FROM tenants ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("query tenants: %w", err)
	}
	defer rows.Close()
	var out []Tenant
	for rows.Next() {
		var t Tenant
		if err := rows.Scan(&t.ID, &t.Name, &t.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan tenant: %w", err)
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// CreateTenant 创建租户。
func (p *PGStore) CreateTenant(ctx context.Context, name string) (Tenant, error) {
	var t Tenant
	err := p.pool.QueryRow(ctx,
		`INSERT INTO tenants(name) VALUES($1) RETURNING id, name, created_at`, name).
		Scan(&t.ID, &t.Name, &t.CreatedAt)
	if err != nil {
		return Tenant{}, fmt.Errorf("insert tenant: %w", err)
	}
	return t, nil
}

// DeleteTenant 删除租户。
func (p *PGStore) DeleteTenant(ctx context.Context, name string) error {
	tag, err := p.pool.Exec(ctx, `DELETE FROM tenants WHERE name=$1`, name)
	if err != nil {
		return fmt.Errorf("delete tenant: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ListRoles 列出角色。
func (p *PGStore) ListRoles(ctx context.Context) ([]Role, error) {
	rows, err := p.pool.Query(ctx,
		`SELECT tenant_id, name, perms, preset, created_at FROM roles ORDER BY tenant_id, name`)
	if err != nil {
		return nil, fmt.Errorf("query roles: %w", err)
	}
	defer rows.Close()
	var out []Role
	for rows.Next() {
		var r Role
		var perms []byte
		if err := rows.Scan(&r.TenantID, &r.Name, &perms, &r.Preset, &r.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan role: %w", err)
		}
		if r.Perms, err = jsonUnmarshalStrings(perms); err != nil {
			return nil, fmt.Errorf("decode perms: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// UpsertRole 创建/更新角色（预置角色不可改）。
func (p *PGStore) UpsertRole(ctx context.Context, r Role) (Role, error) {
	perms, err := jsonMarshal(r.Perms)
	if err != nil {
		return Role{}, fmt.Errorf("marshal perms: %w", err)
	}
	var preset bool
	err = p.pool.QueryRow(ctx, `SELECT preset FROM roles WHERE tenant_id=$1 AND name=$2`,
		r.TenantID, r.Name).Scan(&preset)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return Role{}, fmt.Errorf("lookup role: %w", err)
	}
	if err == nil && preset {
		return Role{}, fmt.Errorf("role %q is preset and immutable", r.Name)
	}
	err = p.pool.QueryRow(ctx, `
INSERT INTO roles(tenant_id, name, perms, preset) VALUES($1,$2,$3,$4)
ON CONFLICT (tenant_id, name) DO UPDATE SET perms=EXCLUDED.perms
RETURNING created_at`, r.TenantID, r.Name, perms, r.Preset).Scan(&r.CreatedAt)
	if err != nil {
		return Role{}, fmt.Errorf("upsert role: %w", err)
	}
	return r, nil
}

// Close 关闭连接池。
func (p *PGStore) Close() error { p.pool.Close(); return nil }
