package rbac

import "time"

// 用户/租户/角色模型与权限点（docs/dd/07 §4；权限码命名规范 docs/11 §8：
// <domain>:<action>，domain 白名单 overview|analysis|flows|attack|policy|report|
// bgp|admin|zone|device|forward|audit|monitor|deploy，action 白名单
// read|edit|export|handle|manage|install|upgrade|rollback）。
//
// 四类预置角色：平台管理员（租户隔离豁免）/租户管理员/安全操作员/只读观察者。

// Tenant —— 租户（多租户隔离单元）。
type Tenant struct {
	ID        int64
	Name      string
	CreatedAt time.Time
}

// User —— 用户；TenantID=0 表示平台级账号（租户隔离豁免）。
type User struct {
	ID            int64
	TenantID      int64
	Tenant        string // 冗余租户名（JWT tenant claim）
	Name          string
	PassHash      string // pbkdf2 格式见 password.go
	PlatformAdmin bool
	Roles         []string
	CreatedAt     time.Time
}

// Role —— 角色；Perms 为权限点列表（支持 <domain>:<action> / <domain>:* / *）。
type Role struct {
	TenantID  int64
	Name      string
	Perms     []string
	Preset    bool
	CreatedAt time.Time
}

// 预置角色名。
const (
	RolePlatformAdmin   = "platform-admin"
	RoleTenantAdmin     = "tenant-admin"
	RoleSecurityOp      = "security-operator"
	RoleObserver        = "observer"
	PresetTenantID      = int64(0) // 预置角色挂在平台级（0）
	PlatformTenantLabel = "system" // 平台账号在 JWT tenant 中的占位
)

// PresetRoles —— 四类预置角色（docs/dd/07 §4）。
func PresetRoles() []Role {
	return []Role{
		{Name: RolePlatformAdmin, Perms: []string{"*"}, Preset: true},
		{
			Name: RoleTenantAdmin,
			Perms: []string{
				"overview:read", "analysis:read",
				"zone:read", "zone:edit",
				"device:read", "device:edit",
				"forward:read", "forward:edit",
				"policy:read", "policy:edit",
				"flows:read", "flows:export",
				"attack:read", "attack:handle",
				"report:read", "report:edit",
				"bgp:read",
				"audit:read", "monitor:read",
				"admin:read", "deploy:read",
			},
			Preset: true,
		},
		{
			Name: RoleSecurityOp,
			Perms: []string{
				"overview:read", "analysis:read",
				"zone:read", "device:read",
				"flows:read", "flows:export",
				"attack:read", "attack:handle",
				"bgp:read", "bgp:handle",
				"report:read", "monitor:read",
			},
			Preset: true,
		},
		{
			Name: RoleObserver,
			Perms: []string{
				"overview:read", "analysis:read", "zone:read", "device:read",
				"forward:read", "policy:read", "flows:read", "attack:read",
				"report:read", "bgp:read", "audit:read", "monitor:read",
				"admin:read", "deploy:read",
			},
			Preset: true,
		},
	}
}

// Allowed —— 权限判定：perms 中任一项匹配 required 即通过。
// 支持 "*"（全权）、"<domain>:*"；required 形如 "zone:edit"。
func Allowed(perms []string, required string) bool {
	for _, p := range perms {
		if p == "*" || p == required {
			return true
		}
		if len(p) > 1 && p[len(p)-1] == '*' && p[len(p)-2] == ':' {
			prefix := p[:len(p)-1] // "zone:"
			if len(required) >= len(prefix) && required[:len(prefix)] == prefix {
				return true
			}
		}
	}
	return false
}

// AllowedAll —— 所有 required 均满足才通过。
func AllowedAll(perms []string, required ...string) bool {
	for _, r := range required {
		if !Allowed(perms, r) {
			return false
		}
	}
	return true
}
