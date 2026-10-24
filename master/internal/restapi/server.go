package restapi

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/SchearLoe/lucidnet/master/internal/assign"
	"github.com/SchearLoe/lucidnet/master/internal/audit"
	"github.com/SchearLoe/lucidnet/master/internal/auth"
	"github.com/SchearLoe/lucidnet/master/internal/config"
	"github.com/SchearLoe/lucidnet/master/internal/rbac"
	"github.com/SchearLoe/lucidnet/master/internal/registry"
)

// REST 管理 API（docs/09 §6：/api/v1/admin/*、/api/v1/auth/* 属主 Master；
// 响应信封 {code,msg,data}，docs/00 §6；网关反代到本服务，端口基线 9141）。

// Deps —— 依赖注入。
type Deps struct {
	Signer   *auth.Signer
	Users    rbac.Store
	Audit    audit.Store
	Config   *config.Store
	Registry *registry.Registry
	Assigner *assign.Assigner
	Hub      CmdHub
	Leader   func() bool
	Now      func() time.Time
}

// CmdHub —— 排水命令触发（避免依赖 internal/rpc 全量）。
type CmdHub interface {
	Push(nodeID string, c Cmd) error
}

// Cmd —— 与 internal/rpc.Cmd 同形（跨包最小依赖）。
type Cmd struct {
	ID          string    `json:"id,omitempty"`
	Type        string    `json:"type"`
	PayloadJSON string    `json:"payload"`
	CreatedAt   time.Time `json:"created_at"`
}

// Server —— HTTP 服务。
type Server struct {
	d   Deps
	mux *http.ServeMux
}

// NewServer 构造（路由注册见 routes.go）。
func NewServer(d Deps) *Server {
	if d.Now == nil {
		d.Now = time.Now
	}
	s := &Server{d: d}
	mux := http.NewServeMux()
	s.routes(mux)
	s.mux = mux
	return s
}

// Handler 返回带中间件的根 Handler。
func (s *Server) Handler() http.Handler {
	return s.withRecover(s.mux)
}

// ---------- 响应信封（docs/00 §6 {code,msg,data}） ----------

type envelope struct {
	Code int    `json:"code"`
	Msg  string `json:"msg"`
	Data any    `json:"data,omitempty"`
}

func writeOK(w http.ResponseWriter, data any) {
	writeJSON(w, http.StatusOK, envelope{Code: 0, Msg: "ok", Data: data})
}

func writeErr(w http.ResponseWriter, status, code int, msg string) {
	writeJSON(w, status, envelope{Code: code, Msg: msg})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func decodeBody(r *http.Request, v any) error {
	defer func() { _ = r.Body.Close() }()
	return json.NewDecoder(r.Body).Decode(v)
}

// ---------- 中间件 ----------

func (s *Server) withRecover(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				writeErr(w, http.StatusInternalServerError, 500, "internal error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

type ctxKeyType struct{}

var ctxKey ctxKeyType

// withAuth —— JWT 鉴权 + 权限点检查（docs/dd/07 §4 权限点；docs/11 §8 权限码）。
func (s *Server) withAuth(required string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		raw := r.Header.Get("Authorization")
		if !strings.HasPrefix(raw, "Bearer ") {
			writeErr(w, http.StatusUnauthorized, 401, "missing bearer token")
			return
		}
		claims, err := s.d.Signer.Verify(strings.TrimPrefix(raw, "Bearer "))
		if err != nil || claims.Typ != auth.TypAccess {
			writeErr(w, http.StatusUnauthorized, 401, "invalid token")
			return
		}
		perms := s.effectivePerms(r, claims)
		if !rbac.Allowed(perms, required) {
			writeErr(w, http.StatusForbidden, 403, "permission denied: "+required)
			return
		}
		next(w, r.WithContext(context.WithValue(r.Context(), ctxKey, claims)))
	}
}

// effectivePerms 汇总用户角色的权限点（平台管理员追加 "*" 全权，租户隔离豁免）。
func (s *Server) effectivePerms(r *http.Request, c *auth.Claims) []string {
	if c.PlatformAdmin {
		return []string{"*"}
	}
	u, err := s.d.Users.GetUserByName(r.Context(), c.UserName)
	if err != nil {
		return nil
	}
	perms := make([]string, 0, 8)
	roles, _ := s.d.Users.ListRoles(r.Context())
	for _, rn := range u.Roles {
		for _, role := range roles {
			if role.Name == rn {
				perms = append(perms, role.Perms...)
			}
		}
	}
	return dedupe(perms)
}

// claimsFrom 取请求上下文中的 JWT claims（withAuth 之后的 handler 内）。
func claimsFrom(r *http.Request) *auth.Claims {
	c, _ := r.Context().Value(ctxKey).(*auth.Claims)
	return c
}

// isPlatformAdmin 当前请求是否平台管理员（租户隔离豁免，docs/dd/07 §4）。
func isPlatformAdmin(r *http.Request) bool {
	c := claimsFrom(r)
	return c != nil && c.PlatformAdmin
}

// currentTenant 当前请求租户（非平台管理员生效；资源按 tenant 列过滤）。
func currentTenant(r *http.Request) string {
	c := claimsFrom(r)
	if c == nil || c.PlatformAdmin {
		return ""
	}
	return c.Tenant
}

// recordAudit 写审计（who/when/diff/ip，docs/hld/07 §4）。
func (s *Server) recordAudit(r *http.Request, action, resource, diffJSON, detail string) {
	c := claimsFrom(r)
	user := "system"
	tenant := ""
	if c != nil {
		user = c.UserName
		tenant = c.Tenant
	}
	_, _ = s.d.Audit.Append(r.Context(), audit.Entry{
		Ts:        s.d.Now(),
		User:      user,
		Tenant:    tenant,
		Action:    action,
		Resource:  resource,
		DiffJSON:  diffJSON,
		IP:        clientIP(r),
		Category:  "user",
		DetailMsg: detail,
	})
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// clientIP 提取来源 IP（审计用）。
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
