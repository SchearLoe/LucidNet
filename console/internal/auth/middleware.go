package auth

import (
	"context"
	"net/http"
	"strings"
)

// Identity —— 请求级身份（网关校验后注入，docs/dd/07：租户注入）。
type Identity struct {
	UID    string
	Tenant string
	Roles  []string
	Perms  map[Permission]bool
	// PermsKnown 标记 claims 是否携带 perms；未携带时严格模式拒绝授权检查。
	PermsKnown bool
}

// HasPerm 判断身份是否持有权限码。
func (id *Identity) HasPerm(p Permission) bool { return id.Perms[p] }

// WithIdentity 将身份写入 context。
func WithIdentity(ctx context.Context, id *Identity) context.Context {
	return context.WithValue(ctx, identityKey{}, id)
}

// IdentityFrom 取请求身份；未鉴权返回 nil。
func IdentityFrom(ctx context.Context) *Identity {
	id, _ := ctx.Value(identityKey{}).(*Identity)
	return id
}

type identityKey struct{}

type deniedPermKey struct{}

// DeniedPerm —— RequirePerm 拒绝时把权限码写入 context（供 403 响应渲染）。
func DeniedPerm(ctx context.Context) (Permission, bool) {
	p, ok := ctx.Value(deniedPermKey{}).(Permission)
	return p, ok
}

// Middleware —— JWT 鉴权中间件（docs/dd/07：HS256，网关校验并注入租户）。
type Middleware struct {
	verifier *Verifier
	strict   bool
	// unauthorized 渲染 401（统一信封由 httpapi 注入）。
	unauthorized func(w http.ResponseWriter, r *http.Request, err error)
	// forbidden 渲染 403（ctx 已含 DeniedPerm）。
	forbidden func(w http.ResponseWriter, r *http.Request)
}

// NewMiddleware 构造鉴权中间件；渲染回调由 httpapi 提供统一 {code,msg,data} 信封。
func NewMiddleware(v *Verifier, strict bool,
	unauthorized func(w http.ResponseWriter, r *http.Request, err error),
	forbidden func(w http.ResponseWriter, r *http.Request),
) *Middleware {
	return &Middleware{verifier: v, strict: strict, unauthorized: unauthorized, forbidden: forbidden}
}

// Wrap 返回鉴权中间件包装的 handler（所有 /api/v1 业务路由要求登录）。
func (m *Middleware) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw := bearerToken(r)
		if raw == "" {
			m.unauthorized(w, r, ErrInvalidToken)
			return
		}
		claims, err := m.verifier.Verify(raw)
		if err != nil {
			m.unauthorized(w, r, err)
			return
		}
		perms := make(map[Permission]bool, len(claims.Perms))
		for _, p := range claims.Perms {
			perms[Permission(p)] = true
		}
		id := &Identity{
			UID:        claims.UID,
			Tenant:     claims.Tenant,
			Roles:      claims.Roles,
			Perms:      perms,
			PermsKnown: len(claims.Perms) > 0,
		}
		next.ServeHTTP(w, r.WithContext(WithIdentity(r.Context(), id)))
	})
}

// RequirePerm —— 接口级权限检查（docs/11 §8 <domain>:<action>）。
// 严格模式：claims 未携带 perms 即拒绝（Master 未签发 perms 时应回退 RBAC 查询，见 TODO）。
// 宽松模式（LUCID_CONSOLE_AUTH_STRICT=false，仅联调）：未携带 perms 放行。
func (m *Middleware) RequirePerm(p Permission, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := IdentityFrom(r.Context())
		if id == nil {
			// RequirePerm 必须挂在 Wrap 之后；防御性兜底（未鉴权）。
			m.unauthorized(w, r, ErrInvalidToken)
			return
		}
		allowed := false
		switch {
		case id.PermsKnown:
			allowed = id.HasPerm(p)
		case !m.strict:
			allowed = true
		}
		if !allowed {
			ctx := context.WithValue(r.Context(), deniedPermKey{}, p)
			m.forbidden(w, r.WithContext(ctx))
			return
		}
		next.ServeHTTP(w, r)
	})
}

// bearerToken 提取 token：优先 Authorization: Bearer xxx，回退 ?access_token=（浏览器 WS 无法带 header）。
func bearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if strings.HasPrefix(h, "Bearer ") {
		return strings.TrimSpace(strings.TrimPrefix(h, "Bearer "))
	}
	return strings.TrimSpace(r.URL.Query().Get("access_token"))
}
