package restapi

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/SchearLoe/lucidnet/master/internal/audit"
	"github.com/SchearLoe/lucidnet/master/internal/auth"
	"github.com/SchearLoe/lucidnet/master/internal/rbac"
)

// 认证接口（docs/09 §6 /api/v1/auth/*；JWT 15min + 刷新，docs/hld/07 §2）。

type loginReq struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type tokenPair struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"` // access 有效期（秒）
}

// handleLogin 登录签发 JWT（claims {uid, tenant, roles, perms, exp}，docs/dd/07 §4）。
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req loginReq
	if err := decodeBody(r, &req); err != nil || req.Username == "" || req.Password == "" {
		writeErr(w, http.StatusBadRequest, 400, "username and password required")
		return
	}
	u, err := s.d.Users.GetUserByName(r.Context(), req.Username)
	if err != nil {
		if errors.Is(err, rbac.ErrNotFound) {
			s.recordLogin(r, req.Username, false)
			writeErr(w, http.StatusUnauthorized, 401, "invalid credentials")
			return
		}
		writeErr(w, http.StatusInternalServerError, 500, "query user failed")
		return
	}
	ok, err := rbac.VerifyPassword(req.Password, u.PassHash)
	if err != nil || !ok {
		s.recordLogin(r, req.Username, false)
		writeErr(w, http.StatusUnauthorized, 401, "invalid credentials")
		return
	}
	pair, err := s.issueTokens(r.Context(), u)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, 500, "sign token failed")
		return
	}
	s.recordLogin(r, req.Username, true)
	writeOK(w, pair)
}

// handleRefresh 刷新 access token（refresh token 单独 typ 校验）。
func (s *Server) handleRefresh(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := decodeBody(r, &req); err != nil || req.RefreshToken == "" {
		writeErr(w, http.StatusBadRequest, 400, "refresh_token required")
		return
	}
	claims, err := s.d.Signer.Verify(req.RefreshToken)
	if err != nil || claims.Typ != auth.TypRefresh {
		writeErr(w, http.StatusUnauthorized, 401, "invalid refresh token")
		return
	}
	u, err := s.d.Users.GetUserByName(r.Context(), claims.UserName)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, 401, "user disabled or removed")
		return
	}
	pair, err := s.issueTokens(r.Context(), u)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, 500, "sign token failed")
		return
	}
	writeOK(w, pair)
}

// handleMe 当前用户信息。
func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	c := claimsFrom(r)
	writeOK(w, map[string]any{
		"uid":            c.UID,
		"username":       c.UserName,
		"tenant":         c.Tenant,
		"roles":          c.Roles,
		"platform_admin": c.PlatformAdmin,
	})
}

// issueTokens 签发 access+refresh 令牌对；perms 由角色台账实时展开写入
// （登录与刷新同路径，刷新时按当前角色台账重算，docs/dd/07 §4）。
// 台账读取失败不阻塞签发：perms 置空，Master 侧鉴权仍按角色台账实时判定。
func (s *Server) issueTokens(ctx context.Context, u rbac.User) (tokenPair, error) {
	perms := s.expandPerms(ctx, u.Roles)
	access, err := s.d.Signer.Sign(auth.Claims{
		UID: u.ID, UserName: u.Name, Tenant: u.Tenant,
		Roles: u.Roles, Perms: perms, PlatformAdmin: u.PlatformAdmin, Typ: auth.TypAccess,
	})
	if err != nil {
		return tokenPair{}, err
	}
	refresh, err := s.d.Signer.Sign(auth.Claims{
		UID: u.ID, UserName: u.Name, Tenant: u.Tenant,
		Roles: u.Roles, Perms: perms, PlatformAdmin: u.PlatformAdmin, Typ: auth.TypRefresh,
		ExpiresAt: s.now().Add(auth.DefaultRefreshTTL).Unix(),
	})
	if err != nil {
		return tokenPair{}, err
	}
	return tokenPair{
		AccessToken:  access,
		RefreshToken: refresh,
		TokenType:    "Bearer",
		ExpiresIn:    int(auth.DefaultAccessTTL.Seconds()),
	}, nil
}

// expandPerms 角色→权限点展开（JWT perms claim；通配项原样保留，匹配语义同 rbac.Allowed）。
func (s *Server) expandPerms(ctx context.Context, roles []string) []string {
	all, err := s.d.Users.ListRoles(ctx)
	if err != nil {
		return nil
	}
	return rbac.ExpandPerms(all, roles)
}

func (s *Server) recordLogin(r *http.Request, username string, ok bool) {
	action := "auth.login"
	if !ok {
		action = "auth.login_failed"
	}
	_, _ = s.d.Audit.Append(r.Context(), audit.Entry{
		Ts: s.now(), User: username, Action: action, Resource: "auth",
		IP: clientIP(r), Category: "user",
	})
}

func (s *Server) now() time.Time {
	if s.d.Now != nil {
		return s.d.Now()
	}
	return time.Now()
}
