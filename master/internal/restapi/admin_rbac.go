package restapi

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/SchearLoe/lucidnet/master/internal/audit"
	"github.com/SchearLoe/lucidnet/master/internal/rbac"
)

// 租户/用户/角色与审计（docs/dd/07 §4；docs/09 §7 Master DDL 属主）。

// ---------- 租户 ----------

func (s *Server) handleListTenants(w http.ResponseWriter, r *http.Request) {
	tenants, err := s.d.Users.ListTenants(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, 500, "list tenants failed")
		return
	}
	if tenants == nil {
		tenants = []rbac.Tenant{}
	}
	writeOK(w, tenants)
}

type createTenantReq struct {
	Name string `json:"name"`
}

func (s *Server) handleCreateTenant(w http.ResponseWriter, r *http.Request) {
	var req createTenantReq
	if err := decodeBody(r, &req); err != nil || req.Name == "" {
		writeErr(w, http.StatusBadRequest, 400, "name required")
		return
	}
	if !s.requireLeader(w, r) {
		return
	}
	t, err := s.d.Users.CreateTenant(r.Context(), req.Name)
	if err != nil {
		writeErr(w, http.StatusBadRequest, 400, "create tenant failed: "+err.Error())
		return
	}
	s.recordAudit(r, "tenant.create", "tenant:"+req.Name, `{}`, "")
	writeOK(w, t)
}

func (s *Server) handleDeleteTenant(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if !s.requireLeader(w, r) {
		return
	}
	if err := s.d.Users.DeleteTenant(r.Context(), name); err != nil {
		if errors.Is(err, rbac.ErrNotFound) {
			writeErr(w, http.StatusNotFound, 404, "tenant not found")
			return
		}
		writeErr(w, http.StatusInternalServerError, 500, "delete tenant failed")
		return
	}
	s.recordAudit(r, "tenant.delete", "tenant:"+name, `{}`, "")
	writeOK(w, map[string]string{"name": name})
}

// ---------- 用户 ----------

func (s *Server) handleListUsers(w http.ResponseWriter, r *http.Request) {
	users, err := s.d.Users.ListUsers(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, 500, "list users failed")
		return
	}
	// 租户管理员只能看到本租户用户（平台管理员豁免）
	if t := currentTenant(r); t != "" {
		filtered := users[:0]
		for _, u := range users {
			if u.Tenant == t {
				filtered = append(filtered, u)
			}
		}
		users = filtered
	}
	if users == nil {
		users = []rbac.User{}
	}
	writeOK(w, users)
}

type createUserReq struct {
	Username string   `json:"username"`
	Password string   `json:"password"`
	Tenant   string   `json:"tenant,omitempty"`
	Roles    []string `json:"roles"`
}

// handleCreateUser 创建用户（口令 pbkdf2 存储，docs/dd/07 §4）。
func (s *Server) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	var req createUserReq
	if err := decodeBody(r, &req); err != nil || req.Username == "" || req.Password == "" {
		writeErr(w, http.StatusBadRequest, 400, "username and password required")
		return
	}
	if !s.requireLeader(w, r) {
		return
	}
	// 租户管理员只能在本租户内建用户
	tenantID, tenantName := int64(0), ""
	if t := currentTenant(r); t != "" {
		tenantName = t
		tenants, _ := s.d.Users.ListTenants(r.Context())
		for _, tt := range tenants {
			if tt.Name == t {
				tenantID = tt.ID
			}
		}
	} else if req.Tenant != "" {
		tenantName = req.Tenant
		tenants, _ := s.d.Users.ListTenants(r.Context())
		for _, tt := range tenants {
			if tt.Name == req.Tenant {
				tenantID = tt.ID
			}
		}
	}
	hash, err := rbac.HashPassword(req.Password)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, 500, "hash password failed")
		return
	}
	u, err := s.d.Users.CreateUser(r.Context(), rbac.User{
		TenantID: tenantID, Tenant: tenantName, Name: req.Username, Roles: req.Roles,
	}, hash)
	if err != nil {
		writeErr(w, http.StatusBadRequest, 400, "create user failed: "+err.Error())
		return
	}
	s.recordAudit(r, "user.create", "user:"+req.Username, `{}`, "")
	writeOK(w, u)
}

func (s *Server) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if !s.requireLeader(w, r) {
		return
	}
	if claimsFrom(r).UserName == name {
		writeErr(w, http.StatusBadRequest, 400, "cannot delete self")
		return
	}
	if err := s.d.Users.DeleteUser(r.Context(), name); err != nil {
		if errors.Is(err, rbac.ErrNotFound) {
			writeErr(w, http.StatusNotFound, 404, "user not found")
			return
		}
		writeErr(w, http.StatusInternalServerError, 500, "delete user failed")
		return
	}
	s.recordAudit(r, "user.delete", "user:"+name, `{}`, "")
	writeOK(w, map[string]string{"name": name})
}

// ---------- 角色 ----------

func (s *Server) handleListRoles(w http.ResponseWriter, r *http.Request) {
	roles, err := s.d.Users.ListRoles(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, 500, "list roles failed")
		return
	}
	if roles == nil {
		roles = []rbac.Role{}
	}
	writeOK(w, roles)
}

type upsertRoleReq struct {
	Name   string   `json:"name"`
	Tenant string   `json:"tenant,omitempty"`
	Perms  []string `json:"perms"`
}

func (s *Server) handleUpsertRole(w http.ResponseWriter, r *http.Request) {
	var req upsertRoleReq
	if err := decodeBody(r, &req); err != nil || req.Name == "" {
		writeErr(w, http.StatusBadRequest, 400, "name required")
		return
	}
	if !s.requireLeader(w, r) {
		return
	}
	var tenantID int64
	if req.Tenant != "" {
		tenants, _ := s.d.Users.ListTenants(r.Context())
		for _, t := range tenants {
			if t.Name == req.Tenant {
				tenantID = t.ID
			}
		}
	}
	role, err := s.d.Users.UpsertRole(r.Context(), rbac.Role{
		TenantID: tenantID, Name: req.Name, Perms: req.Perms,
	})
	if err != nil {
		writeErr(w, http.StatusBadRequest, 400, "upsert role failed: "+err.Error())
		return
	}
	s.recordAudit(r, "role.upsert", "role:"+req.Name, `{}`, "")
	writeOK(w, role)
}

// ---------- 审计查询（docs/hld/07 §4：Console 可查） ----------

func (s *Server) handleQueryAudit(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	page, _ := strconv.Atoi(q.Get("page"))
	pageSize, _ := strconv.Atoi(q.Get("page_size"))
	f := audit.Filter{
		User:     q.Get("user"),
		Action:   q.Get("action"),
		Page:     page,
		PageSize: pageSize,
	}
	var err error
	if v := q.Get("from"); v != "" {
		if f.From, err = time.Parse(time.RFC3339, v); err != nil {
			writeErr(w, http.StatusBadRequest, 400, "from must be RFC3339")
			return
		}
	}
	if v := q.Get("to"); v != "" {
		if f.To, err = time.Parse(time.RFC3339, v); err != nil {
			writeErr(w, http.StatusBadRequest, 400, "to must be RFC3339")
			return
		}
	}
	entries, total, err := s.d.Audit.Query(r.Context(), f)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, 500, "query audit failed")
		return
	}
	if entries == nil {
		entries = []audit.Entry{}
	}
	writeOK(w, map[string]any{"total": total, "page": f.Page, "page_size": f.PageSize, "items": entries})
}
