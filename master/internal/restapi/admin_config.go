package restapi

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"

	"github.com/SchearLoe/lucidnet/master/internal/config"
)

// 配置发布 / 版本 / 回滚（docs/09 §6 /api/v1/admin/*；etcd 键空间 docs/09 §5）。

const (
	ScopeZonesPath        = "zones"
	ScopeForwardRulesPath = "forward_rules"
	ScopeAnalyticsPath    = "analytics"
	ScopeCollectorPath    = "collector"
)

// scopeKey REST 资源名 → etcd 作用域键。
func (s *Server) scopeKey(resource, node string) string {
	switch resource {
	case ScopeZonesPath:
		return config.ScopeZones
	case ScopeForwardRulesPath:
		return config.ScopeForwardRules
	case ScopeAnalyticsPath:
		return config.ScopeAnalytics
	case ScopeCollectorPath:
		return config.CollectorScope(node)
	}
	return ""
}

// readSnapshotBody 读取快照体（JSON 数组/对象原样转发校验与存储）。
func readSnapshotBody(r *http.Request) ([]byte, error) {
	defer func() { _ = r.Body.Close() }()
	return io.ReadAll(r.Body)
}

func (s *Server) handleGetZones(w http.ResponseWriter, r *http.Request) {
	s.getScope(w, r, config.ScopeZones)
}

func (s *Server) handlePutZones(w http.ResponseWriter, r *http.Request) {
	s.putScope(w, r, config.ScopeZones)
}

func (s *Server) handleGetForwardRules(w http.ResponseWriter, r *http.Request) {
	s.getScope(w, r, config.ScopeForwardRules)
}

func (s *Server) handlePutForwardRules(w http.ResponseWriter, r *http.Request) {
	s.putScope(w, r, config.ScopeForwardRules)
}

// handleGetScope/handlePutScope —— analytics 与 collector/{node} 通用形态。
func (s *Server) handleGetScope(resource string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		scope := s.scopeKey(resource, r.PathValue("node"))
		if scope == "" {
			writeErr(w, http.StatusBadRequest, 400, "invalid scope")
			return
		}
		s.getScope(w, r, scope)
	}
}

func (s *Server) handlePutScope(resource string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		scope := s.scopeKey(resource, r.PathValue("node"))
		if scope == "" {
			writeErr(w, http.StatusBadRequest, 400, "invalid scope")
			return
		}
		s.putScope(w, r, scope)
	}
}

// getScope 读取当前生效快照（Envelope 信封，与 etcd 值一致）。
func (s *Server) getScope(w http.ResponseWriter, r *http.Request, scope string) {
	env, err := s.d.Config.Current(r.Context(), scope)
	if err != nil {
		if errors.Is(err, config.ErrNotFound) {
			writeOK(w, map[string]any{"version": 0, "data": nil})
			return
		}
		writeErr(w, http.StatusInternalServerError, 500, "get config failed")
		return
	}
	// 租户隔离（MVP：非平台管理员只读自己租户的 zone 子集）
	if scope == config.ScopeZones && currentTenant(r) != "" {
		writeOK(w, tenantZonesView(env, currentTenant(r)))
		return
	}
	writeOK(w, env)
}

// putScope 发布快照（校验 → PG 权威 → etcd → ACK 跟踪，docs/dd/07 §5）。
func (s *Server) putScope(w http.ResponseWriter, r *http.Request, scope string) {
	if !s.requireLeader(w, r) {
		return
	}
	data, err := readSnapshotBody(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, 400, "invalid json body")
		return
	}
	version, err := s.d.Config.Publish(r.Context(), scope, data, claimsFrom(r).UserName)
	if err != nil {
		writeErr(w, http.StatusBadRequest, 400, "publish failed: "+err.Error())
		return
	}
	s.recordAudit(r, "config.publish", "scope:"+scope,
		`{"version":`+strconv.FormatUint(version, 10)+`}`, "")
	writeOK(w, map[string]any{"scope": scope, "version": version})
}

type publishGenericReq struct {
	Scope string          `json:"scope"`
	Data  json.RawMessage `json:"data"`
}

// handlePublishGeneric 通用发布入口（gRPC PublishConfig 的 REST 等价）。
func (s *Server) handlePublishGeneric(w http.ResponseWriter, r *http.Request) {
	var req publishGenericReq
	if err := decodeBody(r, &req); err != nil || req.Scope == "" {
		writeErr(w, http.StatusBadRequest, 400, "scope and data required")
		return
	}
	if !s.requireLeader(w, r) {
		return
	}
	version, err := s.d.Config.Publish(r.Context(), req.Scope, req.Data, claimsFrom(r).UserName)
	if err != nil {
		writeErr(w, http.StatusBadRequest, 400, "publish failed: "+err.Error())
		return
	}
	s.recordAudit(r, "config.publish", "scope:"+req.Scope,
		`{"version":`+strconv.FormatUint(version, 10)+`}`, "")
	writeOK(w, map[string]any{"scope": req.Scope, "version": version})
}

// ---------- 版本与回滚（docs/dd/07 §5） ----------

// handleListVersions 版本历史（?scope=&limit=）。
func (s *Server) handleListVersions(w http.ResponseWriter, r *http.Request) {
	scope := r.URL.Query().Get("scope")
	if scope == "" {
		writeErr(w, http.StatusBadRequest, 400, "scope required")
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	versions, err := s.d.Config.ListVersions(r.Context(), scope, limit)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, 500, "list versions failed")
		return
	}
	if versions == nil {
		versions = []config.Version{}
	}
	writeOK(w, versions)
}

// handleGetVersion 单版本（?scope=&version=）。
func (s *Server) handleGetVersion(w http.ResponseWriter, r *http.Request) {
	scope := r.URL.Query().Get("scope")
	version, err := strconv.ParseUint(r.URL.Query().Get("version"), 10, 64)
	if scope == "" || err != nil {
		writeErr(w, http.StatusBadRequest, 400, "scope and version required")
		return
	}
	v, err := s.d.Config.GetVersion(r.Context(), scope, version)
	if err != nil {
		if errors.Is(err, config.ErrNotFound) {
			writeErr(w, http.StatusNotFound, 404, "version not found")
			return
		}
		writeErr(w, http.StatusInternalServerError, 500, "get version failed")
		return
	}
	writeOK(w, v)
}

type rollbackReq struct {
	Scope   string `json:"scope"`
	Version uint64 `json:"version"`
}

// handleRollback 一键回滚（etcd 历史版本 + PG 配置快照双恢复，docs/dd/07 §5）。
func (s *Server) handleRollback(w http.ResponseWriter, r *http.Request) {
	var req rollbackReq
	if err := decodeBody(r, &req); err != nil || req.Scope == "" || req.Version == 0 {
		writeErr(w, http.StatusBadRequest, 400, "scope and version required")
		return
	}
	if !s.requireLeader(w, r) {
		return
	}
	newVersion, err := s.d.Config.Rollback(r.Context(), req.Scope, req.Version, claimsFrom(r).UserName)
	if err != nil {
		writeErr(w, http.StatusBadRequest, 400, "rollback failed: "+err.Error())
		return
	}
	s.recordAudit(r, "config.rollback", "scope:"+req.Scope,
		`{"from":`+strconv.FormatUint(req.Version, 10)+`,"to":`+strconv.FormatUint(newVersion, 10)+`}`,
		"rollback config")
	writeOK(w, map[string]any{"scope": req.Scope, "rolled_back_to": req.Version, "new_version": newVersion})
}

// ---------- 发布补偿队列（PG outbox 持久化，docs/dd/07 §1 失败补偿重试队列） ----------

// handleListOutbox 待重试补偿单（etcd 发布失败、退避重试中）。
func (s *Server) handleListOutbox(w http.ResponseWriter, r *http.Request) {
	entries, err := s.d.Config.PendingOutbox(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, 500, "list outbox failed")
		return
	}
	if entries == nil {
		entries = []config.OutboxEntry{}
	}
	writeOK(w, entries)
}

type cancelOutboxReq struct {
	Scope   string `json:"scope"`
	Version uint64 `json:"version"`
}

// handleCancelOutbox 人工取消补偿单（版本保持 failed；经重发新版本恢复）。
func (s *Server) handleCancelOutbox(w http.ResponseWriter, r *http.Request) {
	var req cancelOutboxReq
	if err := decodeBody(r, &req); err != nil || req.Scope == "" || req.Version == 0 {
		writeErr(w, http.StatusBadRequest, 400, "scope and version required")
		return
	}
	if !s.requireLeader(w, r) {
		return
	}
	if err := s.d.Config.CancelPending(r.Context(), req.Scope, req.Version); err != nil {
		if errors.Is(err, config.ErrOutboxNotFound) {
			writeErr(w, http.StatusNotFound, 404, "pending outbox entry not found")
			return
		}
		writeErr(w, http.StatusInternalServerError, 500, "cancel outbox failed")
		return
	}
	s.recordAudit(r, "config.outbox_cancel", "scope:"+req.Scope,
		`{"version":`+strconv.FormatUint(req.Version, 10)+`}`, "cancel config publish retry")
	writeOK(w, map[string]any{"scope": req.Scope, "version": req.Version, "status": "cancelled"})
}

// tenantZonesView —— 租户视角 zone 快照（平台管理员/无租户上下文返回全量）。
func tenantZonesView(env config.Envelope, tenant string) map[string]any {
	var zones []map[string]any
	_ = json.Unmarshal(env.Data, &zones)
	filtered := make([]map[string]any, 0, len(zones))
	for _, z := range zones {
		if zt, _ := z["tenant"].(string); zt == tenant {
			filtered = append(filtered, z)
		}
	}
	raw, _ := json.Marshal(filtered)
	return map[string]any{"version": env.Version, "updated_at": env.UpdatedAt,
		"data": json.RawMessage(raw)}
}

// handleNotImplemented M2+ 占位（501；不越界实现 08 部署编排等）。
func (s *Server) handleNotImplemented(what string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		writeErr(w, http.StatusNotImplemented, 501, "not implemented: "+what)
	}
}
