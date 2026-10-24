package restapi

import "net/http"

// 路由（docs/09 §6 Master 归属；docs/dd/07 §1 REST 清单）。
// 权限点对照：读 admin:read，写 admin:manage；zones zone:read/zone:edit；
// forward_rules forward:read/forward:edit（域白名单 docs/11 §8）。
func (s *Server) routes(mux *http.ServeMux) {
	// 健康探针（无鉴权）
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeOK(w, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		if s.d.Leader != nil && !s.d.Leader() {
			writeJSON(w, http.StatusOK, envelope{Code: 0, Msg: "standby", Data: map[string]bool{"leader": false}})
			return
		}
		writeOK(w, map[string]bool{"leader": true})
	})
	// Prometheus 抓取（docs/11 §9；无鉴权——仅聚合指标，不落节点 ID/IP 等明细）
	mux.Handle("GET /metrics", s.metricsHandler())

	// 认证
	mux.HandleFunc("POST /api/v1/auth/login", s.handleLogin)
	mux.HandleFunc("POST /api/v1/auth/refresh", s.handleRefresh)
	mux.Handle("GET /api/v1/auth/me", s.withAuth("overview:read", s.handleMe))
	// JWKS 公钥（RS256 未配置时为空集；公钥属公开信息不鉴权，LucidBGP 验签入口，dd/07 §4）
	mux.HandleFunc("GET /api/v1/auth/jwks", s.handleJWKS)
	mux.HandleFunc("GET /api/v1/auth/jwks.pem", s.handleJWKSPem)

	// 节点与拓扑（集群状态查询 API）
	mux.Handle("GET /api/v1/admin/nodes", s.withAuth("admin:read", s.handleListNodes))
	mux.Handle("GET /api/v1/admin/nodes/{id}", s.withAuth("admin:read", s.handleGetNode))
	mux.Handle("POST /api/v1/admin/nodes/{id}/drain", s.withAuth("admin:manage", s.handleDrainNode))
	mux.Handle("POST /api/v1/admin/nodes/{id}/state", s.withAuth("admin:manage", s.handleSetNodeState))
	mux.Handle("POST /api/v1/admin/nodes/{id}/weight", s.withAuth("admin:manage", s.handleSetWeight))

	// exporter 台账与分配表
	mux.Handle("GET /api/v1/admin/exporters", s.withAuth("admin:read", s.handleListExporters))
	mux.Handle("POST /api/v1/admin/exporters", s.withAuth("admin:manage", s.handleUpsertExporter))
	mux.Handle("GET /api/v1/admin/assign/table", s.withAuth("admin:read", s.handleAssignTable))
	mux.Handle("PUT /api/v1/admin/assign/pins", s.withAuth("admin:manage", s.handleAssignPin))

	// 配置发布（etcd 权威键空间）
	mux.Handle("GET /api/v1/admin/zones", s.withAuth("zone:read", s.handleGetZones))
	mux.Handle("PUT /api/v1/admin/zones", s.withAuth("zone:edit", s.handlePutZones))
	mux.Handle("GET /api/v1/admin/forward_rules", s.withAuth("forward:read", s.handleGetForwardRules))
	mux.Handle("PUT /api/v1/admin/forward_rules", s.withAuth("forward:edit", s.handlePutForwardRules))
	mux.Handle("GET /api/v1/admin/config/analytics", s.withAuth("admin:read", s.handleGetScope(ScopeAnalyticsPath)))
	mux.Handle("PUT /api/v1/admin/config/analytics", s.withAuth("admin:manage", s.handlePutScope(ScopeAnalyticsPath)))
	mux.Handle("GET /api/v1/admin/config/collector/{node}", s.withAuth("admin:read", s.handleGetScope(ScopeCollectorPath)))
	mux.Handle("PUT /api/v1/admin/config/collector/{node}", s.withAuth("admin:manage", s.handlePutScope(ScopeCollectorPath)))
	mux.Handle("POST /api/v1/admin/publish", s.withAuth("admin:manage", s.handlePublishGeneric))

	// 配置版本与回滚
	mux.Handle("GET /api/v1/admin/versions", s.withAuth("admin:read", s.handleListVersions))
	mux.Handle("GET /api/v1/admin/versions/view", s.withAuth("admin:read", s.handleGetVersion))
	mux.Handle("POST /api/v1/admin/versions/rollback", s.withAuth("admin:manage", s.handleRollback))

	// 发布补偿队列（PG outbox；docs/dd/07 §1）
	mux.Handle("GET /api/v1/admin/outbox", s.withAuth("admin:read", s.handleListOutbox))
	mux.Handle("POST /api/v1/admin/outbox/cancel", s.withAuth("admin:manage", s.handleCancelOutbox))

	// RBAC / 租户
	mux.Handle("GET /api/v1/admin/tenants", s.withAuth("admin:read", s.handleListTenants))
	mux.Handle("POST /api/v1/admin/tenants", s.withAuth("admin:manage", s.handleCreateTenant))
	mux.Handle("DELETE /api/v1/admin/tenants/{name}", s.withAuth("admin:manage", s.handleDeleteTenant))
	mux.Handle("GET /api/v1/admin/users", s.withAuth("admin:read", s.handleListUsers))
	mux.Handle("POST /api/v1/admin/users", s.withAuth("admin:manage", s.handleCreateUser))
	mux.Handle("DELETE /api/v1/admin/users/{name}", s.withAuth("admin:manage", s.handleDeleteUser))
	mux.Handle("GET /api/v1/admin/roles", s.withAuth("admin:read", s.handleListRoles))
	mux.Handle("POST /api/v1/admin/roles", s.withAuth("admin:manage", s.handleUpsertRole))

	// 审计
	mux.Handle("GET /api/v1/admin/audit", s.withAuth("audit:read", s.handleQueryAudit))

	// M2+ 占位（不越界实现 Console 资产/策略 CRUD 与 Deploy 编排）
	mux.Handle("GET /api/v1/admin/devices", s.withAuth("device:read", s.handleNotImplemented("devices CRUD (M2: Console 资产管理)")))
	mux.Handle("GET /api/v1/admin/policies", s.withAuth("policy:read", s.handleNotImplemented("detect_policies CRUD (M2)")))
	mux.Handle("/api/v1/deploy/", s.withAuth("deploy:read", s.handleNotImplemented("deploy orchestration belongs to 08 LucidDeploy (dd/07 §6)")))
}
