// Package auth —— JWT 鉴权（docs/dd/07：HS256，Master 与网关共享密钥，
// claims={uid, tenant, roles, exp}；网关校验后注入租户）与权限码检查
// （docs/11 §8：<domain>:<action>，白名单见登记表 doc10 §5.2）。
package auth

// Permission —— 权限码 <domain>:<action>（docs/11 §8）。
type Permission string

// 权限码登记（doc10 §5.2 初始清单内；Console 用到的子集）。
const (
	PermOverviewRead Permission = "overview:read"
	PermAnalysisRead Permission = "analysis:read"
	PermZoneRead     Permission = "zone:read"
	PermFlowsQuery   Permission = "flows:query"
	PermFlowsExport  Permission = "flows:export"
	PermAttackRead   Permission = "attack:read"
	PermAttackHandle Permission = "attack:handle"
	PermReportRead   Permission = "report:read"
	PermReportManage Permission = "report:manage"
	PermMonitorRead  Permission = "monitor:read"
	PermAuditRead    Permission = "audit:read"
	PermAdminManage  Permission = "admin:manage"
)

// Claims —— JWT claims（docs/dd/07 契约：{uid, tenant, roles, exp}）。
// perms 为扩展位：当前契约未登记，若 Master 不签发则严格模式下授权检查失败
//（见报告「契约变更建议」）。
type Claims struct {
	UID    string   `json:"uid"`
	Tenant string   `json:"tenant"`
	Roles  []string `json:"roles"`
	Perms  []string `json:"perms,omitempty"` // 未登记扩展：稳定后应写入 docs/09
}
