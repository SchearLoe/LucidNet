package httpapi

import (
	"net/http"
)

// reportsPlaceholder —— GET /api/v1/reports（R8 报表中心占位）。
//
// TODO(M3, docs/dd/05 §4)：R8 自定义报表为 M3 里程碑。
// 计划：report DSL（JSON，PG reports 表）→ lucid-reporter（cron 触发 → html/template
// 渲染 → XLSX(excelize)/PDF(headless Chromium 池) → MinIO reports/ → SMTP/站内信 →
// report_instances 落库）。当前仅登记路由与权限码（report:read/report:manage）。
func (h *Handlers) reportsPlaceholder() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeErr(w, r, http.StatusNotImplemented, codeNotImpl,
			"报表中心属 M3 里程碑（docs/dd/05 §4），M1 仅占位")
	})
}
