package httpapi

import (
	"net/http"
	"strconv"

	"github.com/SchearLoe/lucidnet/console/internal/query"
	"github.com/SchearLoe/lucidnet/shared"
)

// listAlarms —— GET /api/v1/alarms（R7 告警列表：severity/category/zone_id/
// from_ms/to_ms 过滤 + 分页，docs/00 §6）。
func (h *Handlers) listAlarms() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f := query.AlarmFilter{
			ZoneID: atoi32(r.URL.Query().Get("zone_id")),
		}
		for _, v := range r.URL.Query()["severity"] {
			if n, err := strconv.ParseUint(v, 10, 32); err == nil {
				f.Severities = append(f.Severities, shared.AlarmSeverity(n))
			}
		}
		for _, v := range r.URL.Query()["category"] {
			if n, err := strconv.ParseUint(v, 10, 32); err == nil {
				f.Categories = append(f.Categories, shared.AlarmCategory(n))
			}
		}
		f.FromMs = atoi64(r.URL.Query().Get("from_ms"))
		f.ToMs = atoi64(r.URL.Query().Get("to_ms"))
		f.Page, f.PageSize = pageParams(r)

		pageData, err := h.Alarms.ListAlarms(r.Context(), f)
		if err != nil {
			writeAPIError(w, r, err, "告警列表查询")
			return
		}
		writeOK(w, r, pageData)
	})
}
