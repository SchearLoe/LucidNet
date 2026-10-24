package httpapi

import (
	"log/slog"
	"net/http"

	"github.com/SchearLoe/lucidnet/console/internal/auth"
	"github.com/SchearLoe/lucidnet/console/internal/query"
	"github.com/SchearLoe/lucidnet/console/internal/ratelimit"
	"github.com/SchearLoe/lucidnet/console/internal/upstream"
	"github.com/SchearLoe/lucidnet/console/internal/ws"
)

// Handlers —— REST 编排层依赖集。
type Handlers struct {
	Attacks query.AttackReader
	Alarms  query.AlarmReader
	Zones   query.RealtimeReader
	Storage upstream.StorageClient
	BGP     *upstream.BGPClient
	Limiter *ratelimit.Limiter // 明细查询令牌桶（10 QPS/用户，docs/dd/05 §6）
	Log     *slog.Logger
	// MaxQueryWindowSec —— R6 同步查询时间窗上限（6h，docs/dd/04 §2.1；超过引导异步导出）。
	MaxQueryWindowSec int64
}

// Routes 装配全部路由；trace/recover/请求日志为外层中间件，JWT 鉴权挂 /api/v1/*。
func Routes(h *Handlers, am *auth.Middleware, stream *ws.Handler) http.Handler {
	api := http.NewServeMux()

	// —— 展示查询（R2/R5/R7）——
	api.Handle("GET /api/v1/zones/realtime", am.RequirePerm(auth.PermZoneRead, h.zoneRealtime()))
	api.Handle("GET /api/v1/attacks", am.RequirePerm(auth.PermAttackRead, h.listAttacks()))
	api.Handle("GET /api/v1/attacks/{attack_id}", am.RequirePerm(auth.PermAttackRead, h.getAttack()))
	api.Handle("GET /api/v1/attacks/{attack_id}/minutes", am.RequirePerm(auth.PermAttackRead, h.attackMinutes()))
	api.Handle("GET /api/v1/alarms", am.RequirePerm(auth.PermAttackRead, h.listAlarms()))

	// —— 一键处置（R9，转发 LucidBGP）——
	api.Handle("POST /api/v1/attacks/{attack_id}/mitigate", am.RequirePerm(auth.PermAttackHandle, h.mitigate()))

	// —— 明细查询/导出（R6，转发 Storage）——
	api.Handle("POST /api/v1/flows/search", am.RequirePerm(auth.PermFlowsQuery, h.searchFlows()))
	api.Handle("POST /api/v1/export/jobs", am.RequirePerm(auth.PermFlowsExport, h.createExportJob()))
	api.Handle("GET /api/v1/export/jobs/{job_id}", am.RequirePerm(auth.PermFlowsExport, h.getExportJob()))

	// —— WebSocket 实时流（网关自有，docs/00 §6；仅需登录，无权限码）——
	api.Handle("GET /api/v1/stream/{topic}", http.HandlerFunc(stream.ServeStream))

	// —— 报表中心（R8，M3 占位）——
	api.Handle("GET /api/v1/reports", am.RequirePerm(auth.PermReportRead, h.reportsPlaceholder()))

	// 根路由：健康检查免鉴权；/api/v1/* 统一挂 JWT。
	root := http.NewServeMux()
	root.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		writeOK(w, r, map[string]string{"status": "ok"})
	})
	root.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		writeOK(w, r, map[string]string{"status": "ready"})
	})
	root.Handle("/api/v1/", am.Wrap(withLog(h.Log, api)))
	return withTrace(withRecover(h.Log, root))
}

// withLog 注入请求日志器。
func withLog(log *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r.WithContext(withLogger(r.Context(), log)))
	})
}

// withRecover panic 兜底（500 + trace_id）。
func withRecover(log *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				log.Error("panic recovered", "module", "gateway", "path", r.URL.Path, "panic", rec)
				writeErr(w, r, http.StatusInternalServerError, 500, "internal error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// withTrace 贯穿 trace id（docs/11 §9：trace_id 字段；无入站则生成）。
func withTrace(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tid := r.Header.Get("X-Lucid-Trace-Id")
		if tid == "" {
			tid = newTraceID()
		}
		w.Header().Set("X-Lucid-Trace-Id", tid)
		r.Header.Set("X-Lucid-Trace-Id", tid)
		next.ServeHTTP(w, r)
	})
}
