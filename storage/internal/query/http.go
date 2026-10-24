package query

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"
)

// 统一响应信封（docs/00 §6：{code,msg,data}）。
type envelope struct {
	Code int    `json:"code"`
	Msg  string `json:"msg"`
	Data any    `json:"data"`
}

// 响应码（骨架约定：0 成功 / 40000 参数错误 / 50000 内部错误；网关透传）。
const (
	codeOK         = 0
	codeBadRequest = 40000
	codeInternal   = 50000
)

// searchResult —— /api/v1/flows/search 响应数据（docs/dd/04 §2.2：
// {total_estimate, rows, query_id}）。
// 骨架行为：回显生成的 SQL（sql/estimate_sql），rows 恒为空数组；
// 接 CH 执行后填充 rows 与 total_estimate（uniqExact 超 TotalEstimateCap
// 截断显示 ">10M"）——TODO 见模块 README dd/04 §2.2 条目。
type searchResult struct {
	QueryID       string `json:"query_id"`
	SQL           string `json:"sql"`
	EstimateSQL   string `json:"estimate_sql"`
	Rows          []any  `json:"rows"`
	TotalEstimate int64  `json:"total_estimate"`
	Page          int    `json:"page"`
	PageSize      int    `json:"page_size"`
	CursorMode    bool   `json:"cursor_mode"`
}

// SearchHandler —— POST /api/v1/flows/search（docs/dd/04 §2.2；经网关路由，
// docs/09 §6 路由归属 Storage）。
type SearchHandler struct {
	builder *Builder
}

// NewSearchHandler 构造查询 handler。
func NewSearchHandler(b *Builder) *SearchHandler {
	if b == nil {
		b = NewBuilder()
	}
	return &SearchHandler{builder: b}
}

// Routes 返回骨架 HTTP 路由（net/http；网关反代 /api/v1/*，docs/09 §6）。
func (h *SearchHandler) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("POST /api/v1/flows/search", h)
	return mux
}

// ServeHTTP 处理明细查询请求。
func (h *SearchHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, codeBadRequest, "method not allowed, use POST")
		return
	}
	var req SearchRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, codeBadRequest, fmt.Sprintf("decode request: %v", err))
		return
	}
	built, err := h.builder.Build(req)
	if err != nil {
		if isBuilderErr(err) {
			writeError(w, http.StatusBadRequest, codeBadRequest, err.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, codeInternal, "internal error")
		return
	}
	writeOK(w, searchResult{
		QueryID:       newQueryID(),
		SQL:           built.SQL,
		EstimateSQL:   built.EstimateSQL,
		Rows:          []any{},
		TotalEstimate: 0,
		Page:          built.Page,
		PageSize:      built.PageSize,
		CursorMode:    built.CursorMode,
	})
}

// builderSentinelErrs —— 全部为 400 语义的构建器哨兵错误。
var builderSentinelErrs = []error{
	ErrWindowTooLarge, ErrBadTimeRange, ErrBadFilter, ErrNoFilters, ErrTooManyFilters,
	ErrBadField, ErrBadOrderBy, ErrCursorRequired, ErrBadCursor, ErrCursorWithCustomOrder,
}

func isBuilderErr(err error) bool {
	for _, e := range builderSentinelErrs {
		if errors.Is(err, e) {
			return true
		}
	}
	return false
}

func writeOK(w http.ResponseWriter, data any) {
	writeJSON(w, http.StatusOK, envelope{Code: codeOK, Msg: "ok", Data: data})
}

func writeError(w http.ResponseWriter, status, code int, msg string) {
	writeJSON(w, status, envelope{Code: code, Msg: msg, Data: struct{}{}})
}

func writeJSON(w http.ResponseWriter, status int, v envelope) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		// 响应头已写出，仅能记录；骨架以标准日志兜底
		fmt.Printf("query: write response: %v\n", err)
	}
}

// newQueryID —— 查询追踪 ID（16B 随机 hex；退化用时间戳）。
func newQueryID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("q-%016x", time.Now().UnixNano())
	}
	return hex.EncodeToString(b[:])
}
