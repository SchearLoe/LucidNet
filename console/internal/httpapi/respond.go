// Package httpapi —— lucid-gateway REST 面（docs/09 §6 路由归属；响应信封
// {code,msg,data}，docs/00 §6）。本包只做协议/校验/编排，不做业务计算。
package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/SchearLoe/lucidnet/console/internal/query"
	"github.com/SchearLoe/lucidnet/console/internal/upstream"
)

// 业务错误码（docs/00 §6 信封 code；HTTP 状态与 code 同源，细分错误用 5 位码）。
const (
	codeOK          = 0
	codeBadRequest  = 400
	codeUnauthorized = 401
	codeForbidden   = 403
	codeNotFound    = 404
	codeNotImpl     = 501
	codeRateLimited = 429
	codeUpstreamBad = 502
	codeUpstreamNa  = 503
)

// envelope —— 统一响应信封。trace_id 为附加字段（doc10 §3.7 错误态可复制 trace_id）。
type envelope struct {
	Code    int    `json:"code"`
	Msg     string `json:"msg"`
	Data    any    `json:"data"`
	TraceID string `json:"trace_id,omitempty"`
}

// WriteUnauthorized —— 401 渲染（auth 中间件回调）。
func WriteUnauthorized(w http.ResponseWriter, r *http.Request, err error) {
	logger(r).Warn("unauthorized", "path", r.URL.Path, "err", err)
	writeErr(w, r, http.StatusUnauthorized, codeUnauthorized, "未认证："+err.Error())
}

// WriteForbidden —— 403 渲染（auth 中间件回调；deniedPerm 非空时附权限码）。
func WriteForbidden(w http.ResponseWriter, r *http.Request, deniedPerm string) {
	msg := "权限不足"
	if deniedPerm != "" {
		msg += "（需 " + deniedPerm + "，权限码登记见 docs/10 §5.2 / docs/11 §8）"
	}
	writeErr(w, r, http.StatusForbidden, codeForbidden, msg)
}

// writeOK 200 成功响应。
func writeOK(w http.ResponseWriter, r *http.Request, data any) {
	writeJSON(w, r, http.StatusOK, envelope{Code: codeOK, Msg: "ok", Data: data, TraceID: traceID(r)})
}

// writeErr 业务错误（带 HTTP 状态与细分 code）。
func writeErr(w http.ResponseWriter, r *http.Request, status, code int, msg string) {
	writeJSON(w, r, status, envelope{Code: code, Msg: msg, TraceID: traceID(r)})
}

// writeAPIError 将内部错误映射为统一响应：
// query.ErrUpstreamUnavailable / upstream.ErrNotReady → 503；其余 → 502。
func writeAPIError(w http.ResponseWriter, r *http.Request, err error, what string) {
	log := logger(r)
	switch {
	case errors.Is(err, upstream.ErrNotReady), errors.Is(err, query.ErrUpstreamUnavailable):
		log.Warn("upstream unavailable", "what", what, "err", err)
		writeErr(w, r, http.StatusServiceUnavailable, codeUpstreamNa,
			what+"：上游（Storage/Analytics）不可用或未部署，请稍后重试")
	default:
		log.Error("upstream call failed", "what", what, "err", err)
		writeErr(w, r, http.StatusBadGateway, codeUpstreamBad, what+"失败："+err.Error())
	}
}

func writeJSON(w http.ResponseWriter, r *http.Request, status int, body any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		logger(r).Error("write response", "err", err)
	}
}

// logger 从 context 取请求日志器（router.go 注入；缺省回退全局）。
func logger(r *http.Request) *slog.Logger {
	if l, ok := r.Context().Value(logKey{}).(*slog.Logger); ok && l != nil {
		return l
	}
	return slog.Default()
}

// withLogger 将日志器写入 context（router.go 装配）。
func withLogger(ctx context.Context, log *slog.Logger) context.Context {
	return context.WithValue(ctx, logKey{}, log)
}

type logKey struct{}

func traceID(r *http.Request) string { return r.Header.Get("X-Lucid-Trace-Id") }
