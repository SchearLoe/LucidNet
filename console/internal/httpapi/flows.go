package httpapi

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/SchearLoe/lucidnet/console/internal/auth"
	"github.com/SchearLoe/lucidnet/console/internal/upstream"
)

// R6 查询约束（docs/dd/04 §2.1）。
const (
	defaultPageSize   = 1000
	maxPageSizeSync   = 10000 // 同步返回行数上限
	maxFilterCount    = 8     // 条件上限（维度字段数）
	defaultWindowSec  = 900   // 默认 15 分钟
	guidanceExportMsg = "时间窗超过 6 小时，请改用异步导出任务：POST /api/v1/export/jobs（≤72h）"
)

// searchFlows —— POST /api/v1/flows/search（R6 明细查询，转发 Storage QueryService，
// docs/09 §6 提供方 Storage；本网关做约束校验 + 令牌桶 10 QPS/用户）。
// 时间参数为 epoch 秒（对齐 CH time_second 语义，docs/00 §4）。
func (h *Handlers) searchFlows() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := auth.IdentityFrom(r.Context())
		if !h.Limiter.Allow(id.UID) {
			writeErr(w, r, http.StatusTooManyRequests, codeRateLimited, "明细查询限流（10 QPS/用户），请稍后重试")
			return
		}
		req, err := decodeBody[upstream.FlowSearchRequest](r)
		if err != nil {
			writeErr(w, r, http.StatusBadRequest, codeBadRequest, "请求体解析失败："+err.Error())
			return
		}
		if msg := validateFlowSearch(req, h.MaxQueryWindowSec); msg != "" {
			writeErr(w, r, http.StatusBadRequest, codeBadRequest, msg)
			return
		}
		reply, err := h.Storage.SearchFlows(r.Context(), *req)
		if err != nil {
			writeAPIError(w, r, err, "明细查询（R6）")
			return
		}
		writeOK(w, r, reply)
	})
}

// createExportJob —— POST /api/v1/export/jobs（R5/R6 异步导出，转发 Storage ExportService）。
func (h *Handlers) createExportJob() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		req, err := decodeBody[upstream.ExportJobRequest](r)
		if err != nil {
			writeErr(w, r, http.StatusBadRequest, codeBadRequest, "请求体解析失败："+err.Error())
			return
		}
		if req.Type == "" {
			writeErr(w, r, http.StatusBadRequest, codeBadRequest, "type 必填（flows|attack_flows|aggr|attacks）")
			return
		}
		if msg := validateExportWindow(req.TimeStart, req.TimeEnd); msg != "" {
			writeErr(w, r, http.StatusBadRequest, codeBadRequest, msg)
			return
		}
		job, err := h.Storage.CreateExportJob(r.Context(), *req)
		if err != nil {
			writeAPIError(w, r, err, "创建导出任务")
			return
		}
		writeJSON(w, r, http.StatusAccepted, envelope{Code: codeOK, Msg: "accepted", Data: job, TraceID: traceID(r)})
	})
}

// getExportJob —— GET /api/v1/export/jobs/{job_id}（任务状态/进度/下载链接）。
func (h *Handlers) getExportJob() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		job, err := h.Storage.GetExportJob(r.Context(), r.PathValue("job_id"))
		if err != nil {
			writeAPIError(w, r, err, "导出任务查询")
			return
		}
		writeOK(w, r, job)
	})
}

// validateFlowSearch 校验 dd/04 §2.1 约束；返回非空 msg 即 400。
func validateFlowSearch(req *upstream.FlowSearchRequest, maxWindowSec int64) string {
	if req.TimeStart <= 0 || req.TimeEnd <= 0 {
		return "time_start/time_end 必填（epoch 秒）"
	}
	if req.TimeEnd < req.TimeStart {
		return "time_end 必须大于 time_start"
	}
	if maxWindowSec <= 0 {
		maxWindowSec = 6 * 3600
	}
	window := req.TimeEnd - req.TimeStart
	if window > maxWindowSec {
		return guidanceExportMsg
	}
	if window < 60 {
		return "时间窗过小（最小 1 分钟）"
	}
	if n := req.Filters.Count(); n == 0 {
		return "至少 1 个维度条件（IP/端口/协议/zone/设备/接口）"
	} else if n > maxFilterCount {
		return "条件过多（≤8 个）"
	}
	if req.PageSize == 0 {
		req.PageSize = defaultPageSize
	}
	if req.PageSize > maxPageSizeSync {
		return "page_size 超过同步上限 10,000（大结果请用导出任务）"
	}
	if req.Page > 50 && len(req.Cursor) == 0 {
		return "深分页（page>50）必须使用游标模式（cursor）"
	}
	return ""
}

// validateExportWindow 校验导出窗口 ≤72h（docs/dd/04 §5.1）。
func validateExportWindow(start, end int64) string {
	if start <= 0 || end <= 0 {
		return "time_start/time_end 必填（epoch 秒）"
	}
	if end <= start {
		return "time_end 必须大于 time_start"
	}
	if end-start > 72*3600 {
		return "导出窗口超过上限 72h"
	}
	return ""
}

// decodeBody 泛型 JSON 请求体解析（上限 1MB）。
func decodeBody[T any](r *http.Request) (*T, error) {
	var v T
	dec := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	return &v, nil
}
