package export

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/SchearLoe/lucidnet/storage/internal/query"
)

// 响应码（与 internal/query 同口径：0 成功 / 40000 参数 / 40400 未找到 / 50000 内部）。
const (
	codeOK         = 0
	codeBadRequest = 40000
	codeNotFound   = 40400
	codeInternal   = 50000
)

// envelope —— 统一响应信封（docs/00 §6：{code,msg,data}）。
type envelope struct {
	Code int    `json:"code"`
	Msg  string `json:"msg"`
	Data any    `json:"data"`
}

// APIHandler —— 导出任务 API（docs/dd/04 §5.1；docs/09 §6：/api/v1/export/jobs
// 归属 Storage，经网关路由）。
type APIHandler struct {
	store Store
	newID func() string
	now   func() int64
}

// NewAPIHandler 构造导出 API handler。
func NewAPIHandler(store Store) *APIHandler {
	return &APIHandler{
		store: store,
		newID: newJobID,
		now:   func() int64 { return time.Now().Unix() },
	}
}

// Routes 返回骨架 HTTP 路由（net/http 1.22 方法+路径模式）。
func (h *APIHandler) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/export/jobs", h.handleCreate)
	mux.HandleFunc("GET /api/v1/export/jobs/{id}", h.handleGet)
	return mux
}

// createJobRequest —— POST /api/v1/export/jobs 请求体（dd/04 §5.1）。
type createJobRequest struct {
	Type      JobType       `json:"type"`
	AttackID  string        `json:"attack_id"`
	ZoneID    int32         `json:"zone_id"`
	ZoneName  string        `json:"zone_name"`
	TimeStart int64         `json:"time_start"` // epoch 秒（docs/09 §6）
	TimeEnd   int64         `json:"time_end"`
	Fields    []string      `json:"fields"`
	Filters   query.Filters `json:"filters"`
	Format    Format        `json:"format"`
	Sample    string        `json:"sample"`
}

type createJobData struct {
	JobID string `json:"job_id"`
}

// jobStatusData —— GET 响应数据（dd/04 §5.1：status|progress|url|expires_at）。
type jobStatusData struct {
	JobID     string  `json:"job_id"`
	Status    Status  `json:"status"`
	Progress  float64 `json:"progress"`
	URL       string  `json:"url,omitempty"`
	ExpiresAt int64   `json:"expires_at,omitempty"`
	Error     string  `json:"error,omitempty"`
}

func (h *APIHandler) handleCreate(w http.ResponseWriter, r *http.Request) {
	var req createJobRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, codeBadRequest, fmt.Sprintf("decode request: %v", err))
		return
	}
	now := h.now()
	job := Job{
		ID:        h.newID(),
		Type:      req.Type,
		AttackID:  req.AttackID,
		ZoneID:    req.ZoneID,
		ZoneName:  req.ZoneName,
		TimeStart: req.TimeStart,
		TimeEnd:   req.TimeEnd,
		Fields:    req.Fields,
		Filters:   req.Filters,
		Format:    req.Format,
		Sample:    req.Sample,
		Status:    StatusQueued,
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := h.store.Create(r.Context(), job); err != nil {
		if errors.Is(err, ErrInvalidJob) {
			writeErr(w, http.StatusBadRequest, codeBadRequest, err.Error())
			return
		}
		writeErr(w, http.StatusInternalServerError, codeInternal, "internal error")
		return
	}
	writeJSON(w, http.StatusAccepted, envelope{Code: codeOK, Msg: "ok", Data: createJobData{JobID: job.ID}})
}

func (h *APIHandler) handleGet(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	job, err := h.store.Get(r.Context(), id)
	if err != nil {
		if errors.Is(err, ErrJobNotFound) {
			writeErr(w, http.StatusNotFound, codeNotFound, "export job not found")
			return
		}
		writeErr(w, http.StatusInternalServerError, codeInternal, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, envelope{Code: codeOK, Msg: "ok", Data: jobStatusData{
		JobID:     job.ID,
		Status:    job.Status,
		Progress:  job.Progress,
		URL:       job.URL,
		ExpiresAt: job.ExpiresAt,
		Error:     job.Error,
	}})
}

func writeErr(w http.ResponseWriter, status, code int, msg string) {
	writeJSON(w, status, envelope{Code: code, Msg: msg, Data: struct{}{}})
}

func writeJSON(w http.ResponseWriter, status int, v envelope) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		fmt.Printf("export: write response: %v\n", err)
	}
}

// newJobID —— 任务 ID（16B 随机 hex；退化用时间戳）。
func newJobID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("job-%016x", time.Now().UnixNano())
	}
	return hex.EncodeToString(b[:])
}
