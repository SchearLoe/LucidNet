// Package upstream —— 跨模块上游客户端（docs/09 §6 唯一权威路由）：
//   - Storage QueryService/ExportService：/api/v1/flows/search、/api/v1/export/jobs（R6/R5），
//     以及 attack_minutes 点查（docs/dd/04 §3，攻击详情分钟表 R5）。
//   - LucidBGP：POST /api/bgp/alarms 一键处置预填（docs/dd/05 §5）。
//
// Storage 模块并行开发中：请求/响应结构按 dd/04 §2.2/§5.1 契约实现，
// 未部署时由 httpapi 降级为 503 + 提示（不伪造数据）。
package upstream

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/SchearLoe/lucidnet/shared"
)

// ErrNotReady —— 上游未部署/未配置（Storage 并行开发中，M1 允许）。
var ErrNotReady = errors.New("upstream not ready")

// FlowSearchRequest —— R6 明细查询（docs/dd/04 §2.2 契约字段）。
type FlowSearchRequest struct {
	TimeStart int64           `json:"time_start"`
	TimeEnd   int64           `json:"time_end"`
	Filters   FlowFilters     `json:"filters"`
	OrderBy   string          `json:"order_by,omitempty"`
	Desc      bool            `json:"desc,omitempty"`
	Page      int             `json:"page,omitempty"`
	PageSize  int             `json:"page_size,omitempty"`
	Fields    []string        `json:"fields,omitempty"`
	Cursor    json.RawMessage `json:"cursor,omitempty"` // 深分页游标（page>50 强制）
}

// FlowFilters —— 维度过滤（白名单；docs/dd/04 §2.1：≥1 个条件，≤8 个）。
type FlowFilters struct {
	SrcIP     string `json:"src_ip,omitempty"`     // IP 或 CIDR
	DstIP     string `json:"dst_ip,omitempty"`
	SrcPort   uint32 `json:"src_port,omitempty"`
	DstPort   uint32 `json:"dst_port,omitempty"`
	Proto     uint32 `json:"proto,omitempty"`
	ZoneID    int32  `json:"zone_id,omitempty"`
	DeviceID  uint32 `json:"device_id,omitempty"`
	InIf      uint32 `json:"in_if,omitempty"`
	OutIf     uint32 `json:"out_if,omitempty"`
	IPVersion uint32 `json:"ip_version,omitempty"` // R3：4/6
}

// Count —— 条件数（供网关侧校验 dd/04 §2.1 上限）。
func (f FlowFilters) Count() int {
	n := 0
	for _, v := range []any{f.SrcIP, f.DstIP, f.SrcPort, f.DstPort, f.Proto, f.ZoneID, f.DeviceID, f.InIf, f.OutIf, f.IPVersion} {
		switch t := v.(type) {
		case string:
			if t != "" {
				n++
			}
		case uint32:
			if t != 0 {
				n++
			}
		case int32:
			if t != 0 {
				n++
			}
		}
	}
	return n
}

// FlowSearchReply —— Storage 查询响应（total_estimate 超 1,000 万由 Storage 截断）。
type FlowSearchReply struct {
	TotalEstimate int64                    `json:"total_estimate"`
	Rows          []map[string]any         `json:"rows"`
	QueryID       string                   `json:"query_id"`
	Cursor        json.RawMessage          `json:"cursor,omitempty"`
}

// ExportJobRequest —— 异步导出任务（docs/dd/04 §5.1）。
type ExportJobRequest struct {
	Type      string      `json:"type"` // flows|attack_flows|aggr|attacks
	AttackID  string      `json:"attack_id,omitempty"`
	TimeStart int64       `json:"time_start"`
	TimeEnd   int64       `json:"time_end"`
	Filters   FlowFilters `json:"filters,omitempty"`
	Format    string      `json:"format,omitempty"` // text|csv|jsonl（默认 text=docs/00 §7）
	Sample    string      `json:"sample,omitempty"` // raw|downscale_10x
}

// ExportJobStatus —— 任务状态响应。
type ExportJobStatus struct {
	JobID     string  `json:"job_id"`
	Status    string  `json:"status"` // queued|running|done|failed
	Progress  float64 `json:"progress,omitempty"`
	URL       string  `json:"url,omitempty"`
	ExpiresAt int64   `json:"expires_at,omitempty"`
	Error     string  `json:"error,omitempty"`
}

// StorageClient —— Storage 查询/导出/攻击分钟客户端接口。
type StorageClient interface {
	SearchFlows(ctx context.Context, req FlowSearchRequest) (*FlowSearchReply, error)
	CreateExportJob(ctx context.Context, req ExportJobRequest) (*ExportJobStatus, error)
	GetExportJob(ctx context.Context, jobID string) (*ExportJobStatus, error)
	// AttackMinutes —— attack_minutes 点查（R5 分钟明细表，docs/dd/04 §3）。
	AttackMinutes(ctx context.Context, attackID string, fromMs, toMs int64) ([]shared.AttackMinute, error)
}

// HTTPStorage —— Storage REST 客户端实现（base = LUCID_CONSOLE_STORAGE_URL）。
type HTTPStorage struct {
	base string
	http *http.Client
}

// NewHTTPStorage 构造；base 形如 http://host:port。
func NewHTTPStorage(base string) *HTTPStorage {
	return &HTTPStorage{
		base: strings.TrimRight(base, "/"),
		http: &http.Client{Timeout: 15 * time.Second},
	}
}

// SearchFlows 转发 R6 查询。
func (s *HTTPStorage) SearchFlows(ctx context.Context, req FlowSearchRequest) (*FlowSearchReply, error) {
	var reply FlowSearchReply
	if err := s.post(ctx, "/api/v1/flows/search", req, &reply); err != nil {
		return nil, err
	}
	return &reply, nil
}

// CreateExportJob 创建导出任务（202 语义）。
func (s *HTTPStorage) CreateExportJob(ctx context.Context, req ExportJobRequest) (*ExportJobStatus, error) {
	var reply ExportJobStatus
	if err := s.post(ctx, "/api/v1/export/jobs", req, &reply); err != nil {
		return nil, err
	}
	return &reply, nil
}

// GetExportJob 查询任务状态。
func (s *HTTPStorage) GetExportJob(ctx context.Context, jobID string) (*ExportJobStatus, error) {
	var reply ExportJobStatus
	if err := s.get(ctx, "/api/v1/export/jobs/"+url.PathEscape(jobID), &reply); err != nil {
		return nil, err
	}
	return &reply, nil
}

// AttackMinutes 点查攻击分钟明细。
func (s *HTTPStorage) AttackMinutes(ctx context.Context, attackID string, fromMs, toMs int64) ([]shared.AttackMinute, error) {
	var reply struct {
		Rows []shared.AttackMinute `json:"rows"`
	}
	q := fmt.Sprintf("/api/v1/attacks/%s/minutes?from_ms=%d&to_ms=%d",
		url.PathEscape(attackID), fromMs, toMs)
	if err := s.get(ctx, q, &reply); err != nil {
		return nil, err
	}
	return reply.Rows, nil
}

func (s *HTTPStorage) post(ctx context.Context, path string, body, out any) error {
	raw, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("encode request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.base+path, bytes.NewReader(raw))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	return s.do(req, out)
}

func (s *HTTPStorage) get(ctx context.Context, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.base+path, nil)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	return s.do(req, out)
}

func (s *HTTPStorage) do(req *http.Request, out any) error {
	resp, err := s.http.Do(req)
	if err != nil {
		return fmt.Errorf("%w: storage %s: %v", ErrNotReady, req.URL.Path, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return fmt.Errorf("read storage reply: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("storage %s: status %d: %s", req.URL.Path, resp.StatusCode, truncate(data, 256))
	}
	if out != nil && len(data) > 0 {
		if err := json.Unmarshal(data, out); err != nil {
			return fmt.Errorf("decode storage reply %s: %w", req.URL.Path, err)
		}
	}
	return nil
}

func truncate(b []byte, n int) string {
	if len(b) > n {
		return string(b[:n]) + "..."
	}
	return string(b)
}

// UnavailableStorage —— 降级桩：Storage 未部署时全部返回 ErrNotReady（httpapi 转 503）。
type UnavailableStorage struct{}

// SearchFlows 返回 ErrNotReady。
func (UnavailableStorage) SearchFlows(context.Context, FlowSearchRequest) (*FlowSearchReply, error) {
	return nil, ErrNotReady
}

// CreateExportJob 返回 ErrNotReady。
func (UnavailableStorage) CreateExportJob(context.Context, ExportJobRequest) (*ExportJobStatus, error) {
	return nil, ErrNotReady
}

// GetExportJob 返回 ErrNotReady。
func (UnavailableStorage) GetExportJob(context.Context, string) (*ExportJobStatus, error) {
	return nil, ErrNotReady
}

// AttackMinutes 返回 ErrNotReady。
func (UnavailableStorage) AttackMinutes(context.Context, string, int64, int64) ([]shared.AttackMinute, error) {
	return nil, ErrNotReady
}
