package upstream

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// MitigateRequest —— 一键处置预填（docs/dd/05 §5：POST /api/bgp/alarms，
// 带 attack_id/zone/top_sources，LucidBGP 处置表单预填）。
type MitigateRequest struct {
	AttackID   string   `json:"attack_id"`
	ZoneID     int32    `json:"zone_id"`
	ZoneName   string   `json:"zone_name,omitempty"`
	TopSources []string `json:"top_sources,omitempty"`
}

// BGPClient —— LucidBGP 联动客户端（R9；/api/bgp/* 反代之外的直调面）。
type BGPClient struct {
	base string
	http *http.Client
}

// NewBGPClient 构造。
func NewBGPClient(base string) *BGPClient {
	return &BGPClient{
		base: trimBase(base),
		http: &http.Client{Timeout: 10 * time.Second},
	}
}

// ForwardAlarm 转发攻击告警到 LucidBGP（处置表单预填）。
func (c *BGPClient) ForwardAlarm(ctx context.Context, req MitigateRequest) error {
	raw, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("encode bgp alarm: %w", err)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+"/api/bgp/alarms", bytes.NewReader(raw))
	if err != nil {
		return fmt.Errorf("build bgp request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(httpReq)
	if err != nil {
		return fmt.Errorf("%w: bgp /api/bgp/alarms: %v", ErrNotReady, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		return fmt.Errorf("bgp /api/bgp/alarms: status %d: %s", resp.StatusCode, data)
	}
	return nil
}

func trimBase(s string) string {
	for len(s) > 0 && s[len(s)-1] == '/' {
		s = s[:len(s)-1]
	}
	return s
}
