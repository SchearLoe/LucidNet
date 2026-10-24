package httpapi

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/SchearLoe/lucidnet/console/internal/auth"
	"github.com/SchearLoe/lucidnet/console/internal/hub"
	"github.com/SchearLoe/lucidnet/console/internal/query"
	"github.com/SchearLoe/lucidnet/console/internal/ratelimit"
	"github.com/SchearLoe/lucidnet/console/internal/store"
	"github.com/SchearLoe/lucidnet/console/internal/upstream"
	"github.com/SchearLoe/lucidnet/console/internal/ws"
	"github.com/SchearLoe/lucidnet/shared"
)

// newTestServer —— 组装最小网关（内存读模型 + Storage 不可用桩 + dev token）。
func newTestServer(t *testing.T, strict bool) (*httptest.Server, string, *store.Memory) {
	t.Helper()
	mem := store.NewMemory(100, 100)
	h := hub.NewHub()
	log := slog.Default()

	const secret = "test-secret"
	verifier := auth.NewVerifier([]byte(secret))
	authMw := auth.NewMiddleware(verifier, strict,
		WriteUnauthorized,
		func(w http.ResponseWriter, r *http.Request) {
			denied := ""
			if p, ok := auth.DeniedPerm(r.Context()); ok {
				denied = string(p)
			}
			WriteForbidden(w, r, denied)
		},
	)
	handlers := &Handlers{
		Attacks: mem, Alarms: mem, Zones: mem,
		Storage:           upstream.UnavailableStorage{},
		BGP:               upstream.NewBGPClient("http://127.0.0.1:1"),
		Limiter:           ratelimit.New(1000, 1000),
		Log:               log,
		MaxQueryWindowSec: 6 * 3600,
	}
	root := Routes(handlers, authMw, ws.NewHandler(h, log))
	srv := httptest.NewServer(root)
	t.Cleanup(srv.Close)

	tok, err := auth.MintDevToken([]byte(secret), "tester", "tenant-a",
		[]auth.Permission{auth.PermZoneRead, auth.PermAttackRead, auth.PermAttackHandle,
			auth.PermFlowsQuery, auth.PermFlowsExport, auth.PermReportRead}, time.Hour)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	return srv, tok, mem
}

// doJSON 发起请求并解析 {code,msg,data} 信封。
func doJSON(t *testing.T, method, url, token, body string) (int, map[string]any, []byte) {
	t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, url, rd)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var env map[string]any
	_ = json.Unmarshal(raw, &env)
	return resp.StatusCode, env, raw
}

func TestHealthNoAuth(t *testing.T) {
	srv, _, _ := newTestServer(t, true)
	resp, err := http.Get(srv.URL + "/healthz")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("healthz = %d", resp.StatusCode)
	}
}

// TestAuthEnforced —— 未带 token → 401；带 token 无权限 → 403（含被拒权限码）。
func TestAuthEnforced(t *testing.T) {
	srv, _, _ := newTestServer(t, true)

	status, _, _ := doJSON(t, http.MethodGet, srv.URL+"/api/v1/attacks", "", "")
	if status != http.StatusUnauthorized {
		t.Fatalf("no token = %d, want 401", status)
	}

	tokNoPerm, _ := auth.MintDevToken([]byte("test-secret"), "u2", "t",
		[]auth.Permission{auth.PermMonitorRead}, time.Hour)
	status, env, _ := doJSON(t, http.MethodGet, srv.URL+"/api/v1/attacks", tokNoPerm, "")
	if status != http.StatusForbidden {
		t.Fatalf("no perm = %d, want 403", status)
	}
	if msg, _ := env["msg"].(string); !strings.Contains(msg, "attack:read") {
		t.Fatalf("msg should name denied perm: %v", env["msg"])
	}
}

// TestAttackListEnvelopeAndCSV —— R7 列表信封 + CSV 导出（喂内存读模型）。
func TestAttackListEnvelopeAndCSV(t *testing.T) {
	srv, tok, mem := newTestServer(t, true)
	mem.UpsertAttack(&shared.AttackEvent{
		AttackID: "at-1", ZoneID: 101, ZoneName: "客户A",
		AttackType: shared.AttackSYNFlood, Status: shared.AttackConfirmed,
		PeakBps: 12345678, Confidence: 0.9, StartMs: 1700000000000,
		TopSources: []string{"1.2.3.4"},
	})

	status, env, _ := doJSON(t, http.MethodGet, srv.URL+"/api/v1/attacks?page=1&page_size=10", tok, "")
	if status != http.StatusOK {
		t.Fatalf("attacks = %d", status)
	}
	if code, _ := env["code"].(float64); code != 0 {
		t.Fatalf("envelope code = %v", env["code"])
	}
	data, _ := json.Marshal(env["data"])
	if !strings.Contains(string(data), "at-1") {
		t.Fatalf("rows missing at-1: %s", data)
	}

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/v1/attacks?format=csv", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("csv: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/csv") {
		t.Fatalf("csv content-type = %s", ct)
	}
	if !bytes.Contains(raw, []byte("attack_id")) {
		t.Fatalf("csv header missing: %s", raw)
	}
}

// TestFlowsSearchValidation —— R6 网关侧约束（>6h 引导导出、缺条件、窗口倒置）。
func TestFlowsSearchValidation(t *testing.T) {
	srv, tok, _ := newTestServer(t, true)

	cases := []struct {
		name string
		body string
		want string
	}{
		{"window>6h", `{"time_start":1700000000,"time_end":1700028800,"filters":{"zone_id":1}}`, "异步导出"},
		{"no filter", `{"time_start":1700000000,"time_end":1700003600,"filters":{}}`, "至少 1 个维度条件"},
		{"bad range", `{"time_start":1700003600,"time_end":1700000000,"filters":{"zone_id":1}}`, "time_end"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			status, env, _ := doJSON(t, http.MethodPost, srv.URL+"/api/v1/flows/search", tok, tc.body)
			if status != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400: %v", status, env)
			}
			if msg, _ := env["msg"].(string); !strings.Contains(msg, tc.want) {
				t.Fatalf("msg %q missing %q", msg, tc.want)
			}
		})
	}
}

// TestUpstreamNotReady —— Storage 未部署 → 503（不伪造数据）；报表 M3 → 501。
func TestUpstreamNotReady(t *testing.T) {
	srv, tok, _ := newTestServer(t, true)

	status, _, _ := doJSON(t, http.MethodPost, srv.URL+"/api/v1/flows/search", tok,
		`{"time_start":1700000000,"time_end":1700003600,"filters":{"zone_id":101},"page_size":100}`)
	if status != http.StatusServiceUnavailable {
		t.Fatalf("flows search = %d, want 503", status)
	}

	status, _, _ = doJSON(t, http.MethodGet, srv.URL+"/api/v1/attacks/at-1/minutes", tok, "")
	if status != http.StatusServiceUnavailable {
		t.Fatalf("minutes = %d, want 503", status)
	}

	status, _, _ = doJSON(t, http.MethodGet, srv.URL+"/api/v1/reports", tok, "")
	if status != http.StatusNotImplemented {
		t.Fatalf("reports = %d, want 501", status)
	}
}

// TestZonesRealtimeAndAlarms —— R2 实时视图 + R7 告警列表信封。
func TestZonesRealtimeAndAlarms(t *testing.T) {
	srv, tok, mem := newTestServer(t, true)
	mem.UpdateZone(101, "客户A", 1e9, 2e8, 1e6, 2e5, 1, time.Now().UnixMilli())
	mem.AppendAlarm(&shared.Alarm{AlarmID: "al-1", ZoneID: 101, Severity: shared.SeverityCritical,
		Category: shared.CategoryAttack, RaiseMs: time.Now().UnixMilli(), Subject: "SYN Flood"})

	status, env, _ := doJSON(t, http.MethodGet, srv.URL+"/api/v1/zones/realtime", tok, "")
	if status != http.StatusOK {
		t.Fatalf("zones = %d", status)
	}
	data, _ := json.Marshal(env["data"])
	if !strings.Contains(string(data), `"zone_id":101`) {
		t.Fatalf("zones data missing zone 101: %s", data)
	}

	status, _, raw := doJSON(t, http.MethodGet, srv.URL+"/api/v1/alarms?severity=3", tok, "")
	if status != http.StatusOK || !strings.Contains(string(raw), "al-1") {
		t.Fatalf("alarms = %d: %s", status, raw)
	}
}

// 编译期断言：内存读模型实现全部三个读接口。
var (
	_ query.AttackReader   = (*store.Memory)(nil)
	_ query.AlarmReader    = (*store.Memory)(nil)
	_ query.RealtimeReader = (*store.Memory)(nil)
)
