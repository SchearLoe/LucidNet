package master

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"
)

// TestDevModeBootSmoke —— 开发模式（无 PG/etcd/Kafka）端到端冒烟：
// 健康探针 → 登录 → 节点/分配表查询。端口冲突时跳过。
func TestDevModeBootSmoke(t *testing.T) {
	opts := Default()
	opts.GrpcAddr = "127.0.0.1:19140"
	opts.HTTPAddr = "127.0.0.1:19141"
	opts.AdminPassword = "smoke-pw"

	srv, err := New(opts)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- srv.Run(ctx) }()
	stopped := make(chan struct{})
	go func() {
		if err := <-errCh; err != nil {
			t.Errorf("run: %v", err)
		}
		close(stopped)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-stopped:
		case <-time.After(10 * time.Second):
			t.Error("server did not stop in time")
		}
	})

	base := "http://" + opts.HTTPAddr
	// 等待 HTTP 就绪
	deadline := time.Now().Add(5 * time.Second)
	for {
		if resp, err := http.Get(base + "/healthz"); err == nil {
			_ = resp.Body.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("http server not ready in 5s")
		}
		time.Sleep(20 * time.Millisecond)
	}
	// healthz
	health := mustGET(t, base+"/healthz")
	if !strings.Contains(health, `"status":"ok"`) {
		t.Fatalf("healthz = %s", health)
	}
	// 登录（预置平台管理员）
	var login struct {
		Code int `json:"code"`
		Data struct {
			AccessToken string `json:"access_token"`
		} `json:"data"`
	}
	decode(t, mustPOST(t, base+"/api/v1/auth/login",
		`{"username":"admin","password":"smoke-pw"}`), &login)
	if login.Code != 0 || login.Data.AccessToken == "" {
		t.Fatalf("login resp = %+v", login)
	}
	// 错误口令拒绝
	var bad struct {
		Code int `json:"code"`
	}
	decode(t, mustPOST(t, base+"/api/v1/auth/login",
		`{"username":"admin","password":"nope"}`), &bad)
	if bad.Code == 0 {
		t.Fatal("bad password accepted")
	}
	// 鉴权后的节点列表（初始为空数组）
	var nodes struct {
		Data []json.RawMessage `json:"data"`
	}
	decode(t, mustAuthGET(t, base+"/api/v1/admin/nodes", login.Data.AccessToken), &nodes)
	if nodes.Data == nil {
		t.Fatal("nodes data should be empty array")
	}
	// 分配表（启动即计算，空表）
	var table struct {
		Data struct {
			Version uint64 `json:"version"`
		} `json:"data"`
	}
	decode(t, mustAuthGET(t, base+"/api/v1/admin/assign/table", login.Data.AccessToken), &table)
	if table.Data.Version == 0 {
		t.Fatal("assign table version should be >= 1 after boot")
	}
	// 无 token 401
	if code := statusOf(t, mustReq(t, "GET", base+"/api/v1/admin/nodes", nil, "")); code != 401 {
		t.Fatalf("unauth status = %d, want 401", code)
	}
	// 优雅停机由 Cleanup 验证
}

func mustGET(t *testing.T, url string) string {
	t.Helper()
	return bodyOf(t, mustReq(t, "GET", url, nil, ""))
}

func mustPOST(t *testing.T, url, body string) string {
	t.Helper()
	return bodyOf(t, mustReq(t, "POST", url, strings.NewReader(body), ""))
}

func mustAuthGET(t *testing.T, url, token string) string {
	t.Helper()
	return bodyOf(t, mustReq(t, "GET", url, nil, token))
}

func mustReq(t *testing.T, method, url string, body *strings.Reader, token string) *http.Response {
	t.Helper()
	var req *http.Request
	var err error
	if body != nil {
		req, err = http.NewRequest(method, url, body)
	} else {
		req, err = http.NewRequest(method, url, nil)
	}
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

func bodyOf(t *testing.T, resp *http.Response) string {
	t.Helper()
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(resp.Body)
	return buf.String()
}

func statusOf(t *testing.T, resp *http.Response) int {
	t.Helper()
	_, _ = resp.Body.Read(make([]byte, 1))
	return resp.StatusCode
}

func decode(t *testing.T, body string, v any) {
	t.Helper()
	if err := json.Unmarshal([]byte(body), v); err != nil {
		t.Fatalf("decode %q: %v", body, err)
	}
}
