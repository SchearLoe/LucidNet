package query

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestSearchHTTPOK —— 合法请求 → 200 {code:0} + SQL 回显 + query_id（骨架行为）。
func TestSearchHTTPOK(t *testing.T) {
	h := NewSearchHandler(NewBuilder())
	body := `{"time_start":1771901100,"time_end":1771902000,
	          "filters":{"dst_port":443,"zone_id":101},
	          "order_by":"bytes","desc":true,"page":1,"page_size":100}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/flows/search", strings.NewReader(body))
	rec := httptest.NewRecorder()
	h.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
	var env struct {
		Code int    `json:"code"`
		Msg  string `json:"msg"`
		Data struct {
			QueryID     string `json:"query_id"`
			SQL         string `json:"sql"`
			EstimateSQL string `json:"estimate_sql"`
			Rows        []any  `json:"rows"`
			CursorMode  bool   `json:"cursor_mode"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if env.Code != codeOK {
		t.Fatalf("code = %d, msg = %s", env.Code, env.Msg)
	}
	if env.Data.QueryID == "" {
		t.Error("missing query_id")
	}
	if !strings.Contains(env.Data.SQL, "ORDER BY bytes DESC") || !strings.Contains(env.Data.SQL, "dst_port = 443") {
		t.Errorf("sql echo wrong:\n%s", env.Data.SQL)
	}
	if len(env.Data.Rows) != 0 {
		t.Error("skeleton rows must be empty until CH executor lands")
	}
}

// TestSearchHTTPBadRequest —— 构建器错误 → 400 {code:40000}（表驱动样本）。
func TestSearchHTTPBadRequest(t *testing.T) {
	h := NewSearchHandler(nil).Routes()
	for _, body := range []string{
		"{not json",
		`{"time_start":0,"time_end":10,"filters":{"zone_id":1}}`,
		`{"time_start":1,"time_end":999999999,"filters":{"zone_id":1}}`,
		`{"time_start":1,"time_end":2,"filters":{}}`,
		`{"time_start":1,"time_end":2,"filters":{"zone_id":1},"page":51}`,
		`{"time_start":1,"time_end":2,"filters":{"zone_id":1},"fields":["evil"]}`,
	} {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/flows/search", strings.NewReader(body))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("body %s: status = %d, want 400 (%s)", body, rec.Code, rec.Body.String())
		}
		var env struct {
			Code int `json:"code"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &env)
		if env.Code != codeBadRequest {
			t.Errorf("body %s: envelope code = %d", body, env.Code)
		}
	}
}

// TestSearchHTTPMethodNotAllowed —— GET 拒绝。
func TestSearchHTTPMethodNotAllowed(t *testing.T) {
	h := NewSearchHandler(nil).Routes()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/flows/search", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	// 路由模式仅注册 POST：方法不匹配 → 404（ServeMux 语义）；handler 内亦有 405 兜底
	if rec.Code != http.StatusMethodNotAllowed && rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d", rec.Code)
	}
}
