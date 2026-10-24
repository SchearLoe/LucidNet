package export

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// call —— 执行单次 HTTP 请求。
func call(t *testing.T, h http.Handler, method, target, body string) *httptest.ResponseRecorder {
	t.Helper()
	var req *http.Request
	var err error
	if body == "" {
		req, err = http.NewRequest(method, target, nil)
	} else {
		req, err = http.NewRequest(method, target, strings.NewReader(body))
	}
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func decodeEnvelope(t *testing.T, rec *httptest.ResponseRecorder) (envelope, map[string]any) {
	t.Helper()
	var env envelope
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode envelope: %v（body=%s）", err, rec.Body.String())
	}
	data, _ := env.Data.(map[string]any)
	return env, data
}

// TestExportAPICreateAndGet —— 建任务 202 + 查状态 200（docs/dd/04 §5.1）。
func TestExportAPICreateAndGet(t *testing.T) {
	store := NewMemoryStore(nil)
	h := NewAPIHandler(store).Routes()

	rec := call(t, h, http.MethodPost, "/api/v1/export/jobs",
		`{"type":"flows","time_start":1771901100,"time_end":1771904700,
		 "filters":{"dst_port":443,"zone_id":101},"format":"text","sample":"raw"}`)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("create status = %d, body=%s", rec.Code, rec.Body.String())
	}
	env, data := decodeEnvelope(t, rec)
	if env.Code != codeOK {
		t.Fatalf("envelope code = %d, msg=%s", env.Code, env.Msg)
	}
	jobID, _ := data["job_id"].(string)
	if jobID == "" {
		t.Fatalf("missing job_id: %v", data)
	}

	rec = call(t, h, http.MethodGet, "/api/v1/export/jobs/"+jobID, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("get status = %d", rec.Code)
	}
	env, data = decodeEnvelope(t, rec)
	if env.Code != codeOK || data["status"] != "queued" {
		t.Fatalf("get = code %d, data %v", env.Code, data)
	}

	// 状态推进后回显 running/progress
	j, _ := store.Get(context.Background(), jobID)
	_ = j.Start()
	_ = store.Update(context.Background(), j)
	rec = call(t, h, http.MethodGet, "/api/v1/export/jobs/"+jobID, "")
	env, data = decodeEnvelope(t, rec)
	if data["status"] != "running" {
		t.Fatalf("status = %v, want running", data["status"])
	}
}

// TestExportAPIValidation —— 非法任务 400。
func TestExportAPIValidation(t *testing.T) {
	h := NewAPIHandler(NewMemoryStore(nil)).Routes()
	for _, body := range []string{
		`{"type":"bogus"}`,
		`{"type":"attack_flows"}`,
		`{"type":"flows","time_start":100,"time_end":50}`,
		`{"type":"flows","time_start":1,"time_end":999999999}`,
		`{"type":"flows","time_start":100,"time_end":200,"format":"xlsx"}`,
	} {
		rec := call(t, h, http.MethodPost, "/api/v1/export/jobs", body)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("body %s: status = %d, want 400 (%s)", body, rec.Code, rec.Body.String())
		}
		env, _ := decodeEnvelope(t, rec)
		if env.Code != codeBadRequest {
			t.Errorf("body %s: envelope code = %d", body, env.Code)
		}
	}
}

// TestExportAPINotFound —— 查询不存在任务 404。
func TestExportAPINotFound(t *testing.T) {
	h := NewAPIHandler(NewMemoryStore(nil)).Routes()
	rec := call(t, h, http.MethodGet, "/api/v1/export/jobs/ghost", "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
	env, _ := decodeEnvelope(t, rec)
	if env.Code != codeNotFound {
		t.Fatalf("envelope code = %d", env.Code)
	}
}

// TestExportAPIBadJSON —— 请求体非 JSON 400。
func TestExportAPIBadJSON(t *testing.T) {
	h := NewAPIHandler(NewMemoryStore(nil)).Routes()
	rec := call(t, h, http.MethodPost, "/api/v1/export/jobs", "{not json")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d", rec.Code)
	}
}
