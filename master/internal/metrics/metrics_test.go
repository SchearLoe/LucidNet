package metrics

import (
	"errors"
	"testing"
	"time"

	dto "github.com/prometheus/client_model/go"
)

// gatherMetric 按 name 取指标族（不存在返回 nil）。
func gatherMetric(t *testing.T, m *Metrics, name string) *dto.MetricFamily {
	t.Helper()
	families, err := m.reg.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	for _, f := range families {
		if f.GetName() == name {
			return f
		}
	}
	return nil
}

// seriesValue 取指定标签组合的序列值（counter/gauge 通用；缺失返回 -1）。
func seriesValue(t *testing.T, f *dto.MetricFamily, labels map[string]string) float64 {
	t.Helper()
	for _, mf := range f.GetMetric() {
		got := map[string]string{}
		for _, lp := range mf.GetLabel() {
			got[lp.GetName()] = lp.GetValue()
		}
		match := len(got) == len(labels)
		for k, v := range labels {
			if got[k] != v {
				match = false
			}
		}
		if match {
			if c := mf.GetCounter(); c != nil {
				return c.GetValue()
			}
			if g := mf.GetGauge(); g != nil {
				return g.GetValue()
			}
		}
	}
	return -1
}

// TestPublishMetrics —— 发布成功/失败计数与耗时直方图。
func TestPublishMetrics(t *testing.T) {
	m := New()
	m.PublishAttempt(nil, 5*time.Millisecond)
	m.PublishAttempt(nil, 10*time.Millisecond)
	m.PublishAttempt(errors.New("etcd down"), 20*time.Millisecond)

	f := gatherMetric(t, m, "lucid_master_config_publish_total")
	if f == nil {
		t.Fatal("lucid_master_config_publish_total missing")
	}
	if got := seriesValue(t, f, map[string]string{"result": "ok"}); got != 2 {
		t.Fatalf("ok = %v, want 2", got)
	}
	if got := seriesValue(t, f, map[string]string{"result": "error"}); got != 1 {
		t.Fatalf("error = %v, want 1", got)
	}
	h := gatherMetric(t, m, "lucid_master_config_publish_seconds")
	if h == nil || len(h.GetMetric()) != 1 || h.GetMetric()[0].GetHistogram().GetSampleCount() != 3 {
		t.Fatalf("publish seconds histogram = %v", h)
	}
}

// TestAckPartialAndOutbox —— partial 计数与补偿队列深度 gauge。
func TestAckPartialAndOutbox(t *testing.T) {
	m := New()
	m.AckPartial()
	m.AckPartial()
	m.SetOutboxDepth(7)
	f := gatherMetric(t, m, "lucid_master_config_ack_partial_total")
	if f == nil || f.GetMetric()[0].GetCounter().GetValue() != 2 {
		t.Fatalf("ack partial = %v", f)
	}
	g := gatherMetric(t, m, "lucid_master_outbox_pending")
	if g == nil || g.GetMetric()[0].GetGauge().GetValue() != 7 {
		t.Fatalf("outbox pending = %v", g)
	}
}

// TestNodeDistribution —— 节点分布按 role×state 聚合（scrape 时采样）。
func TestNodeDistribution(t *testing.T) {
	m := New()
	m.SetNodeSource(func() []NodeState {
		return []NodeState{
			{Role: "collector", State: "online"},
			{Role: "collector", State: "online"},
			{Role: "collector", State: "draining"},
			{Role: "broker", State: "offline", Degraded: true},
		}
	})
	f := gatherMetric(t, m, "lucid_master_nodes")
	if f == nil {
		t.Fatal("lucid_master_nodes missing")
	}
	if got := seriesValue(t, f, map[string]string{"role": "collector", "state": "online"}); got != 2 {
		t.Fatalf("collector online = %v, want 2", got)
	}
	if got := seriesValue(t, f, map[string]string{"role": "collector", "state": "draining"}); got != 1 {
		t.Fatalf("collector draining = %v, want 1", got)
	}
	if got := seriesValue(t, f, map[string]string{"role": "broker", "state": "offline"}); got != 1 {
		t.Fatalf("broker offline = %v, want 1", got)
	}
	d := gatherMetric(t, m, "lucid_master_nodes_degraded")
	if d == nil || d.GetMetric()[0].GetGauge().GetValue() != 1 {
		t.Fatalf("degraded = %v", d)
	}
	// 采样源清空 → 序列消失（不残留陈旧状态）
	m.SetNodeSource(func() []NodeState { return nil })
	if f := gatherMetric(t, m, "lucid_master_nodes"); f != nil && len(f.GetMetric()) != 0 {
		t.Fatalf("stale series = %v", f.GetMetric())
	}
}

// TestRESTRequests —— REST 计数按路由模式 × 状态码。
func TestRESTRequests(t *testing.T) {
	m := New()
	m.AddRESTRequest("GET /api/v1/admin/nodes", 200)
	m.AddRESTRequest("GET /api/v1/admin/nodes", 200)
	m.AddRESTRequest("GET /api/v1/admin/nodes", 401)
	f := gatherMetric(t, m, "lucid_master_rest_requests_total")
	if f == nil {
		t.Fatal("lucid_master_rest_requests_total missing")
	}
	if got := seriesValue(t, f, map[string]string{"route": "GET /api/v1/admin/nodes", "code": "200"}); got != 2 {
		t.Fatalf("200 = %v, want 2", got)
	}
	if got := seriesValue(t, f, map[string]string{"route": "GET /api/v1/admin/nodes", "code": "401"}); got != 1 {
		t.Fatalf("401 = %v, want 1", got)
	}
}

// TestHandlerServes —— /metrics handler 可抓取且含 master 指标。
// （注：lucid_master_nodes 与 rest_requests_total 为有子序列才产出 family——
// 空集群/零请求时不输出空壳序列，属预期语义。）
func TestHandlerServes(t *testing.T) {
	m := New()
	m.PublishAttempt(nil, time.Millisecond)
	m.AckPartial()
	m.SetOutboxDepth(1)
	m.AddRESTRequest("GET /healthz", 200)
	m.SetNodeSource(func() []NodeState {
		return []NodeState{{Role: "collector", State: "online"}}
	})
	h := m.Handler()
	if h == nil {
		t.Fatal("handler nil")
	}
	families, err := m.reg.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	names := map[string]bool{}
	for _, f := range families {
		names[f.GetName()] = true
	}
	for _, want := range []string{
		"lucid_master_config_publish_total", "lucid_master_config_publish_seconds",
		"lucid_master_config_ack_partial_total", "lucid_master_outbox_pending",
		"lucid_master_rest_requests_total", "lucid_master_nodes", "lucid_master_nodes_degraded",
		"go_goroutines", // 附带 Go runtime 采集器
	} {
		if !names[want] {
			t.Errorf("metric %s not registered (have %v)", want, names)
		}
	}
	// 空 sampling 不 panic（无节点 → 无 nodes 序列，degraded=0）
	m.SetNodeSource(nil)
	if _, err := m.reg.Gather(); err != nil {
		t.Fatalf("gather with nil source: %v", err)
	}
}
