// Package metrics —— lucid-master Prometheus exporter（docs/11 §9 命名规范：
// lucid_<组件>_<名词>[_<单位后缀>]；计数器 _total；直方图 _seconds；标签只含有界
// 枚举（role/state/result/route/code），禁高基数——节点 ID/scope 键/IP 只进日志）。
package metrics

import (
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Metrics —— master 控制面全量指标（独立 registry，不复用全局默认表）。
type Metrics struct {
	reg *prometheus.Registry

	mu         sync.Mutex
	nodeSource func() []NodeState

	// 节点分布（scrape 时经 nodeSource 采样，避免事件驱动漂移）
	nodeCollect nodeCollector

	// 配置发布链路
	publishTotal   *prometheus.CounterVec // result=ok|error
	publishSeconds prometheus.Histogram
	ackPartial     prometheus.Counter

	// etcd 补偿队列
	outboxPending prometheus.Gauge

	// REST 管理面
	restRequests *prometheus.CounterVec // route=ServeMux 路由模式（编译期路由表，有界）
}

// NodeState —— 节点状态快照单条（标签口径：role 6 值 × state 4 值，有界枚举）。
type NodeState struct {
	Role     string
	State    string
	Degraded bool
}

// New 构造并注册全部指标（自带 Go runtime / process 采集器）。
func New() *Metrics {
	reg := prometheus.NewRegistry()
	reg.MustRegister(collectors.NewGoCollector())
	reg.MustRegister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	f := promauto.With(reg)
	m := &Metrics{
		reg: reg,
		publishTotal: f.NewCounterVec(prometheus.CounterOpts{
			Name: "lucid_master_config_publish_total",
			Help: "Config publish attempts to etcd (first try and outbox retries), by result.",
		}, []string{"result"}),
		publishSeconds: f.NewHistogram(prometheus.HistogramOpts{
			Name:    "lucid_master_config_publish_seconds",
			Help:    "Config publish attempt duration (etcd put).",
			Buckets: []float64{0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1, 5, 10},
		}),
		ackPartial: f.NewCounter(prometheus.CounterOpts{
			Name: "lucid_master_config_ack_partial_total",
			Help: "Config versions marked partial (ACK timeout 180s, dd/07 §5).",
		}),
		outboxPending: f.NewGauge(prometheus.GaugeOpts{
			Name: "lucid_master_outbox_pending",
			Help: "Pending entries in the persistent config publish outbox (etcd compensation queue).",
		}),
		restRequests: f.NewCounterVec(prometheus.CounterOpts{
			Name: "lucid_master_rest_requests_total",
			Help: "REST admin API requests by route pattern and HTTP status code.",
		}, []string{"route", "code"}),
	}
	m.nodeCollect = nodeCollector{
		source:       m.nodeStates,
		nodesDesc:    prometheus.NewDesc("lucid_master_nodes", "Nodes by role and state.", []string{"role", "state"}, nil),
		degradedDesc: prometheus.NewDesc("lucid_master_nodes_degraded", "Nodes flagged degraded (heartbeat silence > 30s).", nil, nil),
	}
	reg.MustRegister(m.nodeCollect)
	// result 桶预置，避免抓取早期序列缺失
	m.publishTotal.WithLabelValues("ok")
	m.publishTotal.WithLabelValues("error")
	return m
}

// Handler Prometheus 抓取端点（挂 REST :9141 /metrics）。
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.reg, promhttp.HandlerOpts{})
}

// SetNodeSource 节点状态采样源（装配层注入 registry 快照；nil 安全）。
func (m *Metrics) SetNodeSource(fn func() []NodeState) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.nodeSource = fn
}

func (m *Metrics) nodeStates() []NodeState {
	m.mu.Lock()
	fn := m.nodeSource
	m.mu.Unlock()
	if fn == nil {
		return nil
	}
	return fn()
}

// nodeCollector scrape 时采样节点分布（自定义 Collector：无事件耦合、无漂移）。
type nodeCollector struct {
	source       func() []NodeState
	nodesDesc    *prometheus.Desc
	degradedDesc *prometheus.Desc
}

// Describe 实现 prometheus.Collector。
func (c nodeCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.nodesDesc
	ch <- c.degradedDesc
}

// Collect 实现 prometheus.Collector。
func (c nodeCollector) Collect(ch chan<- prometheus.Metric) {
	if c.source == nil {
		return
	}
	type key struct{ role, state string }
	counts := map[key]float64{}
	degraded := 0.0
	for _, n := range c.source() {
		counts[key{n.Role, n.State}]++
		if n.Degraded {
			degraded++
		}
	}
	for k, v := range counts {
		ch <- prometheus.MustNewConstMetric(c.nodesDesc, prometheus.GaugeValue, v, k.role, k.state)
	}
	ch <- prometheus.MustNewConstMetric(c.degradedDesc, prometheus.GaugeValue, degraded)
}

// PublishAttempt 记录一次 etcd 发布尝试（首投与补偿重投共用；docs/09 §5）。
func (m *Metrics) PublishAttempt(err error, elapsed time.Duration) {
	result := "ok"
	if err != nil {
		result = "error"
	}
	m.publishTotal.WithLabelValues(result).Inc()
	m.publishSeconds.Observe(elapsed.Seconds())
}

// AckPartial 记录一次 ACK 超时标 partial。
func (m *Metrics) AckPartial() { m.ackPartial.Inc() }

// SetOutboxDepth 补偿队列 pending 深度。
func (m *Metrics) SetOutboxDepth(n int) { m.outboxPending.Set(float64(n)) }

// AddRESTRequest 记录一次 REST 请求（route = ServeMux 编译期路由模式，如
// "GET /api/v1/admin/nodes/{id}"；无动态值，非高基数）。
func (m *Metrics) AddRESTRequest(route string, code int) {
	m.restRequests.WithLabelValues(route, strconv.Itoa(code)).Inc()
}
