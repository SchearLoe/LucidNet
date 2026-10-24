// Package metrics —— lucid-broker Prometheus exporter（docs/11 §9 命名规范：
// lucid_<组件>_<名词>[_<单位后缀>]；计数器 _total；标签白名单，禁高基数 IP 标签）。
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Metrics —— broker 全量指标（实现 forwarder.Counters 与 flb.Counters 接口）。
type Metrics struct {
	reg prometheus.Registerer

	ingestPackets prometheus.Counter
	ingestDropped prometheus.Counter

	flbForwarded       prometheus.Counter
	flbDrop            prometheus.Counter
	flbUnknown         prometheus.Counter
	flbCollectorUp     *prometheus.GaugeVec // dest=collector addr（有界）
	flbAssignExporters prometheus.Gauge

	fwdRecords     *prometheus.CounterVec // rule_id, dest
	fwdDrop        *prometheus.CounterVec // rule_id, dest
	fwdDestDown    *prometheus.GaugeVec   // dest
	fwdResample    *prometheus.GaugeVec   // dest
	proxyDecodeErr prometheus.Counter

	kafkaProduce  *prometheus.CounterVec // topic
	kafkaError    *prometheus.CounterVec // topic
	rulesVersion  prometheus.Gauge
	assignVersion prometheus.Gauge
}

// New 注册全部指标到 reg（nil=默认注册表）。
func New(reg prometheus.Registerer) *Metrics {
	if reg == nil {
		reg = prometheus.DefaultRegisterer
	}
	f := promauto.With(reg)
	return &Metrics{
		reg: reg,
		ingestPackets: f.NewCounter(prometheus.CounterOpts{
			Name: "lucid_broker_ingest_packets_total", Help: "UDP flow datagrams received.",
		}),
		ingestDropped: f.NewCounter(prometheus.CounterOpts{
			Name: "lucid_broker_ingest_dropped_total", Help: "Datagrams dropped at ingress (listener errors).",
		}),
		flbForwarded: f.NewCounter(prometheus.CounterOpts{
			Name: "lucid_broker_flb_forwarded_total", Help: "Datagrams forwarded to collectors (FLB).",
		}),
		flbDrop: f.NewCounter(prometheus.CounterOpts{
			Name: "lucid_broker_flb_drop_total", Help: "Datagrams dropped by FLB (no healthy collector).",
		}),
		flbUnknown: f.NewCounter(prometheus.CounterOpts{
			Name: "lucid_broker_flb_unknown_exporter_total", Help: "Datagrams from exporters missing in assign table (dd/01 §2.4).",
		}),
		flbCollectorUp: f.NewGaugeVec(prometheus.GaugeOpts{
			Name: "lucid_broker_flb_collector_up", Help: "Collector health as seen by broker probes (1=up).",
		}, []string{"dest"}),
		flbAssignExporters: f.NewGauge(prometheus.GaugeOpts{
			Name: "lucid_broker_flb_assign_exporters", Help: "Exporters in current assign table.",
		}),
		fwdRecords: f.NewCounterVec(prometheus.CounterOpts{
			Name: "lucid_broker_forward_records_total", Help: "Flow records forwarded per rule/dest (dd/01 §5).",
		}, []string{"rule_id", "dest"}),
		fwdDrop: f.NewCounterVec(prometheus.CounterOpts{
			Name: "lucid_broker_forward_drop_total", Help: "Flow records/datagrams dropped per rule/dest.",
		}, []string{"rule_id", "dest"}),
		fwdDestDown: f.NewGaugeVec(prometheus.GaugeOpts{
			Name: "lucid_broker_forward_dest_down", Help: "Forward destination health (1=down, dd/01 §4.3).",
		}, []string{"dest"}),
		fwdResample: f.NewGaugeVec(prometheus.GaugeOpts{
			Name: "lucid_broker_forward_resample_ratio", Help: "Configured keep ratio per destination (dd/01 §5).",
		}, []string{"dest"}),
		proxyDecodeErr: f.NewCounter(prometheus.CounterOpts{
			Name: "lucid_broker_proxy_decode_errors_total", Help: "Proxy-path decode failures.",
		}),
		kafkaProduce: f.NewCounterVec(prometheus.CounterOpts{
			Name: "lucid_broker_kafka_produce_total", Help: "Records accepted by Kafka producer per topic.",
		}, []string{"topic"}),
		kafkaError: f.NewCounterVec(prometheus.CounterOpts{
			Name: "lucid_broker_kafka_produce_errors_total", Help: "Kafka delivery failures per topic.",
		}, []string{"topic"}),
		rulesVersion: f.NewGauge(prometheus.GaugeOpts{
			Name: "lucid_broker_forward_rules_version", Help: "Current forward rules snapshot version.",
		}),
		assignVersion: f.NewGauge(prometheus.GaugeOpts{
			Name: "lucid_broker_flb_assign_version", Help: "Current assign table version.",
		}),
	}
}

// —— ingest ——

// AddIngestPackets 累计收包。
func (m *Metrics) AddIngestPackets(n int) { m.ingestPackets.Add(float64(n)) }

// AddIngestDropped 累计入口丢弃。
func (m *Metrics) AddIngestDropped(n int) { m.ingestDropped.Add(float64(n)) }

// —— flb.Counters ——

// FlbForwarded 实现 flb.Counters。
func (m *Metrics) FlbForwarded(n int) { m.flbForwarded.Add(float64(n)) }

// FlbDrop 实现 flb.Counters。
func (m *Metrics) FlbDrop(n int) { m.flbDrop.Add(float64(n)) }

// FlbUnknownExporter 实现 flb.Counters。
func (m *Metrics) FlbUnknownExporter() { m.flbUnknown.Inc() }

// SetCollectorHealth 实现 flb.Counters。
func (m *Metrics) SetCollectorHealth(addr string, up bool) {
	v := 1.0
	if !up {
		v = 0
	}
	m.flbCollectorUp.WithLabelValues(addr).Set(v)
}

// SetAssignVersion 分配表版本。
func (m *Metrics) SetAssignVersion(v uint64) { m.assignVersion.Set(float64(v)) }

// SetAssignExporters 分配表 exporter 数。
func (m *Metrics) SetAssignExporters(n int) { m.flbAssignExporters.Set(float64(n)) }

// —— forwarder.Counters ——

// ForwardRecords 实现 forwarder.Counters。
func (m *Metrics) ForwardRecords(ruleID, dest string, n int) {
	m.fwdRecords.WithLabelValues(ruleID, dest).Add(float64(n))
}

// ForwardDrop 实现 forwarder.Counters。
func (m *Metrics) ForwardDrop(ruleID, dest string, n int) {
	m.fwdDrop.WithLabelValues(ruleID, dest).Add(float64(n))
}

// SetDestDown 实现 forwarder.Counters。
func (m *Metrics) SetDestDown(dest string, down bool) {
	v := 1.0
	if !down {
		v = 0
	}
	m.fwdDestDown.WithLabelValues(dest).Set(v)
}

// SetResampleRatio 实现 forwarder.Counters。
func (m *Metrics) SetResampleRatio(dest string, ratio float64) {
	m.fwdResample.WithLabelValues(dest).Set(ratio)
}

// ProxyDecodeError 实现 forwarder.Counters。
func (m *Metrics) ProxyDecodeError() { m.proxyDecodeErr.Inc() }

// KafkaProduce 实现 forwarder.Counters。
func (m *Metrics) KafkaProduce(topic string, n int) {
	m.kafkaProduce.WithLabelValues(topic).Add(float64(n))
}

// KafkaProduceError 实现 forwarder.Counters。
func (m *Metrics) KafkaProduceError(topic string, n int) {
	m.kafkaError.WithLabelValues(topic).Add(float64(n))
}

// SetRulesVersion 规则快照版本。
func (m *Metrics) SetRulesVersion(v uint64) { m.rulesVersion.Set(float64(v)) }
