// Package config —— lucid-broker 本地启动配置（env：LUCID_BROKER_*，docs/11 §8）。
//
// 注意区分两类配置：
//   - 本文件：进程静态引导配置（监听端口/etcd/Kafka 地址等），只经环境变量；
//   - 运行时配置（转发规则/分配表）：Master 写 etcd（docs/09 §5），admin 包 watch 下发，
//     模型定义见 internal/forwarder 与 internal/flb。
package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config —— lucid-broker 进程配置（Option 模式经由 FromEnv 构造）。
type Config struct {
	// NodeID 节点标识（Master 注册/心跳与 Prometheus node 标签）。
	NodeID string
	// ListenAddr UDP 监听地址（hld/01 §4：exporters→Broker 流协议入口）。
	ListenAddr string
	// ListenPorts 流协议入口端口（hld/01 §4：9995/9996/6343/2055…，端口可配）。
	ListenPorts []int
	// WorkersPerPort 每端口 SO_REUSEPORT socket 数（dd/01 §1：每 CPU 一进程模型）。
	WorkersPerPort int
	// RcvBufBytes SO_RCVBUF（dd/01 §2.5：≥64MB）。
	RcvBufBytes int

	// EtcdEndpoints etcd 集群（docs/09 §5：/lucid/assign/flow、/lucid/forward/rules watch）。
	EtcdEndpoints []string
	// AssignKey / RulesKey etcd 键（docs/09 §5 唯一权威，仅测试可覆盖）。
	AssignKey string
	RulesKey  string

	// KafkaBrokers Kafka 集群（flows.raw 等 topic 生产，docs/09 §2）。
	KafkaBrokers []string

	// MasterAddr Master gRPC 地址（注册/心跳，docs/09 §4；空=禁用）。
	MasterAddr string
	// HeartbeatInterval 心跳周期。
	HeartbeatInterval time.Duration

	// MetricsAddr Prometheus exporter 监听地址（dd/08 §2.2 端口基线：组件 01 → 9110）。
	MetricsAddr string

	// DefaultCollectors 分配表为空时的兜底 collector 列表（host:port）。
	DefaultCollectors []string
	// ProbeInterval / ProbeFailThreshold 探活节奏（dd/01 §2.3：1s×3 次失败标记 down）。
	ProbeInterval      time.Duration
	ProbeFailThreshold int
	// ProbeRestoreAfter 本地摘除后 Master 未纠正的恢复时限（dd/01 §2.3：60s 信 Master）。
	ProbeRestoreAfter time.Duration

	// ReplayWindow / ReplayMaxBytes 目的地断连重放环形缓冲策略
	// （dd/01 §4.3 + 任务二：5s 或 512MB 先到为准；0/负 = 禁用）。
	ReplayWindow   time.Duration
	ReplayMaxBytes int64
}

// 缺省值（对照 dd/01 / hld/01 / dd/08 §2.2）。
const (
	DefaultMetricsAddr       = ":9110"
	DefaultRcvBufBytes       = 64 << 20 // dd/01 §2.5：SO_RCVBUF ≥ 64MB
	DefaultWorkersPerPort    = 2
	DefaultHeartbeatInterval = 10 * time.Second
	DefaultProbeInterval     = 1 * time.Second
	DefaultProbeFailThresh   = 3
	DefaultProbeRestoreAfter = 60 * time.Second
	DefaultReplayWindow      = 5 * time.Second // dd/01 §4.3：断连重放窗口
	DefaultReplayMaxBytes    = 512 << 20       // dd/01 §4.3：环形 512MB
	DefaultAssignKey         = "/lucid/assign/flow"
	DefaultRulesKey          = "/lucid/forward/rules"
)

// FromEnv 从环境变量构造配置（LUCID_BROKER_*，docs/11 §8）。
func FromEnv() (Config, error) {
	var cfg Config
	var errs []error

	cfg.NodeID = envOr("LUCID_BROKER_NODE_ID", hostname())
	cfg.ListenAddr = envOr("LUCID_BROKER_LISTEN_ADDR", "0.0.0.0")
	if v := os.Getenv("LUCID_BROKER_LISTEN_PORTS"); v != "" {
		for _, p := range strings.Split(v, ",") {
			port, err := strconv.Atoi(strings.TrimSpace(p))
			if err != nil || port <= 0 || port > 65535 {
				errs = append(errs, fmt.Errorf("config: invalid LUCID_BROKER_LISTEN_PORTS entry %q", p))
				continue
			}
			cfg.ListenPorts = append(cfg.ListenPorts, port)
		}
	} else {
		// hld/01 §4：NetFlow 2055/9995/9996，sFlow 6343。
		cfg.ListenPorts = []int{2055, 9995, 9996, 6343}
	}
	cfg.WorkersPerPort = envInt("LUCID_BROKER_WORKERS_PER_PORT", DefaultWorkersPerPort)
	cfg.RcvBufBytes = envInt("LUCID_BROKER_RCVBUF_BYTES", DefaultRcvBufBytes)

	cfg.EtcdEndpoints = envList("LUCID_BROKER_ETCD_ENDPOINTS", []string{"127.0.0.1:2379"})
	cfg.AssignKey = envOr("LUCID_BROKER_ASSIGN_KEY", DefaultAssignKey)
	cfg.RulesKey = envOr("LUCID_BROKER_RULES_KEY", DefaultRulesKey)
	cfg.KafkaBrokers = envList("LUCID_BROKER_KAFKA_BROKERS", []string{"127.0.0.1:9092"})

	cfg.MasterAddr = envOr("LUCID_BROKER_MASTER_ADDR", "") // 空=禁用注册/心跳
	cfg.HeartbeatInterval = time.Duration(envInt("LUCID_BROKER_HEARTBEAT_INTERVAL_MS", int(DefaultHeartbeatInterval/time.Millisecond))) * time.Millisecond
	cfg.MetricsAddr = envOr("LUCID_BROKER_METRICS_ADDR", DefaultMetricsAddr)

	cfg.DefaultCollectors = envList("LUCID_BROKER_DEFAULT_COLLECTORS", nil)
	cfg.ProbeInterval = time.Duration(envInt("LUCID_BROKER_PROBE_INTERVAL_MS", int(DefaultProbeInterval/time.Millisecond))) * time.Millisecond
	cfg.ProbeFailThreshold = envInt("LUCID_BROKER_PROBE_FAIL_THRESHOLD", DefaultProbeFailThresh)
	cfg.ProbeRestoreAfter = time.Duration(envInt("LUCID_BROKER_PROBE_RESTORE_AFTER_MS", int(DefaultProbeRestoreAfter/time.Millisecond))) * time.Millisecond
	cfg.ReplayWindow = time.Duration(envInt("LUCID_BROKER_REPLAY_WINDOW_MS", int(DefaultReplayWindow/time.Millisecond))) * time.Millisecond
	cfg.ReplayMaxBytes = int64(envInt("LUCID_BROKER_REPLAY_MAX_BYTES", DefaultReplayMaxBytes))

	if len(cfg.ListenPorts) == 0 {
		errs = append(errs, errors.New("config: no listen ports"))
	}
	if cfg.WorkersPerPort <= 0 {
		cfg.WorkersPerPort = DefaultWorkersPerPort
	}
	if cfg.RcvBufBytes <= 0 {
		cfg.RcvBufBytes = DefaultRcvBufBytes
	}
	if cfg.ProbeFailThreshold <= 0 {
		cfg.ProbeFailThreshold = DefaultProbeFailThresh
	}
	return cfg, errors.Join(errs...)
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func envList(key string, def []string) []string {
	if v := os.Getenv(key); v != "" {
		var out []string
		for _, item := range strings.Split(v, ",") {
			if item = strings.TrimSpace(item); item != "" {
				out = append(out, item)
			}
		}
		if len(out) > 0 {
			return out
		}
	}
	return def
}

func hostname() string {
	h, err := os.Hostname()
	if err != nil || h == "" {
		return "broker-unknown"
	}
	return h
}
