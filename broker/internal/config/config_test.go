package config

import (
	"testing"
	"time"
)

func TestFromEnvDefaults(t *testing.T) {
	t.Setenv("LUCID_BROKER_NODE_ID", "broker-01")
	// 其余未设 → 缺省
	cfg, err := FromEnv()
	if err != nil {
		t.Fatalf("FromEnv: %v", err)
	}
	if cfg.NodeID != "broker-01" {
		t.Errorf("node = %s", cfg.NodeID)
	}
	if len(cfg.ListenPorts) != 4 { // 2055/9995/9996/6343（hld/01 §4）
		t.Errorf("ports = %v", cfg.ListenPorts)
	}
	if cfg.MetricsAddr != DefaultMetricsAddr {
		t.Errorf("metrics = %s", cfg.MetricsAddr)
	}
	if cfg.RcvBufBytes != DefaultRcvBufBytes {
		t.Errorf("rcvbuf = %d", cfg.RcvBufBytes)
	}
	if cfg.AssignKey != DefaultAssignKey || cfg.RulesKey != DefaultRulesKey {
		t.Errorf("etcd keys = %s %s", cfg.AssignKey, cfg.RulesKey)
	}
}

func TestFromEnvOverride(t *testing.T) {
	t.Setenv("LUCID_BROKER_LISTEN_PORTS", "2055,9995")
	t.Setenv("LUCID_BROKER_ETCD_ENDPOINTS", "e1:2379, e2:2379")
	t.Setenv("LUCID_BROKER_KAFKA_BROKERS", "k1:9092")
	t.Setenv("LUCID_BROKER_MASTER_ADDR", "10.0.0.1:9140")
	t.Setenv("LUCID_BROKER_HEARTBEAT_INTERVAL_MS", "5000")
	t.Setenv("LUCID_BROKER_PROBE_FAIL_THRESHOLD", "5")
	cfg, err := FromEnv()
	if err != nil {
		t.Fatalf("FromEnv: %v", err)
	}
	if len(cfg.ListenPorts) != 2 || cfg.ListenPorts[0] != 2055 {
		t.Errorf("ports = %v", cfg.ListenPorts)
	}
	if len(cfg.EtcdEndpoints) != 2 || cfg.EtcdEndpoints[1] != "e2:2379" {
		t.Errorf("etcd = %v", cfg.EtcdEndpoints)
	}
	if cfg.MasterAddr != "10.0.0.1:9140" {
		t.Errorf("master = %s", cfg.MasterAddr)
	}
	if cfg.HeartbeatInterval != 5*time.Second {
		t.Errorf("hb = %v", cfg.HeartbeatInterval)
	}
	if cfg.ProbeFailThreshold != 5 {
		t.Errorf("probe thresh = %d", cfg.ProbeFailThreshold)
	}
}

func TestFromEnvInvalidPort(t *testing.T) {
	t.Setenv("LUCID_BROKER_LISTEN_PORTS", "abc")
	if _, err := FromEnv(); err == nil {
		t.Fatal("invalid port must error")
	}
}
