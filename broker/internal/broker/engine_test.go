package broker

import (
	"context"
	"testing"
	"time"

	"github.com/SchearLoe/lucidnet/broker/internal/config"
)

// TestNewAssembly —— 引擎组装烟测：无 Kafka（空 brokers）时不阻断数据面。
func TestNewAssembly(t *testing.T) {
	cfg := config.Config{
		NodeID:             "broker-test",
		ListenAddr:         "127.0.0.1",
		ListenPorts:        []int{20550},
		WorkersPerPort:     1,
		RcvBufBytes:        1 << 20,
		EtcdEndpoints:      []string{"127.0.0.1:23790"}, // 不可达：watch 启动报错但不影响组件构造
		KafkaBrokers:       nil,                         // 无 Kafka：forwarder sink 为 nil
		ProbeInterval:      200 * time.Millisecond,
		ProbeFailThreshold: 2,
		ProbeRestoreAfter:  time.Second,
	}
	e, err := New(cfg, nil, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if e.Forwarder() == nil || e.Dispatcher() == nil || e.Producer() != nil {
		t.Fatal("assembly components wrong")
	}

	// Start：ingest 监听成功；etcd 不可达 watch 仅记日志（数据面不受影响）
	ctx, cancel := context.WithCancel(context.Background())
	if err := e.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	cancel() // 触发 watch/probe 协程退出
	e.Stop() // 优雅关停（幂等；含 wg.Wait）
	e.Stop() // 二次调用验证幂等
}
