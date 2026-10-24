// lucid-broker —— LucidNet 汇聚分流进程（docs/dd/01）：
// UDP 收包（FLB 分发 collector）+ R1 多目的转发（透传/代理重编码/再采样/Kafka 生产）
// + etcd watch 配置热更新 + Master 注册心跳 + Prometheus 指标。
package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/SchearLoe/lucidnet/broker/internal/broker"
	"github.com/SchearLoe/lucidnet/broker/internal/config"
	"github.com/SchearLoe/lucidnet/broker/internal/metrics"
)

func main() {
	if err := run(); err != nil {
		slog.Error("lucid-broker: fatal", "err", err)
		os.Exit(1)
	}
}

func run() error {
	// JSON 单行日志（docs/11 §9：固定字段 ts/level/module/msg/node/err）
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})).
		With("module", "broker")

	cfg, err := config.FromEnv()
	if err != nil {
		return err
	}
	log = log.With("node", cfg.NodeID)

	m := metrics.New(nil)

	engine, err := broker.New(cfg, m, log)
	if err != nil {
		return err
	}

	// Prometheus /metrics（dd/08 §2.2：组件 01 → 9110）
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	srv := &http.Server{Addr: cfg.MetricsAddr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Error("metrics http server exited", "addr", cfg.MetricsAddr, "err", err)
		}
	}()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	log.Info("lucid-broker: launching", "metrics_addr", cfg.MetricsAddr)

	err = engine.Run(ctx)
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	_ = srv.Shutdown(shutdownCtx)
	cancel()
	return err
}
