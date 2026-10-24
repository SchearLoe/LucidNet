// lucid-gateway —— LucidConsole API 网关（docs/09 §6：/api/v1/* 单点接入 +
// WS 实时推送）。M1-MVP 主链路：鉴权、展示查询（R2/R5/R7）、R6 转发 Storage、
// gateway.ws 消费推送。
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/SchearLoe/lucidnet/shared"

	"github.com/SchearLoe/lucidnet/console/internal/auth"
	"github.com/SchearLoe/lucidnet/console/internal/codec"
	"github.com/SchearLoe/lucidnet/console/internal/config"
	"github.com/SchearLoe/lucidnet/console/internal/httpapi"
	"github.com/SchearLoe/lucidnet/console/internal/hub"
	"github.com/SchearLoe/lucidnet/console/internal/ingest"
	"github.com/SchearLoe/lucidnet/console/internal/ratelimit"
	"github.com/SchearLoe/lucidnet/console/internal/store"
	"github.com/SchearLoe/lucidnet/console/internal/upstream"
	"github.com/SchearLoe/lucidnet/console/internal/ws"
)

// allPerms —— dev token 全量权限（联调用）。
var allPerms = []auth.Permission{
	auth.PermOverviewRead, auth.PermAnalysisRead, auth.PermZoneRead,
	auth.PermFlowsQuery, auth.PermFlowsExport, auth.PermAttackRead,
	auth.PermAttackHandle, auth.PermReportRead, auth.PermReportManage,
	auth.PermMonitorRead, auth.PermAdminManage,
}

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	devToken := flag.String("dev-token", "", "签发联调 JWT（uid）；非空则打印 token 后退出（仅本地联调）")
	devTenant := flag.String("dev-tenant", "default", "dev-token 租户")
	devTTL := flag.Duration("dev-ttl", 12*time.Hour, "dev-token 有效期")
	flag.Parse()

	cfg, err := config.Load()
	if err != nil {
		log.Error("config load failed", "module", "gateway", "err", err)
		os.Exit(1)
	}

	if *devToken != "" {
		tok, err := auth.MintDevToken([]byte(cfg.JWTSecret), *devToken, *devTenant, allPerms, *devTTL)
		if err != nil {
			log.Error("mint dev token failed", "module", "gateway", "err", err)
			os.Exit(1)
		}
		_, _ = fmt.Println(tok)
		return
	}

	// —— 读模型：内存近端缓存（gateway.ws 消费 alarms 喂数据）——
	mem := store.NewMemory(cfg.RecentAttacksCap, cfg.RecentAlarmsCap)
	h := hub.NewHub()

	// —— 上游客户端（Storage 并行开发中：未部署时降级 503）——
	storageClient := upstream.NewHTTPStorage(cfg.StorageURL)
	bgp := upstream.NewBGPClient(cfg.BGPURL)

	// —— 鉴权（docs/dd/07：HS256 与 Master 共享密钥，claims={uid,tenant,roles,exp}）——
	verifier := auth.NewVerifier([]byte(cfg.JWTSecret))
	authMw := auth.NewMiddleware(verifier, cfg.AuthStrict,
		httpapi.WriteUnauthorized,
		func(w http.ResponseWriter, r *http.Request) {
			denied := ""
			if p, ok := auth.DeniedPerm(r.Context()); ok {
				denied = string(p)
			}
			httpapi.WriteForbidden(w, r, denied)
		},
	)

	// —— REST ——
	handlers := &httpapi.Handlers{
		Attacks:           mem,
		Alarms:            mem,
		Zones:             mem,
		Storage:           storageClient,
		BGP:               bgp,
		Limiter:           ratelimit.New(cfg.FlowsQueryQPS, cfg.FlowsQueryBurst),
		Log:               log,
		MaxQueryWindowSec: 6 * 3600,
	}
	stream := ws.NewHandler(h, log)
	root := httpapi.Routes(handlers, authMw, stream)

	srv := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           root,
		ReadHeaderTimeout: 10 * time.Second,
	}

	// —— Kafka 消费泵（gateway.ws；broker 未配置时不阻塞 HTTP 启动，WS 空转）——
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if len(cfg.KafkaBrokers) == 0 {
		log.Warn("no kafka brokers configured, ws stream will stay empty (dev mode)",
			"module", "gateway", "group", shared.GroupGatewayWS)
	} else {
		go runIngest(ctx, cfg, mem, h, log)
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	log.Info("lucid-gateway listening",
		"module", "gateway", "addr", cfg.HTTPAddr,
		"storage", cfg.StorageURL, "bgp", cfg.BGPURL,
		"group", shared.GroupGatewayWS, "topics", "alarms,bgp.mitigations")
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Error("http server failed", "module", "gateway", "err", err)
		os.Exit(1)
	}
	log.Info("lucid-gateway stopped", "module", "gateway")
}

// runIngest 启动 gateway.ws 消费泵；失败延迟重试直至 ctx 取消（Kafka 未就绪不致命）。
func runIngest(ctx context.Context, cfg config.Config, mem *store.Memory, h *hub.Hub, log *slog.Logger) {
	dec := chooseCodec(log)
	for {
		group, err := ingest.NewFranzGroup(cfg.KafkaBrokers, shared.GroupGatewayWS,
			[]string{shared.TopicAlarms, shared.TopicBGPMitigations}, cfg.KafkaDialTimeout)
		if err != nil {
			log.Error("kafka consumer create failed", "module", "gateway", "err", err)
		} else {
			pump := ingest.NewPump(group, dec, &ingestSink{mem: mem, hub: h}, log)
			log.Info("ingest pump started", "module", "gateway",
				"group", shared.GroupGatewayWS, "codec", codecName(dec))
			if err := pump.Run(ctx); err != nil && ctx.Err() == nil {
				log.Error("ingest pump exited", "module", "gateway", "err", err)
			}
			_ = group.Close()
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(5 * time.Second):
		}
	}
}

// chooseCodec —— 线格式选择：gen/go proto 代码未落地（docs/09 §0），M1 默认
// JSONCodec（联调/E2E）；LUCID_CONSOLE_CODEC=proto 显式选择 proto+lz4（当前为桩）。
func chooseCodec(log *slog.Logger) codec.Codec {
	switch os.Getenv("LUCID_CONSOLE_CODEC") {
	case "proto":
		log.Warn("using proto+lz4 codec stub; decode will fail until gen/ lands (docs/09 §0)", "module", "gateway")
		return codec.ProtoCodec{}
	default:
		log.Info("using json codec for gateway.ws consumption (dev; wire contract remains proto+lz4)", "module", "gateway")
		return codec.JSONCodec{}
	}
}

func codecName(c codec.Codec) string {
	switch c.(type) {
	case codec.ProtoCodec:
		return "proto+lz4(stub)"
	default:
		return "json(dev)"
	}
}

// ingestSink —— 泵下游组合：内存近端缓存 + WS hub（ingest.Sink）。
type ingestSink struct {
	mem *store.Memory
	hub *hub.Hub
}

func (s *ingestSink) UpsertAttack(a *shared.AttackEvent) { s.mem.UpsertAttack(a) }
func (s *ingestSink) AppendAlarm(a *shared.Alarm)        { s.mem.AppendAlarm(a) }
func (s *ingestSink) Publish(m hub.Message)              { s.hub.Publish(m) }
