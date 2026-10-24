// Command lucid-analytics —— 流式分析组件（walking skeleton，docs/dd/03）。
//
// 组装：Source(JSONL 回放 / Kafka 桩) → 单消费者 Pipeline →
// Detector(Zone 秒级检测) + Aggregator(分钟聚合) + AttackFSM → alarms 发布。
// 检测/聚合/状态机状态仅被 Pipeline 主循环 goroutine 访问（结构化免锁，dd/03 §1）。
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/SchearLoe/lucidnet/analytics/internal/aggregate"
	"github.com/SchearLoe/lucidnet/analytics/internal/alarm"
	"github.com/SchearLoe/lucidnet/analytics/internal/consume"
	"github.com/SchearLoe/lucidnet/analytics/internal/detector"
	"github.com/SchearLoe/lucidnet/analytics/internal/fsm"
	"github.com/SchearLoe/lucidnet/analytics/internal/rtkeys"
	"github.com/SchearLoe/lucidnet/shared"
)

// logBatchSink —— flows.aggr.minute 批日志出口（开发实现；
// 生产实现为 Kafka 生产者，09 §2：key=exporter，由 Storage Inserter 落 CH）。
type logBatchSink struct{ log *slog.Logger }

func (s logBatchSink) PublishMinuteBatch(batch *shared.AggrMinuteBatch) error {
	var minute int64
	if len(batch.Rows) > 0 {
		minute = batch.Rows[0].Minute
	}
	s.log.Info("aggr minute batch",
		"module", "analytics", "minute", minute,
		"rows", len(batch.Rows), "batch_id", batch.BatchID)
	return nil
}

// config —— 启动配置（flag + 环境变量 LUCID_ANALYTICS_*，docs/11 §8）。
type config struct {
	mode            string // dev(jsonl 回放) | kafka(桩) | demo(生成演示流量并回放)
	jsonlPath       string
	brokers         string
	group           string
	internalExclude bool
}

func loadConfig() config {
	cfg := config{}
	flag.StringVar(&cfg.mode, "mode", envOr("LUCID_ANALYTICS_MODE", "demo"), "dev|kafka|demo")
	flag.StringVar(&cfg.jsonlPath, "jsonl", os.Getenv("LUCID_ANALYTICS_JSONL"), "JSONL 回放文件（dev 模式）")
	flag.StringVar(&cfg.brokers, "brokers", envOr("LUCID_ANALYTICS_KAFKA_BROKERS", "127.0.0.1:9092"), "Kafka brokers（kafka 模式，桩）")
	flag.StringVar(&cfg.group, "group", envOr("LUCID_ANALYTICS_GROUP", shared.GroupAnalyticsDetect), "消费组（须为登记组名，09 §2）")
	flag.BoolVar(&cfg.internalExclude, "internal-exclude", true, "互联过滤开关（dd/03 §2.2）")
	flag.Parse()
	return cfg
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func main() {
	if err := run(loadConfig()); err != nil {
		slog.Error("lucid-analytics exit", "module", "analytics", "err", err)
		os.Exit(1)
	}
}

func run(cfg config) error {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// 发布器：内存 channel 开发实现（M2 换 alarm.NewKafkaPublisher，09 §2）
	pub := alarm.NewDevPublisher(1024)
	defer pub.Close()
	go drainAlarms(pub)

	// Redis 实时键桩（09 §6 rt:* 前缀）：攻击证据快照 rt:evidence:{attack_id}
	// TTL 24h；TopN rt:topn:{dim}:{ts} TTL 10m 待 TopN 算子（README TODO 4）。
	// M2 换真实 Redis 客户端实现 rtkeys.Store。
	rtStore := rtkeys.NewDevStore()

	// 状态机 + 检测引擎 + 聚合器
	fsmCfg := fsm.DefaultConfig()
	mgr := fsm.New(fsmCfg, alarm.AttackEmitter{Pub: pub, Evidence: rtStore})
	det := detector.New(detector.DefaultConfig(), mgr)

	batchSink := logBatchSink{log: logger}
	agg, err := aggregate.NewAggregator(batchSink, aggregate.WithInternalExclude(cfg.internalExclude))
	if err != nil {
		return fmt.Errorf("analytics: build aggregator: %w", err)
	}

	// 流源
	var src consume.Source
	switch cfg.mode {
	case "kafka":
		src, err = consume.NewKafkaSource(splitBrokers(cfg.brokers), cfg.group)
		if err != nil {
			return fmt.Errorf("analytics: kafka source: %w", err)
		}
	case "dev":
		if cfg.jsonlPath == "" {
			return fmt.Errorf("analytics: dev mode requires -jsonl path")
		}
		src = consume.NewJSONLSource(cfg.jsonlPath, consume.WithPaced())
	case "demo":
		path, err := writeDemoTraffic()
		if err != nil {
			return fmt.Errorf("analytics: demo traffic: %w", err)
		}
		slog.Info("demo traffic generated", "module", "analytics", "path", path)
		src = consume.NewJSONLSource(path, consume.WithPaced())
	default:
		return fmt.Errorf("analytics: unknown mode %q", cfg.mode)
	}

	// 单消费者事件循环（结构化免锁）
	pipe, err := consume.NewPipeline(src,
		func(rec *shared.FlowRecord) error {
			if err := det.Add(rec); err != nil {
				return fmt.Errorf("detector add: %w", err)
			}
			return agg.Add(rec)
		},
		func() {
			det.Tick()
			mgr.Tick()
		},
	)
	if err != nil {
		return fmt.Errorf("analytics: build pipeline: %w", err)
	}

	slog.Info("lucid-analytics started",
		"module", "analytics", "mode", cfg.mode,
		"topic_in", shared.TopicFlowsRaw, "topic_out", shared.TopicAlarms)
	runErr := pipe.Run(ctx)

	// 收尾：发布未到期分钟（grace 内数据由下次进程续接，dd/03 §8）
	rows, flushErr := agg.Flush()
	dst := det.Stats()
	ast := pub.Stats()
	slog.Info("lucid-analytics stopped",
		"module", "analytics",
		"records_in", dst.RecordsIn, "no_zone", dst.NoZone, "stale_drop", dst.StaleDrop,
		"srcagg_overflow", dst.SrcAggOverflow, "sweep_cells", dst.SweepCells,
		"zones", det.ZoneCount(), "active_attacks", mgr.ActiveCount(),
		"flushed_rows", rows,
		"alarms_published", ast.Published, "alarms_dropped", ast.DroppedAlarm,
		"evidence_keys", rtStore.Len(),
		"run_err", runErr, "flush_err", flushErr)
	if runErr != nil && ctx.Err() == nil {
		return fmt.Errorf("analytics: pipeline: %w", runErr)
	}
	return nil
}

// drainAlarms —— 消费内存告警通道（演示输出；生产实现为 Kafka 生产者）。
func drainAlarms(pub *alarm.DevPublisher) {
	for env := range pub.Alarms() {
		if env.Attack != nil {
			b, _ := json.Marshal(env.Attack)
			slog.Info("attack event", "module", "analytics", "attack", string(b))
		}
		if env.Alarm != nil {
			b, _ := json.Marshal(env.Alarm)
			slog.Info("alarm", "module", "analytics", "alarm", string(b))
		}
	}
}

func splitBrokers(s string) []string {
	var out []string
	for _, p := range filepath.SplitList(s) {
		if p != "" {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		out = []string{s}
	}
	return out
}

// writeDemoTraffic —— 生成 30s 演示流量 JSONL（基于当前墙钟）：
// zone 101：平稳背景 + 第 10s 起 8s 的 SYN Flood；
// zone 202：/24 扫段（40 目的 × 单源微量包，跨两个 10s 窗）；
// zone 303：平稳对照。
func writeDemoTraffic() (string, error) {
	base := time.Now().Unix() + 2
	type scenario struct {
		zone int32
		gen  func(sec int64) []shared.FlowRecord
	}
	v4 := func(a, b, c, d byte) [16]byte {
		var ip [16]byte
		ip[10], ip[11] = 0xff, 0xff
		ip[12], ip[13], ip[14], ip[15] = a, b, c, d
		return ip
	}
	const (
		protoTCP = 6
		flagSYN  = 1 << 1
	)
	scenarios := []scenario{
		{zone: 101, gen: func(sec int64) []shared.FlowRecord {
			var recs []shared.FlowRecord
			off := sec - base
			for i := 0; i < 20; i++ { // 平稳背景 20 流/s
				recs = append(recs, shared.FlowRecord{
					TimeStartMs: sec * 1000, Exporter: "demo-exp", IPVersion: 4,
					Proto: protoTCP, SrcIP: v4(10, 0, byte(i), 1), DstIP: v4(10, 1, 2, 3),
					SrcPort: 40000, DstPort: 443, Packets: 4, Bytes: 500,
					TCPFlags: 0x18, ZoneID: 101, ZoneSide: 1, IfRole: 3,
				})
			}
			if off >= 10 && off < 18 { // SYN Flood：6,000 新流/s
				for i := 0; i < 6000; i++ {
					recs = append(recs, shared.FlowRecord{
						TimeStartMs: sec * 1000, Exporter: "demo-exp", IPVersion: 4,
						Proto: protoTCP, SrcIP: v4(10, byte(i>>8), byte(i), byte(sec%250)), DstIP: v4(10, 1, 2, 3),
						SrcPort: uint32(20000 + i%40000), DstPort: 443, Packets: 1, Bytes: 100,
						TCPFlags: flagSYN, ZoneID: 101, ZoneSide: 1, IfRole: 3,
					})
				}
			}
			return recs
		}},
		{zone: 202, gen: func(sec int64) []shared.FlowRecord {
			var recs []shared.FlowRecord
			for d := 0; d < 4; d++ { // 4 新目的/s（10s 窗 40 目的）
				dstIdx := int(sec-base)%10*4 + d
				recs = append(recs, shared.FlowRecord{
					TimeStartMs: sec * 1000, Exporter: "demo-exp", IPVersion: 4,
					Proto: protoTCP, SrcIP: v4(172, 16, 0, 1), DstIP: v4(203, 0, 113, byte(dstIdx+1)),
					SrcPort: 33333, DstPort: uint32(dstIdx) + 1, Packets: 1, Bytes: 60,
					TCPFlags: flagSYN, ZoneID: 202, ZoneSide: 1, IfRole: 3,
				})
			}
			return recs
		}},
		{zone: 303, gen: func(sec int64) []shared.FlowRecord {
			var recs []shared.FlowRecord
			for i := 0; i < 10; i++ {
				recs = append(recs, shared.FlowRecord{
					TimeStartMs: sec * 1000, Exporter: "demo-exp", IPVersion: 4,
					Proto: 17, SrcIP: v4(192, 168, 0, byte(i)), DstIP: v4(10, 3, 3, 3),
					SrcPort: 50000, DstPort: 53, Packets: 2, Bytes: 200,
					ZoneID: 303, ZoneSide: 1, IfRole: 3,
				})
			}
			return recs
		}},
	}

	f, err := os.CreateTemp("", "lucid-demo-*.jsonl")
	if err != nil {
		return "", err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	for s := int64(0); s < 30; s++ {
		sec := base + s
		for _, sc := range scenarios {
			for _, rec := range sc.gen(sec) {
				if err := enc.Encode(&rec); err != nil {
					return "", fmt.Errorf("encode demo record: %w", err)
				}
			}
		}
	}
	return f.Name(), nil
}
