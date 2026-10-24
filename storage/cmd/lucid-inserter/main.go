// lucid-inserter —— CH 写入唯一通道（Kafka 消费 → 分片路由 → 批量落表，
// docs/09 §2/§8、docs/dd/04 §1.3）。
//
// walking skeleton：组装桩组件空跑——ChannelConsumer（内存消费桩）+
// demoCodec（JSON 演示编码，仅空跑；线格式 proto+lz4 见 docs/09 §2）+
// CHSink（clickhouse-go 桩）+ MemoryDeduper + Router + Pipeline。
// 真实 Kafka/CH/PG 接入 TODO 见模块 README。
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/SchearLoe/lucidnet/shared"
	"github.com/SchearLoe/lucidnet/storage/internal/inserter"
)

func main() {
	var (
		shards        = flag.Int("shards", 3, "ClickHouse 分片数（docs/hld/04 §3）")
		batchRows     = flag.Int("batch-rows", inserter.DefaultBatchMaxRows, "批量行数阈值（docs/dd/04 §1.3）")
		flushInterval = flag.Duration("flush-interval", inserter.DefaultFlushInterval, "flush 周期")
		kafkaBrokers  = flag.String("kafka", "", "Kafka brokers（空=内存消费桩）")
		chDsn         = flag.String("ch", "", "ClickHouse DSN（空=写桩，仅日志）")
		demo          = flag.Bool("demo", false, "注入演示消息跑通全链路后退出")
	)
	flag.Parse()
	log.SetFlags(log.Ltime | log.Lmicroseconds)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	router, err := inserter.NewRouter(*shards)
	if err != nil {
		log.Fatalf("router: %v", err)
	}
	sink := inserter.NewCHSink(*chDsn, log.Printf)
	dedup := inserter.NewMemoryDeduper(4096)
	consumer := inserter.NewChannelConsumer(256)

	pipeline, err := inserter.NewPipeline(consumer, demoCodec{}, sink, router,
		inserter.WithDeduper(dedup),
		inserter.WithBatchParams(*batchRows, *flushInterval),
		inserter.WithBadMessageHook(func(err error) { log.Printf("bad message: %v", err) }),
	)
	if err != nil {
		log.Fatalf("pipeline: %v", err)
	}

	if *kafkaBrokers != "" {
		log.Printf("real kafka consumer not landed yet (brokers=%s), running stub channel (TODO dd/04 §1.3)", *kafkaBrokers)
	}
	if *demo {
		if *batchRows > 4 {
			// 演示模式改小批量，避免等 50k 行/2s 才见落库日志
			pipeline, err = inserter.NewPipeline(consumer, demoCodec{}, sink, router,
				inserter.WithDeduper(dedup),
				inserter.WithBatchParams(4, *flushInterval),
				inserter.WithBadMessageHook(func(err error) { log.Printf("bad message: %v", err) }))
			if err != nil {
				log.Fatalf("pipeline(demo): %v", err)
			}
		}
		go func() {
			time.Sleep(100 * time.Millisecond)
			injectDemo(consumer)
			time.Sleep(300 * time.Millisecond)
			_ = consumer.Close() // 关闭通道 → 流水线尾刷退出
		}()
	}

	log.Printf("lucid-inserter: shards=%d batch=%d rows/%s stub=channel-consumer", *shards, *batchRows, *flushInterval)
	err = pipeline.Run(ctx)
	msgs, rows, deduped, bad, flushErrs := pipeline.StatsSnapshot()
	log.Printf("lucid-inserter exit: run_err=%v messages=%d rows_mapped=%d deduped=%d bad=%d flush_errs=%d",
		err, msgs, rows, deduped, bad, flushErrs)
	if err != nil {
		os.Exit(1)
	}
}

// injectDemo —— 按 docs/00 §3 topic 表投喂四类契约消息（JSON 演示编码）。
func injectDemo(c *inserter.ChannelConsumer) {
	base := time.Now().Add(-time.Minute).UnixMilli()

	// flows.raw：4 条明细（v4 映射 + v6 交替）
	flows := make([]shared.FlowRecord, 4)
	for i := range flows {
		rec := shared.FlowRecord{
			TimeStartMs: base + int64(i)*1000, TimeEndMs: base + int64(i)*1000 + 120,
			Exporter: fmt.Sprintf("10.0.0.%d", 1+i%2), DeviceID: 7,
			InIf: 12, OutIf: 15, SrcPort: 40000, DstPort: 443,
			Proto: 6, Packets: uint64(10 + i), Bytes: uint64(640 + i*100),
			TCPFlags: 0x02, SampleRate: 100, SrcAS: 65001, DstAS: 4808,
			AppID: 3, ZoneID: 101, IfRole: 3, ZoneSide: uint8(shared.ZoneSideDst),
		}
		if i%2 == 0 {
			rec.IPVersion = 4
			rec.SrcIP = [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 1, 2, 3, byte(4 + i)}
			rec.DstIP = [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 5, 6, 7, 8}
		} else {
			rec.IPVersion = 6
			rec.SrcIP = [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, byte(1 + i)}
			rec.DstIP = [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0x00, 0x80}
		}
		flows[i] = rec
	}
	inject(c, shared.TopicFlowsRaw, shared.FlowKey(101, "10.0.0.1"), mustJSON(map[string]any{"rows": flows}))

	// flows.aggr.minute：2 行聚合
	minute := time.Now().Add(-time.Minute).Unix() / 60 * 60
	aggr := shared.AggrMinuteBatch{BatchID: 9001, Rows: []shared.AggrRow{
		{Minute: minute, Exporter: "10.0.0.1", InIf: 12, Direction: shared.DirIn, ZoneID: 101,
			Proto: 6, DstPort: 443, BytesSum: 86400, PacketsSum: 120, FlowsCount: 12},
		{Minute: minute, Exporter: "10.0.0.2", InIf: 13, Direction: shared.DirOut, ZoneID: 202,
			Proto: 17, DstPort: 53, BytesSum: 6400, PacketsSum: 10, FlowsCount: 2},
	}}
	inject(c, shared.TopicFlowsAggrMinute, []byte("10.0.0.1"), mustJSON(aggr))

	// attacks.minutes：1 行分钟详情
	atk := shared.AttackMinuteBatch{BatchID: 9002, Rows: []shared.AttackMinute{{
		AttackID: "01JDEMOATTACK", MinuteEpoch: minute, BpsIn: 9_000_000_000, PpsIn: 8_000_000,
		NewFlows: 9999, SynRatio: 0.91, UdpRatio: 0.02,
		TopSources: []string{"1.1.1.1", "2.2.2.2"}, TopPorts: []uint32{443, 80},
	}}}
	inject(c, shared.TopicAttacksMinutes, []byte("01JDEMOATTACK"), mustJSON(atk))

	// alarms：AttackEvent + Alarm 两类信封
	envAttack := shared.AlarmEnvelope{Attack: &shared.AttackEvent{
		AttackID: "01JDEMOATTACK", ZoneID: 101, ZoneName: "客户A", AttackType: shared.AttackSYNFlood,
		TargetPrefix: "203.0.113.0/24", StartMs: base, EndMs: base + 60000,
		PeakBps: 9_000_000_000, PeakPps: 8_000_000, Confidence: 0.93,
		TopSources: []string{"1.1.1.1"}, Status: shared.AttackConfirmed,
	}}
	inject(c, shared.TopicAlarms, shared.FlowKey(101, ""), mustJSON(envAttack))
	envAlarm := shared.AlarmEnvelope{Alarm: &shared.Alarm{
		AlarmID: "alm-demo-1", Source: "analytics", Severity: shared.SeverityCritical,
		Category: shared.CategoryAttack, RaiseMs: base + 1000,
		Subject: "SYN flood detected", ZoneID: 101, AttackID: "01JDEMOATTACK",
	}}
	inject(c, shared.TopicAlarms, shared.FlowKey(101, ""), mustJSON(envAlarm))
}

func inject(c *inserter.ChannelConsumer, topic string, key, value []byte) {
	c.Inject(inserter.Message{Topic: topic, Key: key, Value: value, Timestamp: time.Now()})
	log.Printf("demo inject: topic=%s bytes=%d", topic, len(value))
}

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		log.Fatalf("demo marshal: %v", err)
	}
	return b
}

// demoCodec —— JSON 演示解码器（空跑专用；生产为 proto+lz4，docs/09 §2，
// gen/ 代码生成就绪后在 internal/inserter 替换 ProtoCodec）。
type demoCodec struct{}

type demoFlowsEnvelope struct {
	Rows []shared.FlowRecord `json:"rows"`
}

func (demoCodec) DecodeFlowsRaw(b []byte) ([]shared.FlowRecord, error) {
	var env demoFlowsEnvelope
	if err := json.Unmarshal(b, &env); err != nil {
		return nil, fmt.Errorf("demo decode flows.raw: %w", err)
	}
	return env.Rows, nil
}

func (demoCodec) DecodeAggrMinuteBatch(b []byte) (shared.AggrMinuteBatch, error) {
	var batch shared.AggrMinuteBatch
	if err := json.Unmarshal(b, &batch); err != nil {
		return shared.AggrMinuteBatch{}, fmt.Errorf("demo decode flows.aggr.minute: %w", err)
	}
	return batch, nil
}

func (demoCodec) DecodeAttackMinuteBatch(b []byte) (shared.AttackMinuteBatch, error) {
	var batch shared.AttackMinuteBatch
	if err := json.Unmarshal(b, &batch); err != nil {
		return shared.AttackMinuteBatch{}, fmt.Errorf("demo decode attacks.minutes: %w", err)
	}
	return batch, nil
}

func (demoCodec) DecodeAlarmEnvelope(b []byte) (shared.AlarmEnvelope, error) {
	var env shared.AlarmEnvelope
	if err := json.Unmarshal(b, &env); err != nil {
		return shared.AlarmEnvelope{}, fmt.Errorf("demo decode alarms: %w", err)
	}
	return env, nil
}
