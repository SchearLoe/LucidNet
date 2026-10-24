// Package producer —— flows.raw 生产（dd/02 §4）。
//
// key = shared.FlowKey(zone_id, exporter)（zone_id 4B 大端 + exporter，09 §2：
// 同客户同分区，检测并行无锁）；序列化 proto+lz4（proto 生成接入前，开发实现用 JSON 行）。
package producer

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/SchearLoe/lucidnet/shared"
)

// 批量/背压参数（dd/02 §4 缺省值；骨架常量即契约）。
const (
	DefaultLinger         = 50 * time.Millisecond // producer linger
	DefaultBatchMaxBytes  = 64 << 10              // 批量上限 64KB
	DefaultMaxBufferBytes = 100 << 20             // 背压阈值 100MB：超限丢最旧批次
)

// ErrKafkaNotImplemented —— franz-go 实现桩（骨架阶段未接通真实 Kafka）。
var ErrKafkaNotImplemented = errors.New("kafka flow producer not implemented (franz-go pending, dd/02 §4)")

// FlowProducer —— 流记录生产接口。
//
// 语义：UDP 端到端（dd/02 §4）—— Produce 不因集群慢而阻塞解码；
// 实现内部按背压策略丢弃（计数 flow_backpressure_drop）。
type FlowProducer interface {
	// Produce —— 投递一条（实现可内部批量/缓冲）。
	Produce(ctx context.Context, rec *shared.FlowRecord) error
	// Flush —— 冲刷缓冲（优雅退出前调用；ctx 超时即放弃剩余）。
	Flush(ctx context.Context) error
	// Close —— 释放资源。
	Close() error
}

// KafkaConfig —— franz-go 生产参数（dd/02 §4：linger 50ms / batch 64KB / lz4 / acks=leader）。
type KafkaConfig struct {
	Brokers []string
	Topic   string // 缺省 shared.TopicFlowsRaw
	// Linger —— 批量等待窗口。
	Linger time.Duration
	// BatchMaxBytes —— 批量字节上限。
	BatchMaxBytes int
	// MaxBufferBytes —— 生产者缓冲上限；超限丢最旧批次并计数
	// lucid_collector_flow_backpressure_drop_total（dd/02 §4 背压，docs/11 §9 命名）。
	MaxBufferBytes int
	// Compression —— "lz4"（缺省，dd/02 §4）。
	Compression string
}

// DefaultKafkaConfig —— dd/02 §4 缺省参数。
func DefaultKafkaConfig(brokers []string) KafkaConfig {
	return KafkaConfig{
		Brokers:        brokers,
		Topic:          shared.TopicFlowsRaw,
		Linger:         DefaultLinger,
		BatchMaxBytes:  DefaultBatchMaxBytes,
		MaxBufferBytes: DefaultMaxBufferBytes,
		Compression:    "lz4",
	}
}

// KafkaFlowProducer —— franz-go 实现桩。
//
// TODO(franz-go)（dd/02 §4）：
//  1. kgo.NewClient（SeedBrokers、RecordPartitioner 带 key（FlowKey）、
//     ProduceRequestTimeout=Linger、MaxBufferedRecords=MaxBufferBytes/Linger 批量语义、lz4、acks=leader）；
//  2. Produce → kgo.Produce 异步；缓冲水位 >MaxBufferBytes 丢最旧批次 + 计数
//     lucid_collector_flow_backpressure_drop_total（UDP 语义端到端）；
//  3. value = proto FlowRecord + lz4（gen/go 接入后），key = shared.FlowKey(rec.ZoneID, rec.Exporter)；
//  4. Flush/Close 透传 client.Flush / client.Close；
//  5. 指标：lucid_collector_kafka_producer_queue（dd/02 §6）。
type KafkaFlowProducer struct {
	cfg KafkaConfig
}

// NewKafka —— 构造桩（参数校验；真实客户端 TODO(franz-go)）。
func NewKafka(cfg KafkaConfig) (*KafkaFlowProducer, error) {
	if len(cfg.Brokers) == 0 {
		return nil, fmt.Errorf("kafka producer: no brokers")
	}
	if cfg.Topic == "" {
		cfg.Topic = shared.TopicFlowsRaw
	}
	return &KafkaFlowProducer{cfg: cfg}, nil
}

// Config —— 只读配置副本（诊断用）。
func (p *KafkaFlowProducer) Config() KafkaConfig { return p.cfg }

// Produce —— TODO(franz-go)；桩恒 ErrKafkaNotImplemented。
func (p *KafkaFlowProducer) Produce(ctx context.Context, rec *shared.FlowRecord) error {
	return fmt.Errorf("produce %s: %w", p.cfg.Topic, ErrKafkaNotImplemented)
}

// Flush —— TODO(franz-go)；桩恒 ErrKafkaNotImplemented。
func (p *KafkaFlowProducer) Flush(ctx context.Context) error {
	return fmt.Errorf("flush %s: %w", p.cfg.Topic, ErrKafkaNotImplemented)
}

// Close —— 桩无资源，恒成功。
func (p *KafkaFlowProducer) Close() error { return nil }
