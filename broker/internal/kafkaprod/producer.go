// Package kafkaprod —— Broker Kafka 生产（franz-go/kgo），docs/09 §2 实现约束：
// 序列化 proto + lz4；producer linger=50ms、batch≥64KB。Broker 侧 topic 产出 =
// 转发规则 kafka 目的地（缺省 flows.raw，key=FlowKey(zone_id, exporter)）。
package kafkaprod

import (
	"context"
	"fmt"
	"time"

	"github.com/twmb/franz-go/pkg/kgo"
)

// 契约参数（docs/09 §2）。
const (
	Linger           = 50 * time.Millisecond
	BatchMaxBytes    = 1 << 20 // ≥64KB 批量目标（docs/09 §2 batch≥64KB），默认 1MB
	MaxBufferedBytes = 256 << 20
	DeliveryTimeout  = 10 * time.Second
)

// Producer —— kgo 客户端封装（forwarder.KafkaSink 实现）。
type Producer struct {
	cl       *kgo.Client
	onProked func(topic string, n int, err error)
}

// New 构造（brokers 空→错误；连接由 kgo 惰性建立）。
func New(brokers []string, onProked func(topic string, n int, err error)) (*Producer, error) {
	if len(brokers) == 0 {
		return nil, fmt.Errorf("kafkaprod: no kafka brokers configured")
	}
	if onProked == nil {
		onProked = func(string, int, error) {}
	}
	cl, err := kgo.NewClient(
		kgo.SeedBrokers(brokers...),
		// docs/09 §2：linger=50ms、batch≥64KB、proto+lz4。
		kgo.ProducerLinger(Linger),
		kgo.ProducerBatchMaxBytes(BatchMaxBytes),
		kgo.ProducerBatchCompression(kgo.Lz4Compression()),
		kgo.RequiredAcks(kgo.AllISRAcks()),
		kgo.RecordDeliveryTimeout(DeliveryTimeout),
		kgo.ProduceRequestTimeout(DeliveryTimeout),
		// 缓冲打满 → TryProduce 快速失败计数丢弃，绝不阻塞收包路径。
		kgo.MaxBufferedBytes(MaxBufferedBytes),
		kgo.MaxBufferedRecords(1<<20),
	)
	if err != nil {
		return nil, fmt.Errorf("kafkaprod: new kgo client: %w", err)
	}
	return &Producer{cl: cl, onProked: onProked}, nil
}

// Produce 实现 forwarder.KafkaSink：异步生产（缓冲满即丢弃计数，UDP 语义）。
func (p *Producer) Produce(ctx context.Context, topic string, key []byte, value []byte) {
	rec := kgo.Record{Topic: topic, Key: key, Value: value}
	p.cl.Produce(ctx, &rec, func(r *kgo.Record, err error) {
		if err != nil {
			p.onProked(r.Topic, 1, err)
			return
		}
		p.onProked(r.Topic, 1, nil)
	})
}

// TryProduce —— 非阻塞生产；缓冲满由投递回调以 err 计数（kgo 语义），绝不阻塞收包。
func (p *Producer) TryProduce(topic string, key []byte, value []byte) {
	rec := kgo.Record{Topic: topic, Key: key, Value: value}
	p.cl.TryProduce(context.Background(), &rec, func(r *kgo.Record, err error) {
		if err != nil {
			p.onProked(r.Topic, 1, err)
			return
		}
		p.onProked(r.Topic, 1, nil)
	})
}

// Flush 尽力投递缓冲（优雅停机）。
func (p *Producer) Flush(ctx context.Context) { p.cl.Flush(ctx) }

// Close 关停（先 Flush）。
func (p *Producer) Close(ctx context.Context) {
	p.cl.Flush(ctx)
	p.cl.Close()
}

// Client 暴露底层客户端（初始化 topic 等运维操作用）。
func (p *Producer) Client() *kgo.Client { return p.cl }
