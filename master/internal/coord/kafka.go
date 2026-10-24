package coord

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"time"

	"github.com/segmentio/kafka-go"
	"google.golang.org/protobuf/proto"

	lucidnetv1 "github.com/SchearLoe/lucidnet/master/internal/masterpb"
	"github.com/SchearLoe/lucidnet/master/internal/registry"
	"github.com/SchearLoe/lucidnet/shared"
)

// Kafka cluster.heartbeat 副本通道消费（docs/00 §3：key=node；etcd lease 为主通道，
// 此为可选副本——未启用 gRPC 直连的组件经此上报心跳）。
//
// 消费组命名规范 <module>.<purpose>（docs/09 §2）：master.heartbeat
// （新增消费组需登记 docs/09 §2 —— 见最终报告契约变更项）。

// HBConsumer —— TopicClusterHB 消费者。
type HBConsumer struct {
	reader *kafka.Reader
	reg    *registry.Registry
	onAck  AckSink
}

// AckSink —— 心跳 ACK 上抛（装配层路由到 config.Store.Ack）。
type AckSink func(ctx context.Context, nodeID string, ack registry.CmdAck)

// NewHBConsumer 构造（brokers 为空则不启用，由装配层判断）。
func NewHBConsumer(brokers []string, reg *registry.Registry, onAck AckSink) *HBConsumer {
	if len(brokers) == 0 {
		return nil
	}
	return &HBConsumer{
		reader: kafka.NewReader(kafka.ReaderConfig{
			Brokers:        brokers,
			Topic:          shared.TopicClusterHB,
			GroupID:        "master.heartbeat",
			MinBytes:       1,
			MaxBytes:       1 << 20,
			CommitInterval: time.Second,
		}),
		reg:   reg,
		onAck: onAck,
	}
}

// Run 消费循环（阻塞；ctx 取消退出）。
func (c *HBConsumer) Run(ctx context.Context) {
	defer c.reader.Close()
	for {
		if err := ctx.Err(); err != nil {
			return
		}
		m, err := c.reader.FetchMessage(ctx)
		if err != nil {
			if errors.Is(err, io.EOF) || ctx.Err() != nil {
				return
			}
			log.Printf(`{"level":"warn","module":"master.coord","msg":"hb fetch","err":%q}`, err.Error())
			if !sleepCtx(ctx, time.Second) {
				return
			}
			continue
		}
		if err := c.handle(ctx, m); err != nil {
			log.Printf(`{"level":"warn","module":"master.coord","msg":"hb handle","err":%q}`, err.Error())
		}
		if err := c.reader.CommitMessages(ctx, m); err != nil {
			log.Printf(`{"level":"warn","module":"master.coord","msg":"hb commit","err":%q}`, err.Error())
		}
	}
}

func (c *HBConsumer) handle(ctx context.Context, m kafka.Message) error {
	var stat lucidnetv1.NodeStat
	if err := proto.Unmarshal(m.Value, &stat); err != nil {
		return fmt.Errorf("unmarshal NodeStat from %s: %w", shared.TopicClusterHB, err)
	}
	nodeID := stat.NodeId
	if nodeID == "" && len(m.Key) > 0 {
		nodeID = string(m.Key) // key=node 契约兜底
	}
	if nodeID == "" {
		return fmt.Errorf("heartbeat without node id")
	}
	if err := c.reg.Heartbeat(ctx, nodeID, tsOf(stat.TsMs), ""); err != nil {
		return fmt.Errorf("record hb for %s: %w", nodeID, err)
	}
	metrics, err := registry.ParseMetricsJSON([]byte(stat.MetricsJson))
	if err != nil {
		return fmt.Errorf("parse metrics for %s: %w", nodeID, err)
	}
	if err := c.reg.ObserveExporters(ctx, nodeID, metrics.Exporters); err != nil {
		return fmt.Errorf("observe exporters for %s: %w", nodeID, err)
	}
	if metrics.Ack != nil && c.onAck != nil {
		c.onAck(ctx, nodeID, *metrics.Ack)
	}
	return nil
}

// Close 关闭 reader。
func (c *HBConsumer) Close() error { return c.reader.Close() }

func tsOf(ms int64) time.Time {
	if ms <= 0 {
		return time.Time{}
	}
	return time.UnixMilli(ms)
}
