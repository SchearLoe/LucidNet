// Package ingest —— Kafka 消费（消费组 gateway.ws，docs/09 §2 组名即接口）：
// topics alarms / bgp.mitigations → 解码 → 内存近端缓存 + WS hub 广播。
package ingest

import (
	"context"
	"errors"
	"sync"
	"time"

	kgo "github.com/twmb/franz-go/pkg/kgo"

	"github.com/SchearLoe/lucidnet/shared"
)

// Consumer —— 消费组语义最小接口（与 storage 口径一致：拉取-处理-提交）。
// 生产实现 = franz-go 消费组；测试 = ChannelConsumer。
type Consumer interface {
	// Polls 阻塞拉取一批记录；ctx 取消时返回 ctx.Err()。
	Polls(ctx context.Context) ([]Record, error)
	// CommitMarks 提交一批记录位点。
	CommitMarks(ctx context.Context, recs []Record) error
	// Close 关闭消费端。
	Close() error
}

// Record —— Kafka 记录。
type Record struct {
	Topic     string
	Key       []byte
	Value     []byte
	Timestamp time.Time
}

// FranzGroup —— franz-go 消费组实现（group=gateway.ws，docs/09 §2 登记）。
// 单泵协程顺序 Polls→处理→CommitMarks；pending 保存最近一批 kgo.Record
// 以便提交位点（Record 为值副本，无法回指）。
type FranzGroup struct {
	client  *kgo.Client
	pending []*kgo.Record
}

// NewFranzGroup 构造并订阅 topics（共享同一消费组）。
func NewFranzGroup(brokers []string, group string, topics []string, dialTimeout time.Duration) (*FranzGroup, error) {
	if len(brokers) == 0 {
		return nil, errors.New("ingest: kafka brokers required")
	}
	client, err := kgo.NewClient(
		kgo.SeedBrokers(brokers...),
		kgo.ConsumerGroup(group),
		kgo.ConsumeTopics(topics...),
		kgo.DisableAutoCommit(), // 处理成功后手动提交（与 storage 消费语义一致）
		kgo.FetchMaxWait(250*time.Millisecond), // 推送延迟预算 ≤2s（docs/hld/05 §5）
		kgo.DialTimeout(dialTimeout),
	)
	if err != nil {
		return nil, err
	}
	return &FranzGroup{client: client}, nil
}

// Polls 阻塞拉取一批记录。
func (g *FranzGroup) Polls(ctx context.Context) ([]Record, error) {
	fetches := g.client.PollRecords(ctx, 128)
	if fetches.IsClientClosed() {
		return nil, context.Canceled
	}
	if err := fetches.Err(); err != nil {
		return nil, err
	}
	var out []Record
	fetches.EachError(func(t string, p int32, err error) {
		// 分区级错误仅记录跳过；franz-go 会自动重试，不阻塞整批。
		_, _, _ = t, p, err
	})
	g.pending = g.pending[:0]
	fetches.EachRecord(func(r *kgo.Record) {
		g.pending = append(g.pending, r)
		out = append(out, Record{
			Topic:     r.Topic,
			Key:       r.Key,
			Value:     r.Value,
			Timestamp: r.Timestamp,
		})
	})
	return out, nil
}

// CommitMarks 提交最近一批记录位点（处理全部成功后调用；
// MarkCommitRecords + CommitMarkedOffsets，配合 DisableAutoCommit 手动提交）。
func (g *FranzGroup) CommitMarks(ctx context.Context, _ []Record) error {
	for _, r := range g.pending {
		g.client.MarkCommitRecords(r)
	}
	g.pending = g.pending[:0]
	return g.client.CommitMarkedOffsets(ctx)
}

// Close 关闭底层客户端。
func (g *FranzGroup) Close() error { g.client.Close(); return nil }

// ChannelConsumer —— 内存通道消费实现（联调桩/单测/cmd 空跑）。
type ChannelConsumer struct {
	mu     sync.Mutex
	ch     chan Record
	closed bool
}

// NewChannelConsumer 构造带缓冲的内存消费通道。
func NewChannelConsumer(buf int) *ChannelConsumer {
	if buf <= 0 {
		buf = 16
	}
	return &ChannelConsumer{ch: make(chan Record, buf)}
}

// Inject 供生产侧投喂（桩注入口）。
func (c *ChannelConsumer) Inject(r Record) {
	c.mu.Lock()
	closed := c.closed
	c.mu.Unlock()
	if closed {
		return
	}
	c.ch <- r
}

// Polls 阻塞取 1 条并尽力排空缓冲（单批 ≤64 条）。
func (c *ChannelConsumer) Polls(ctx context.Context) ([]Record, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case r, ok := <-c.ch:
		if !ok {
			return nil, context.Canceled
		}
		recs := []Record{r}
		for len(recs) < 64 {
			select {
			case r2 := <-c.ch:
				recs = append(recs, r2)
			default:
				return recs, nil
			}
		}
		return recs, nil
	}
}

// CommitMarks 记录提交（内存桩无持久化位点）。
func (c *ChannelConsumer) CommitMarks(context.Context, []Record) error { return nil }

// Close 关闭通道（幂等）。
func (c *ChannelConsumer) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.closed {
		c.closed = true
		close(c.ch)
	}
	return nil
}

// 确保 shared 契约镜像被引用（组名/主题常量即接口）。
var _ = shared.GroupGatewayWS
