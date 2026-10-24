package inserter

import (
	"context"
	"errors"
	"sync"
	"time"
)

// ErrConsumerClosed —— 消费通道已关闭（ChannelConsumer.Close 之后 Fetch 返回）。
var ErrConsumerClosed = errors.New("consumer closed")

// Message —— Kafka 记录（消费侧抽象；真实实现接 franz-go/segmentio，见模块 README TODO）。
type Message struct {
	Topic     string
	Key       []byte
	Value     []byte // proto+lz4 编码负载（docs/09 §2）
	Timestamp time.Time
}

// Consumer —— Kafka 消费接口（docs/09 §2 消费组语义；组名常量见 shared，
// 如 storage.inserter.flows / storage.inserter.aggr / storage.inserter.attacks /
// storage.inserter.alarms，组名即接口）。
//
// 拉取-提交语义（docs/dd/04 §1.3）：仅当一批消息全部处理成功后才 Commit；
// 失败不提交位点，整批重发，幂等由 batch_id + PG export_batches 去重兜底。
type Consumer interface {
	// Fetch 阻塞拉取一批消息；ctx 取消时返回 ctx.Err()，通道关闭时返回 ErrConsumerClosed。
	Fetch(ctx context.Context) ([]Message, error)
	// Commit 提交一批消息的位点。
	Commit(ctx context.Context, msgs []Message) error
	Close() error
}

// ChannelConsumer —— 内存通道消费实现（联调桩/单测/cmd 空跑用）。
// 关闭语义：Close 关闭 done 信号（不 close 数据通道），此后 Fetch 返回
// ErrConsumerClosed、Inject 静默丢弃——避免"close 后 send"panic。
// Inject 在缓冲满且无消费者时阻塞（有界背压）。
type ChannelConsumer struct {
	ch     chan Message
	done   chan struct{}
	once   sync.Once
	mu     sync.Mutex
	commit int
}

// NewChannelConsumer 构造带缓冲的内存消费通道。
func NewChannelConsumer(buf int) *ChannelConsumer {
	if buf <= 0 {
		buf = 1
	}
	return &ChannelConsumer{
		ch:   make(chan Message, buf),
		done: make(chan struct{}),
	}
}

// Inject 供生产侧投喂消息（桩注入口）；已关闭时静默丢弃。
func (c *ChannelConsumer) Inject(m Message) {
	select {
	case <-c.done:
		return // 已关闭：优先丢弃（避免与缓冲可写竞态投递）
	default:
	}
	select {
	case c.ch <- m:
	case <-c.done:
	}
}

// Fetch 阻塞取 1 条并尽力排空缓冲（单批最多 64 条）。
func (c *ChannelConsumer) Fetch(ctx context.Context) ([]Message, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	select {
	case <-c.done: // 已关闭：优先报关闭（残留缓冲丢弃，桩语义）
		return nil, ErrConsumerClosed
	default:
	}
	var first Message
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.done:
		return nil, ErrConsumerClosed
	case m := <-c.ch:
		first = m
	}
	msgs := []Message{first}
	for len(msgs) < 64 {
		select {
		case m := <-c.ch:
			msgs = append(msgs, m)
		default:
			return msgs, nil
		}
	}
	return msgs, nil
}

// Commit 记录已提交消息数（内存桩，无持久化位点）。
func (c *ChannelConsumer) Commit(_ context.Context, msgs []Message) error {
	c.mu.Lock()
	c.commit += len(msgs)
	c.mu.Unlock()
	return nil
}

// Committed 返回累计提交条数（测试断言用）。
func (c *ChannelConsumer) Committed() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.commit
}

// Close 关闭消费通道（幂等）。
func (c *ChannelConsumer) Close() error {
	c.once.Do(func() { close(c.done) })
	return nil
}
