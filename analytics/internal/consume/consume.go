// Package consume —— flows.raw 消费封装（dd/03 §1；09 §2 契约）。
//
// Source 抽象两种实现：
//   - JSONLSource：开发模式从 JSONL 文件回放 shared.FlowRecord 流（单测/演示）；
//   - KafkaSource：franz-go 消费组桩（TODO M2；组名 shared.GroupAnalyticsDetect /
//     GroupAnalyticsAggregate，并行单元=分区，消费批量 5,000 条/批）。
//
// Pipeline 为单消费者事件循环：记录通道 + 秒级 tick 在同一 goroutine 串行分派，
// 保证 detector/aggregate/fsm 状态无锁（dd/03 §1 的结构化并发保证）。
package consume

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/SchearLoe/lucidnet/shared"
)

// Handler —— 单条 FlowRecord 处理回调。
type Handler func(rec *shared.FlowRecord) error

// Source —— 流源接口（Run 返回 nil 表示流正常结束）。
type Source interface {
	Run(ctx context.Context, handle Handler) error
	Close()
}

// ErrKafkaNotImplemented —— Kafka 消费桩未实现（M2 接 franz-go）。
var ErrKafkaNotImplemented = errors.New("consume: kafka source not implemented (TODO dd/03 §1; franz-go)")

// JSONLSource —— 开发模式 JSONL 回放源：每行一条 FlowRecord JSON。
type JSONLSource struct {
	path  string
	paced bool // 按 TimeStartMs 节流回放（演示用，对齐真实时钟）

	mu     sync.Mutex
	closed bool
}

// JSONLOption —— 回放选项。
type JSONLOption func(*JSONLSource)

// WithPaced —— 按记录时间戳节流回放（记录时间落后真实时钟则即时投递）。
func WithPaced() JSONLOption {
	return func(s *JSONLSource) { s.paced = true }
}

// NewJSONLSource —— 构造回放源。
func NewJSONLSource(path string, opts ...JSONLOption) *JSONLSource {
	s := &JSONLSource{path: path}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// Run —— 逐行回放（空行跳过；坏行返回带行号的 %w 错误）。
func (s *JSONLSource) Run(ctx context.Context, handle Handler) error {
	f, err := os.Open(s.path)
	if err != nil {
		return fmt.Errorf("consume: open jsonl %s: %w", s.path, err)
	}
	defer f.Close()

	s.mu.Lock()
	closed := s.closed
	s.mu.Unlock()
	if closed {
		return errors.New("consume: jsonl source closed")
	}

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	line := 0
	for sc.Scan() {
		line++
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		row := sc.Bytes()
		if len(row) == 0 {
			continue
		}
		var rec shared.FlowRecord
		if err := json.Unmarshal(row, &rec); err != nil {
			return fmt.Errorf("consume: jsonl %s line %d: %w", s.path, line, err)
		}
		if s.paced {
			if wait := time.Until(time.UnixMilli(rec.TimeStartMs)); wait > 0 {
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-time.After(wait):
				}
			}
		}
		if err := handle(&rec); err != nil {
			return fmt.Errorf("consume: jsonl %s line %d handle: %w", s.path, line, err)
		}
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("consume: read jsonl %s: %w", s.path, err)
	}
	return nil
}

// Close —— 标记关闭（文件按次打开，无长连接资源）。
func (s *JSONLSource) Close() {
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
}

// KafkaSource —— franz-go 消费组桩（09 §2：组名即接口）。
// TODO(dd/03 §1，M2)：
//   - kgo.NewGroup{Brokers, Group, Topic: shared.TopicFlowsRaw}；
//   - 并行单元=Kafka 分区（≤96），每分区独立 PartitionState；
//   - 消费批量 5,000 条/批；lz4；消费者订阅 etcd 配置变更。
type KafkaSource struct {
	Brokers []string
	Topic   string
	Group   string
}

// NewKafkaSource —— 构造消费桩；group 必须为 shared.GroupAnalyticsDetect /
// GroupAnalyticsAggregate 之一（09 §2 登记组名）。
func NewKafkaSource(brokers []string, group string) (*KafkaSource, error) {
	if group != shared.GroupAnalyticsDetect && group != shared.GroupAnalyticsAggregate {
		return nil, fmt.Errorf("consume: unregistered consumer group %q (09 §2)", group)
	}
	return &KafkaSource{Brokers: brokers, Topic: shared.TopicFlowsRaw, Group: group}, nil
}

// Run —— 桩：恒返回 ErrKafkaNotImplemented。
func (s *KafkaSource) Run(context.Context, Handler) error { return ErrKafkaNotImplemented }

// Close —— 桩。
func (*KafkaSource) Close() {}

// Pipeline —— 单消费者事件循环：源 goroutine 投递记录 → 主循环串行处理
// 记录与秒级 tick（引擎状态仅被主循环 goroutine 访问，结构上免锁）。
type Pipeline struct {
	src       Source
	onRecord  Handler
	onTick    func()
	tickEvery time.Duration
	buf       int
}

// PipelineOption —— 管道选项。
type PipelineOption func(*Pipeline)

// WithTickInterval —— 覆盖 tick 周期（默认 1s，dd/03 §3 检测粒度）。
func WithTickInterval(d time.Duration) PipelineOption {
	return func(p *Pipeline) {
		if d > 0 {
			p.tickEvery = d
		}
	}
}

// WithBuffer —— 覆盖记录通道缓冲（默认 4,096）。
func WithBuffer(n int) PipelineOption {
	return func(p *Pipeline) {
		if n > 0 {
			p.buf = n
		}
	}
}

// NewPipeline —— 构造管道；onTick 可为 nil（无定时回调）。
func NewPipeline(src Source, onRecord Handler, onTick func(), opts ...PipelineOption) (*Pipeline, error) {
	if src == nil {
		return nil, errors.New("consume: nil source")
	}
	if onRecord == nil {
		return nil, errors.New("consume: nil record handler")
	}
	if onTick == nil {
		onTick = func() {}
	}
	p := &Pipeline{src: src, onRecord: onRecord, onTick: onTick, tickEvery: time.Second, buf: 4096}
	for _, opt := range opts {
		opt(p)
	}
	return p, nil
}

// Run —— 阻塞运行至源耗尽 / ctx 取消 / 回调出错。
// 源耗尽时先排空通道内剩余记录再返回源的终止错误。
func (p *Pipeline) Run(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	recs := make(chan *shared.FlowRecord, p.buf)
	srcErr := make(chan error, 1)

	go func() {
		defer close(recs)
		srcErr <- p.src.Run(ctx, func(rec *shared.FlowRecord) error {
			select {
			case recs <- rec:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		})
	}()

	ticker := time.NewTicker(p.tickEvery)
	defer ticker.Stop()

	for {
		select {
		case rec, ok := <-recs:
			if !ok {
				p.src.Close()
				return <-srcErr
			}
			if err := p.onRecord(rec); err != nil {
				p.src.Close()
				return fmt.Errorf("consume: pipeline record handler: %w", err)
			}
		case <-ticker.C:
			p.onTick()
		case <-ctx.Done():
			p.src.Close()
			return ctx.Err()
		}
	}
}
