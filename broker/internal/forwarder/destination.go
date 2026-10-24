package forwarder

import (
	"context"
	"net"
	"sync"
	"time"
)

// KafkaSink —— Kafka 生产最小接口（kafkaprod.Producer 实现；引擎单测可注入桩）。
type KafkaSink interface {
	// Produce 异步生产；value 生命周期由生产方保证。
	Produce(ctx context.Context, topic string, key []byte, value []byte)
}

// Counters —— forwarder 打点接口（internal/metrics 实现，避免包依赖环）。
// 命名与标签口径见 docs/11 §9（标签白名单：rule_id/dest）。
type Counters interface {
	ForwardRecords(ruleID, dest string, n int)
	ForwardDrop(ruleID, dest string, n int)
	SetDestDown(dest string, down bool)
	SetResampleRatio(dest string, ratio float64)
	ProxyDecodeErrors(n int)
	KafkaProduce(topic string, n int)
	KafkaProduceError(topic string, n int)
	// 断连重放（任务二，dd/01 §4.3）
	SetReplayBuffered(ruleID, dest string, n int)
	ReplayDropped(ruleID, dest string, n int)
	SetReplayLag(ruleID, dest string, lag time.Duration)
}

// NoopCounters —— 空实现（测试/未接 metrics 时）。
type NoopCounters struct{}

func (NoopCounters) ForwardRecords(string, string, int)         {}
func (NoopCounters) ForwardDrop(string, string, int)            {}
func (NoopCounters) SetDestDown(string, bool)                   {}
func (NoopCounters) SetResampleRatio(string, float64)           {}
func (NoopCounters) ProxyDecodeErrors(int)                      {}
func (NoopCounters) KafkaProduce(string, int)                   {}
func (NoopCounters) KafkaProduceError(string, int)              {}
func (NoopCounters) SetReplayBuffered(string, string, int)      {}
func (NoopCounters) ReplayDropped(string, string, int)          {}
func (NoopCounters) SetReplayLag(string, string, time.Duration) {}

// DefaultReplayWindow / DefaultReplayMaxBytes —— 断连重放缺省策略
// （dd/01 §4.3：最近 5s 报文，环形 512MB，先到为准；进程级可配）。
const (
	DefaultReplayWindow   = 5 * time.Second
	DefaultReplayMaxBytes = 512 << 20
)

// replayPolicy —— 每目的地断连重放策略（window≤0 或 maxBytes≤0 = 禁用）。
type replayPolicy struct {
	window   time.Duration
	maxBytes int64
}

func (p replayPolicy) enabled() bool { return p.window > 0 && p.maxBytes > 0 }

// rateLimiter —— 令牌桶（dd/01 §4.3：代理会话默认 1Gbps，防打爆下游）。
type rateLimiter struct {
	mu     sync.Mutex
	rate   float64 // bytes/s
	burst  float64
	tokens float64
	last   time.Time
}

// DefaultProxyRateBytes —— 1Gbps。
const DefaultProxyRateBytes = 1 << 30 / 8

func newRateLimiter(rateBytes int64) *rateLimiter {
	if rateBytes <= 0 {
		rateBytes = DefaultProxyRateBytes
	}
	r := float64(rateBytes)
	return &rateLimiter{rate: r, burst: r / 100, tokens: r / 100, last: time.Now()} // 10ms 突发
}

// Allow —— n 字节是否放行（不足则整包拒绝并累计）。
func (l *rateLimiter) Allow(n int, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	elapse := now.Sub(l.last).Seconds()
	l.last = now
	l.tokens += elapse * l.rate
	if l.tokens > l.burst {
		l.tokens = l.burst
	}
	if l.tokens < float64(n) {
		return false
	}
	l.tokens -= float64(n)
	return true
}

// senderHooks —— 目的地打点回调（由引擎以 rule_id/dest 标签闭包注入）。
type senderHooks struct {
	onSent       func()
	onDrop       func()
	onDownChange func(down bool)
	// 断连重放（任务二）
	onReplayBuffered func(buffered int)
	onReplayDropped  func(n int)
	onReplayLag      func(lag time.Duration)
}

func nilSafeHooks(h senderHooks) senderHooks {
	if h.onSent == nil {
		h.onSent = func() {}
	}
	if h.onDrop == nil {
		h.onDrop = func() {}
	}
	if h.onDownChange == nil {
		h.onDownChange = func(bool) {}
	}
	if h.onReplayBuffered == nil {
		h.onReplayBuffered = func(int) {}
	}
	if h.onReplayDropped == nil {
		h.onReplayDropped = func(int) {}
	}
	if h.onReplayLag == nil {
		h.onReplayLag = func(time.Duration) {}
	}
	return h
}

// udpSender —— 目的地 UDP 发送通道（每目的地一个 connected socket + 独立发送协程，
// 保护收包路径不被慢目的地阻塞；连续失败标记 down 并告警打点，dd/01 §4.3）。
// down 期间数据报转入断连重放环形缓冲，恢复后按序重放（任务二）。
type udpSender struct {
	conn    net.Conn // connected UDP（写失败即时反馈 ICMP 不可达）
	queue   chan []byte
	limiter *rateLimiter // nil=不限速（透传）
	replay  *replayBuffer

	hooks senderHooks

	// order —— down 判定 + 入队/重放排空的顺序闸：保证恢复瞬间新 Send 不会
	// 插队到残留重放数据之前（按序重放，dd/01 §4.3）。热路径为单次非竞争锁。
	order sync.Mutex

	mu           sync.Mutex
	consecErrors int
	down         bool

	closeOnce sync.Once
	done      chan struct{}
}

const (
	senderQueueSize    = 4096
	senderDownThresh   = 3
	udpSendBufferBytes = 4 << 20 // dd/01 §4.3：UDP send buffer 4MB
)

// newUDPSender 构造并启动发送协程；rateBytes≤0 不限速；rp.enabled()=false 禁用重放。
func newUDPSender(network, addr string, rateBytes int64, rp replayPolicy, hooks senderHooks) (*udpSender, error) {
	conn, err := net.Dial(network, addr)
	if err != nil {
		return nil, err
	}
	if c, ok := conn.(*net.UDPConn); ok {
		_ = c.SetWriteBuffer(udpSendBufferBytes)
	}
	hooks = nilSafeHooks(hooks)
	var rb *replayBuffer
	if rp.enabled() {
		rb = &replayBuffer{window: rp.window, maxBytes: rp.maxBytes}
	}
	s := &udpSender{
		conn:    conn,
		queue:   make(chan []byte, senderQueueSize),
		limiter: newRateLimiter(rateBytes),
		replay:  rb,
		hooks:   hooks,
		done:    make(chan struct{}),
	}
	go s.loop()
	return s, nil
}

// Send 入队一个数据报（限速/缓冲满即丢弃并打点，绝不阻塞收包路径）。
// down 期间转入重放缓冲（容量约束见 replayBuffer），恢复后按序重放。
// 队列数据为发送方持有的独立缓冲（透传由调用方复制，代理由编码器新建）。
func (s *udpSender) Send(datagram []byte) {
	s.order.Lock()
	s.mu.Lock()
	down := s.down
	s.mu.Unlock()
	if down {
		if s.replay != nil {
			now := time.Now()
			s.replay.push(replayItem{data: datagram, at: now}, now, s.hooks.onReplayDropped)
			s.hooks.onReplayBuffered(s.replay.len())
			s.hooks.onReplayLag(s.replay.oldestAge(now))
		} else {
			s.hooks.onDrop() // 重放未启用：按原语义丢弃
		}
		s.order.Unlock()
		return
	}
	if s.limiter != nil && !s.limiter.Allow(len(datagram), time.Now()) {
		s.order.Unlock()
		s.hooks.onDrop()
		return
	}
	select {
	case s.queue <- datagram:
	default:
		s.order.Unlock()
		s.hooks.onDrop()
		return
	}
	s.order.Unlock()
}

// loop —— 发送主循环。
func (s *udpSender) loop() {
	for {
		select {
		case <-s.done:
			return
		case dg := <-s.queue:
			if _, err := s.conn.Write(dg); err != nil {
				s.recordError()
				s.hooks.onDrop()
			} else {
				s.recordOK()
				s.hooks.onSent()
				s.topUpReplay() // 重放残留（队列/限速截断）随写入续传
			}
		}
	}
}

func (s *udpSender) recordError() {
	s.mu.Lock()
	s.consecErrors++
	down := s.consecErrors >= senderDownThresh && !s.down
	if down {
		s.down = true
	}
	s.mu.Unlock()
	if down {
		s.hooks.onDownChange(true)
	}
}

// recordOK —— 写成功即恢复健康；down→up 转换时先排空重放缓冲再放行新数据
// （order 闸保证此刻不会有 Send 插队，dd/01 §4.3 按序重放）。
func (s *udpSender) recordOK() {
	s.order.Lock()
	s.mu.Lock()
	s.consecErrors = 0
	wasDown := s.down
	s.down = false
	s.mu.Unlock()
	if wasDown {
		s.drainReplayLocked(time.Now())
	}
	s.order.Unlock()
	if wasDown {
		s.hooks.onDownChange(false)
	}
}

// topUpReplay —— up 态下续传重放残留（每次成功写入后调用；限速自节流）。
func (s *udpSender) topUpReplay() {
	if s.replay == nil || s.replay.len() == 0 {
		return
	}
	s.order.Lock()
	s.mu.Lock()
	down := s.down
	s.mu.Unlock()
	if !down {
		s.drainReplayLocked(time.Now())
	}
	s.order.Unlock()
}

// drainReplayLocked —— 重放缓冲按序入队（须持 order 锁）；
// 限速未放行/队列满即停止，剩余留待 top-up，不计丢弃。
func (s *udpSender) drainReplayLocked(now time.Time) {
	if s.replay == nil || s.replay.len() == 0 {
		return
	}
	s.replay.drain(now, func(data []byte) bool {
		if s.limiter != nil && !s.limiter.Allow(len(data), now) {
			return false
		}
		select {
		case s.queue <- data:
			s.hooks.onSent()
			return true
		default:
			return false
		}
	}, s.hooks.onReplayDropped)
	s.hooks.onReplayBuffered(s.replay.len())
	s.hooks.onReplayLag(s.replay.oldestAge(now))
}

// IsDown 查询目的地健康态。
func (s *udpSender) IsDown() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.down
}

// TakeReplay —— 会话重建迁移：取走全部未重放缓冲（ApplyRules 旧会话提取，
// 移交给同逻辑目的地的新会话，任务二）。
func (s *udpSender) TakeReplay() []replayItem {
	if s.replay == nil {
		return nil
	}
	s.order.Lock()
	defer s.order.Unlock()
	items := s.replay.take()
	if len(items) > 0 {
		s.hooks.onReplayBuffered(0)
		s.hooks.onReplayLag(0)
	}
	return items
}

// InstallReplay —— 会话重建迁移：装入继承缓冲并立即续传（up 态，须持后续 order）。
func (s *udpSender) InstallReplay(items []replayItem, now time.Time) {
	if s.replay == nil || len(items) == 0 {
		return
	}
	s.order.Lock()
	s.replay.install(items, now, s.hooks.onReplayDropped)
	s.hooks.onReplayBuffered(s.replay.len())
	s.hooks.onReplayLag(s.replay.oldestAge(now))
	s.mu.Lock()
	down := s.down
	s.mu.Unlock()
	if !down {
		s.drainReplayLocked(now)
	}
	s.order.Unlock()
}

// Close 停止发送协程并关 socket（幂等）；残留重放缓冲随会话终止清空
// （不计数：会话终止非断连丢弃），gauge 归零。
func (s *udpSender) Close() {
	s.closeOnce.Do(func() {
		close(s.done)
		_ = s.conn.Close()
		s.order.Lock()
		if s.replay != nil && s.replay.len() > 0 {
			s.replay.clear()
			s.hooks.onReplayBuffered(0)
			s.hooks.onReplayLag(0)
		}
		s.order.Unlock()
	})
}
