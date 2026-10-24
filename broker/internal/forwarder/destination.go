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
type Counters interface {
	ForwardRecords(ruleID, dest string, n int)
	ForwardDrop(ruleID, dest string, n int)
	SetDestDown(dest string, down bool)
	SetResampleRatio(dest string, ratio float64)
	ProxyDecodeError()
	KafkaProduce(topic string, n int)
	KafkaProduceError(topic string, n int)
}

// NoopCounters —— 空实现（测试/未接 metrics 时）。
type NoopCounters struct{}

func (NoopCounters) ForwardRecords(string, string, int) {}
func (NoopCounters) ForwardDrop(string, string, int)    {}
func (NoopCounters) SetDestDown(string, bool)           {}
func (NoopCounters) SetResampleRatio(string, float64)   {}
func (NoopCounters) ProxyDecodeError()                  {}
func (NoopCounters) KafkaProduce(string, int)           {}
func (NoopCounters) KafkaProduceError(string, int)      {}

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
}

// udpSender —— 目的地 UDP 发送通道（每目的地一个 connected socket + 独立发送协程，
// 保护收包路径不被慢目的地阻塞；连续失败标记 down 并告警打点，dd/01 §4.3）。
type udpSender struct {
	conn    net.Conn // connected UDP（写失败即时反馈 ICMP 不可达）
	queue   chan []byte
	limiter *rateLimiter // nil=不限速（透传）

	hooks senderHooks

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

// newUDPSender 构造并启动发送协程；rateBytes≤0 不限速；network 目前仅 "udp"。
func newUDPSender(network, addr string, rateBytes int64, hooks senderHooks) (*udpSender, error) {
	conn, err := net.Dial(network, addr)
	if err != nil {
		return nil, err
	}
	if c, ok := conn.(*net.UDPConn); ok {
		_ = c.SetWriteBuffer(udpSendBufferBytes)
	}
	if hooks.onSent == nil {
		hooks.onSent = func() {}
	}
	if hooks.onDrop == nil {
		hooks.onDrop = func() {}
	}
	if hooks.onDownChange == nil {
		hooks.onDownChange = func(bool) {}
	}
	s := &udpSender{
		conn:    conn,
		queue:   make(chan []byte, senderQueueSize),
		limiter: newRateLimiter(rateBytes),
		hooks:   hooks,
		done:    make(chan struct{}),
	}
	go s.loop()
	return s, nil
}

// Send 入队一个数据报（限速/缓冲满即丢弃并打点，绝不阻塞收包路径）。
// 队列数据为发送方持有的独立缓冲（透传由调用方复制，代理由编码器新建）。
func (s *udpSender) Send(datagram []byte) {
	if s.limiter != nil && !s.limiter.Allow(len(datagram), time.Now()) {
		s.hooks.onDrop()
		return
	}
	select {
	case s.queue <- datagram:
	default:
		s.hooks.onDrop()
	}
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

func (s *udpSender) recordOK() {
	s.mu.Lock()
	s.consecErrors = 0
	wasDown := s.down
	s.down = false
	s.mu.Unlock()
	if wasDown {
		s.hooks.onDownChange(false)
	}
}

// IsDown 查询目的地健康态。
func (s *udpSender) IsDown() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.down
}

// Close 停止发送协程并关 socket（幂等）。
func (s *udpSender) Close() {
	s.closeOnce.Do(func() {
		close(s.done)
		_ = s.conn.Close()
	})
}
