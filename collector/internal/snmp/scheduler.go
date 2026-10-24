package snmp

import (
	"context"
	"sync"
	"time"
)

// Scheduler —— per-device 轮询调度（dd/02 §5.1）。
//
// 模型：固定粒度 tick（DefaultRoundTick）扫描设备到期表，到期轮询分发给
// 限并发 worker 池（DefaultWorkers=40；2,000 设备预算单轮 30s 内完成）。
// 三类轮询（计数器 30s / 健康 60s / 光功率 300s）各自持有 nextDue；
// 设备不可达的轮询错误计数后跳过，不拖垮轮次（SNMP 尽力语义）。
type Scheduler struct {
	poller Poller
	sink   CountersSink // 可为 nil（不投递审计流）

	workers int
	tick    time.Duration

	mu      sync.Mutex
	devices map[uint32]*deviceState

	rounds    counter
	polls     counter
	errors    counter
	published counter
}

// deviceState —— 单设备调度状态。
type deviceState struct {
	target     DeviceTarget
	nextIf     time.Time
	nextHealth time.Time
	nextDOM    time.Time
}

// counter —— 原子计数（自监控指标 TODO：lucid_collector_snmp_*，docs/11 §9）。
type counter struct {
	mu sync.Mutex
	n  uint64
}

func (c *counter) add()          { c.mu.Lock(); c.n++; c.mu.Unlock() }
func (c *counter) value() uint64 { c.mu.Lock(); defer c.mu.Unlock(); return c.n }

// SchedulerOption —— 调度器选项（docs/11 §3 Option 模式）。
type SchedulerOption func(*Scheduler)

// WithWorkers —— 并发 worker 数（缺省 DefaultWorkers）。
func WithWorkers(n int) SchedulerOption {
	return func(s *Scheduler) {
		if n > 0 {
			s.workers = n
		}
	}
}

// WithTick —— 到期扫描粒度（测试注入小粒度）。
func WithTick(d time.Duration) SchedulerOption {
	return func(s *Scheduler) {
		if d > 0 {
			s.tick = d
		}
	}
}

// WithSink —— 计数器审计流投递（VM lucid_if + Kafka snmp.ifcounters，dd/02 §5.1）。
func WithSink(sink CountersSink) SchedulerOption {
	return func(s *Scheduler) { s.sink = sink }
}

// NewScheduler —— 构造（poller 轮询实现可注入桩）。
func NewScheduler(poller Poller, opts ...SchedulerOption) *Scheduler {
	s := &Scheduler{
		poller:  poller,
		workers: DefaultWorkers,
		tick:    DefaultRoundTick,
		devices: make(map[uint32]*deviceState),
	}
	for _, o := range opts {
		o(s)
	}
	return s
}

// AddDevice —— 登记设备（立即到期：首轮即轮询）。
func (s *Scheduler) AddDevice(d DeviceTarget) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	s.devices[d.DeviceID] = &deviceState{
		target:     d,
		nextIf:     now,
		nextHealth: now,
		nextDOM:    now,
	}
}

// RemoveDevice —— 摘除设备（进行中的轮询不中断）。
func (s *Scheduler) RemoveDevice(deviceID uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.devices, deviceID)
}

// DeviceCount —— 当前登记设备数。
func (s *Scheduler) DeviceCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.devices)
}

// Stats —— 自监控计数快照（轮次/轮询/错误/审计流投递）。
type Stats struct {
	Rounds    uint64
	Polls     uint64
	Errors    uint64
	Published uint64
}

// Stats —— 当前计数。
func (s *Scheduler) Stats() Stats {
	return Stats{
		Rounds:    s.rounds.value(),
		Polls:     s.polls.value(),
		Errors:    s.errors.value(),
		Published: s.published.value(),
	}
}

// pollPlan —— 单轮到期计划。
type pollPlan struct {
	target    DeviceTarget
	ifDue     bool
	healthDue bool
	domDue    bool
}

// Run —— 调度主循环（阻塞至 ctx 取消；优雅退出由调用方 ctx 控制）。
func (s *Scheduler) Run(ctx context.Context) {
	t := time.NewTicker(s.tick)
	defer t.Stop()
	sem := make(chan struct{}, s.workers)
	var wg sync.WaitGroup

	for {
		select {
		case <-ctx.Done():
			wg.Wait() // 等在途轮询落地
			return
		case now := <-t.C:
			s.rounds.add()
			s.mu.Lock()
			plans := make([]pollPlan, 0, len(s.devices))
			for _, st := range s.devices {
				var p pollPlan
				if !now.Before(st.nextIf) {
					st.nextIf = now.Add(st.target.ifInterval())
					p.ifDue = true
				}
				if !now.Before(st.nextHealth) {
					st.nextHealth = now.Add(orDefault(st.target.HealthInterval, DefaultHealthPollInterval))
					p.healthDue = true
				}
				if !now.Before(st.nextDOM) {
					st.nextDOM = now.Add(orDefault(st.target.DOMInterval, DefaultDOMPollInterval))
					p.domDue = true
				}
				if p.ifDue || p.healthDue || p.domDue {
					p.target = st.target
					plans = append(plans, p)
				}
			}
			s.mu.Unlock()
			for _, plan := range plans {
				wg.Add(1)
				sem <- struct{}{}
				go func(p pollPlan) {
					defer func() {
						<-sem
						wg.Done()
					}()
					s.pollDevice(ctx, p)
				}(plan)
			}
		}
	}
}

// pollDevice —— 单设备单轮（错误计数不外抛）。
func (s *Scheduler) pollDevice(ctx context.Context, p pollPlan) {
	s.polls.add()
	if p.ifDue {
		counters, err := s.poller.PollIfCounters(ctx, p.target)
		if err != nil {
			s.errors.add()
		} else if s.sink != nil {
			for _, c := range counters {
				if err := s.sink.PublishIfCounters(ctx, c); err != nil {
					s.errors.add()
					continue
				}
				s.published.add()
			}
		}
	}
	if p.healthDue {
		if err := s.poller.PollDeviceHealth(ctx, p.target); err != nil {
			s.errors.add()
		}
	}
	if p.domDue {
		if err := s.poller.PollDOM(ctx, p.target); err != nil {
			s.errors.add()
		}
	}
}

// orDefault —— 零值取缺省。
func orDefault(d, def time.Duration) time.Duration {
	if d <= 0 {
		return def
	}
	return d
}
