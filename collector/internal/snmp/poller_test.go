package snmp

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakePoller —— 注入式轮询器（调度器单测）。
type fakePoller struct {
	ifCalls     atomic.Int64
	healthCalls atomic.Int64
	domCalls    atomic.Int64
	inFlight    atomic.Int64
	maxInFlight atomic.Int64
	err         error // 非零 → PollIfCounters 报错
}

func (f *fakePoller) PollIfCounters(ctx context.Context, d DeviceTarget) ([]IfCounters, error) {
	cur := f.inFlight.Add(1)
	for {
		max := f.maxInFlight.Load()
		if cur <= max || f.maxInFlight.CompareAndSwap(max, cur) {
			break
		}
	}
	defer f.inFlight.Add(-1)
	f.ifCalls.Add(1)
	if f.err != nil {
		return nil, f.err
	}
	return []IfCounters{{
		DeviceID: d.DeviceID, IfIndex: 1,
		InOctets: 100, OutOctets: 200, InUcastPkts: 3, OutUcastPkts: 4,
		TS: time.Now(),
	}}, nil
}

func (f *fakePoller) PollDeviceHealth(ctx context.Context, d DeviceTarget) error {
	f.healthCalls.Add(1)
	return nil
}

func (f *fakePoller) PollDOM(ctx context.Context, d DeviceTarget) error {
	f.domCalls.Add(1)
	return nil
}

func TestSchedulerPollsAndSinks(t *testing.T) {
	fp := &fakePoller{}
	var sinkMu sync.Mutex
	var got []IfCounters
	sink := SinkFunc(func(ctx context.Context, c IfCounters) error {
		sinkMu.Lock()
		got = append(got, c)
		sinkMu.Unlock()
		return nil
	})

	s := NewScheduler(fp, WithTick(5*time.Millisecond), WithSink(sink))
	s.AddDevice(DeviceTarget{
		DeviceID: 1, Host: "10.0.0.1", Community: "public",
		IfPollInterval: 15 * time.Millisecond, // 计数器快周期
		HealthInterval: 40 * time.Millisecond,
		DOMInterval:    10 * time.Second, // 测试窗口内不应到期
	})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.Run(ctx); close(done) }()

	time.Sleep(120 * time.Millisecond)
	cancel()
	<-done

	if fp.ifCalls.Load() < 3 {
		t.Errorf("if polls = %d, want >= 3", fp.ifCalls.Load())
	}
	if fp.healthCalls.Load() < 1 {
		t.Errorf("health polls = %d, want >= 1", fp.healthCalls.Load())
	}
	if fp.domCalls.Load() != 1 {
		t.Errorf("dom polls = %d, want 1（首轮立即到期，此后 10s 周期内不再轮询）", fp.domCalls.Load())
	}
	sinkMu.Lock()
	n := len(got)
	sinkMu.Unlock()
	if n == 0 {
		t.Error("sink published nothing, want >= 1")
	}
	st := s.Stats()
	if st.Polls == 0 || st.Published != uint64(n) || st.Errors != 0 {
		t.Errorf("stats = %+v, want polls>0 published=%d errors=0", st, n)
	}
	if st.Rounds == 0 {
		t.Error("rounds = 0, want > 0")
	}
}

func TestSchedulerWorkerCap(t *testing.T) {
	// workers=1：任意时刻最多 1 个在途轮询（40 并发上限的限流语义，dd/02 §5.1）
	fp := &fakePoller{}
	s := NewScheduler(fp, WithTick(5*time.Millisecond), WithWorkers(1))
	for i := uint32(1); i <= 5; i++ {
		s.AddDevice(DeviceTarget{DeviceID: i, Host: "10.0.0.9", IfPollInterval: 10 * time.Millisecond})
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.Run(ctx); close(done) }()
	time.Sleep(80 * time.Millisecond)
	cancel()
	<-done
	if s.DeviceCount() != 5 {
		t.Errorf("device count = %d, want 5", s.DeviceCount())
	}
	if m := fp.maxInFlight.Load(); m > 1 {
		t.Errorf("max in-flight = %d, want <= 1", m)
	}
}

func TestSchedulerRemoveDeviceAndErrors(t *testing.T) {
	fp := &fakePoller{err: errors.New("device unreachable")}
	s := NewScheduler(fp, WithTick(5*time.Millisecond))
	s.AddDevice(DeviceTarget{DeviceID: 1, Host: "10.0.0.1", IfPollInterval: 10 * time.Millisecond})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.Run(ctx); close(done) }()
	time.Sleep(50 * time.Millisecond)
	s.RemoveDevice(1)
	time.Sleep(50 * time.Millisecond)
	cancel()
	<-done
	if s.DeviceCount() != 0 {
		t.Errorf("device count after remove = %d, want 0", s.DeviceCount())
	}
	st := s.Stats()
	if st.Errors == 0 {
		t.Error("errors = 0, want > 0（不可达设备计错不外抛）")
	}
}

func TestGoSNMPPollerStub(t *testing.T) {
	p := NewGoSNMPPoller()
	d := DeviceTarget{DeviceID: 1, Host: "10.0.0.1"}
	if _, err := p.PollIfCounters(context.Background(), d); !errors.Is(err, ErrSNMPNotImplemented) {
		t.Errorf("if counters err = %v, want ErrSNMPNotImplemented", err)
	}
	if err := p.PollDeviceHealth(context.Background(), d); !errors.Is(err, ErrSNMPNotImplemented) {
		t.Errorf("health err = %v, want ErrSNMPNotImplemented", err)
	}
	if err := p.PollDOM(context.Background(), d); !errors.Is(err, ErrSNMPNotImplemented) {
		t.Errorf("dom err = %v, want ErrSNMPNotImplemented", err)
	}
}

func TestDeviceTargetDefaults(t *testing.T) {
	d := DeviceTarget{}
	if d.ifInterval() != DefaultIfPollInterval {
		t.Errorf("if interval default = %v, want %v", d.ifInterval(), DefaultIfPollInterval)
	}
	d.IfPollInterval = time.Minute
	if d.ifInterval() != time.Minute {
		t.Errorf("per-device 60s override = %v, want 1m（dd/02 §5.1 可按设备调 60s）", d.ifInterval())
	}
}
