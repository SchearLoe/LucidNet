package forwarder

import (
	"encoding/binary"
	"testing"
	"time"
)

// —— replayBuffer 单测（任务二：容量边界 / down→up 重放顺序 / 缓冲满淘汰） ——

func newTestBuffer(maxBytes int64, window time.Duration) *replayBuffer {
	return &replayBuffer{window: window, maxBytes: maxBytes}
}

func dgOf(n int, size int) []byte {
	b := make([]byte, size)
	binary.BigEndian.PutUint32(b[0:4], uint32(n))
	for i := 4; i < size; i++ {
		b[i] = byte(n)
	}
	return b
}

// TestReplayBufferCapacityOrder —— 容量边界：超量淘汰最旧并计数；drain 严格 FIFO。
func TestReplayBufferCapacityOrder(t *testing.T) {
	b := newTestBuffer(250, time.Minute)
	t0 := time.Now()
	dropped := 0
	onDrop := func(n int) { dropped += n }

	b.push(replayItem{data: dgOf(1, 100), at: t0}, t0, onDrop)
	b.push(replayItem{data: dgOf(2, 100), at: t0}, t0, onDrop)
	if b.len() != 2 || b.bytes != 200 {
		t.Fatalf("len=%d bytes=%d", b.len(), b.bytes)
	}
	// 第 3 条（100B）触发最旧淘汰（总 300B > 250B）
	b.push(replayItem{data: dgOf(3, 100), at: t0}, t0, onDrop)
	if dropped != 1 || b.len() != 2 || b.bytes != 200 {
		t.Fatalf("after overflow: dropped=%d len=%d bytes=%d", dropped, b.len(), b.bytes)
	}

	var order []uint32
	b.drain(t0, func(data []byte) bool {
		order = append(order, binary.BigEndian.Uint32(data[0:4]))
		return true
	}, onDrop)
	if len(order) != 2 || order[0] != 2 || order[1] != 3 {
		t.Fatalf("drain order = %v (want [2 3], oldest evicted)", order)
	}
	if b.len() != 0 || dropped != 1 {
		t.Fatalf("final: len=%d dropped=%d", b.len(), dropped)
	}
}

// TestReplayBufferWindowExpiry —— 窗口语义：超窗条目在 push 与 drain 时淘汰计数。
func TestReplayBufferWindowExpiry(t *testing.T) {
	b := newTestBuffer(1<<20, 5*time.Second)
	t0 := time.Now()
	dropped := 0
	onDrop := func(n int) { dropped += n }

	b.push(replayItem{data: dgOf(1, 10), at: t0}, t0, onDrop)
	b.push(replayItem{data: dgOf(2, 10), at: t0.Add(3 * time.Second)}, t0.Add(3*time.Second), onDrop)

	// t0+4s：无超窗
	b.evictExpiredLocked(t0.Add(4*time.Second), onDrop)
	if b.len() != 2 || dropped != 0 {
		t.Fatalf("mid-window: len=%d dropped=%d", b.len(), dropped)
	}
	// t0+6s：第 1 条超窗（5s 窗口先到为准）
	b.evictExpiredLocked(t0.Add(6*time.Second), onDrop)
	if b.len() != 1 || dropped != 1 {
		t.Fatalf("expired: len=%d dropped=%d", b.len(), dropped)
	}
	// 新入缓冲不超窗（t0+6s 入，at 同刻）
	b.push(replayItem{data: dgOf(3, 10), at: t0.Add(6 * time.Second)}, t0.Add(6*time.Second), onDrop)
	// t0+8.5s drain：dg2 年龄 5.5s 超窗淘汰；dg3 年龄 2.5s 送达
	n := 0
	b.drain(t0.Add(8500*time.Millisecond), func([]byte) bool { n++; return true }, onDrop)
	if n != 1 || dropped != 2 || b.len() != 0 {
		t.Fatalf("drain expiry: n=%d dropped=%d len=%d", n, dropped, b.len())
	}
	// lag 语义：空缓冲 0
	if lag := b.oldestAge(t0.Add(6 * time.Second)); lag != 0 {
		t.Errorf("empty lag = %v", lag)
	}
}

// TestReplayBufferOversized —— 单条超上限直接丢弃计数；disabled 缓冲 push 即弃。
func TestReplayBufferOversized(t *testing.T) {
	b := newTestBuffer(100, time.Minute)
	dropped := 0
	b.push(replayItem{data: dgOf(1, 200), at: time.Now()}, time.Now(), func(n int) { dropped += n })
	if dropped != 1 || b.len() != 0 {
		t.Fatalf("oversized: dropped=%d len=%d", dropped, b.len())
	}

	disabled := newTestBuffer(0, 0)
	disabled.push(replayItem{data: dgOf(1, 10), at: time.Now()}, time.Now(), func(n int) { dropped += n })
	if dropped != 2 {
		t.Fatalf("disabled push must count drop, dropped=%d", dropped)
	}
}

// TestReplayBufferDrainBackpressure —— sink 返回 false 停止排空，剩余保留按序续传。
func TestReplayBufferDrainBackpressure(t *testing.T) {
	b := newTestBuffer(1<<20, time.Minute)
	t0 := time.Now()
	for i := 1; i <= 4; i++ {
		b.push(replayItem{data: dgOf(i, 10), at: t0}, t0, nil)
	}
	n := 0
	b.drain(t0, func([]byte) bool { n++; return n < 2 }, nil) // 第 2 次即拒收
	if n != 2 || b.len() != 3 {
		t.Fatalf("stop semantics: n=%d len=%d", n, b.len())
	}
	var order []uint32
	b.drain(t0, func(data []byte) bool { order = append(order, binary.BigEndian.Uint32(data[0:4])); return true }, nil)
	if len(order) != 3 || order[0] != 2 || order[1] != 3 || order[2] != 4 {
		t.Fatalf("resume order = %v", order)
	}
}

// TestReplayBufferTakeInstall —— 会话重建迁移：take 清空、install 保留原时刻。
func TestReplayBufferTakeInstall(t *testing.T) {
	src := newTestBuffer(1<<20, time.Minute)
	t0 := time.Now()
	src.push(replayItem{data: dgOf(1, 10), at: t0}, t0, nil)
	src.push(replayItem{data: dgOf(2, 10), at: t0.Add(time.Second)}, t0.Add(time.Second), nil)

	dst := newTestBuffer(1<<20, 5*time.Second)
	items := src.take()
	if len(items) != 2 || src.len() != 0 {
		t.Fatalf("take: items=%d len=%d", len(items), src.len())
	}
	dropped := 0
	dst.install(items, t0.Add(5*time.Second), func(n int) { dropped += n })
	// 第 1 条年龄恰 5s ≥ 窗口 → 按原 at 判定淘汰（不因迁移重置）；第 2 条 4s 保留
	if dropped != 1 || dst.len() != 1 {
		t.Fatalf("install: dropped=%d len=%d", dropped, dst.len())
	}
	if got := dst.oldestAge(t0.Add(5 * time.Second)); got != 4*time.Second {
		t.Errorf("oldest age = %v (want 4s: t0+1s 入缓冲)", got)
	}
}

// —— udpSender 集成：down → 缓冲，恢复 → 按序重放（真实 socket 到本地 sink） ——

func newReplayTestSender(t *testing.T, addr string, rp replayPolicy) (*udpSender, *hookSpy) {
	t.Helper()
	spy := &hookSpy{}
	s, err := newUDPSender("udp", addr, 0, rp, senderHooks{
		onSent:           spy.sent,
		onDrop:           spy.drop,
		onDownChange:     spy.downChange,
		onReplayBuffered: spy.replayBuffered,
		onReplayDropped:  spy.replayDropped,
		onReplayLag:      spy.replayLag,
	})
	if err != nil {
		t.Fatalf("newUDPSender: %v", err)
	}
	t.Cleanup(s.Close)
	return s, spy
}

type hookSpy struct {
	sentN, dropN, replayDroppedN, buffered int
	down                                   bool
	lag                                    time.Duration
}

func (h *hookSpy) sent()                     { h.sentN++ }
func (h *hookSpy) drop()                     { h.dropN++ }
func (h *hookSpy) downChange(down bool)      { h.down = down }
func (h *hookSpy) replayBuffered(n int)      { h.buffered = n }
func (h *hookSpy) replayDropped(n int)       { h.replayDroppedN += n }
func (h *hookSpy) replayLag(l time.Duration) { h.lag = l }

// TestSenderDownReplayToEnd —— down 期间入缓冲（不计数丢弃），恢复后按序重放送达。
func TestSenderDownReplayToEnd(t *testing.T) {
	sink := newUDPSink(t)
	s, spy := newReplayTestSender(t, sink.addr, replayPolicy{window: time.Minute, maxBytes: 1 << 20})

	// 人为标记 down（写失败路径的等价状态，避免平台相关 UDP 行为）
	s.recordError()
	s.recordError()
	s.recordError()
	if !s.IsDown() {
		t.Fatal("sender must be down after 3 errors")
	}

	a, b, c := dgOf(1, 32), dgOf(2, 32), dgOf(3, 32)
	s.Send(a)
	s.Send(b)
	s.Send(c)
	if spy.buffered != 3 || spy.replayDroppedN != 0 {
		t.Fatalf("buffered=%d dropped=%d", spy.buffered, spy.replayDroppedN)
	}
	if spy.dropN != 0 || spy.sentN != 0 {
		t.Fatalf("down 期间不得有发送/丢弃：sent=%d drop=%d", spy.sentN, spy.dropN)
	}

	// 恢复：recordOK（写成功路径）触发按序重放
	s.recordOK()
	got1, got2, got3 := sink.recv(t), sink.recv(t), sink.recv(t)
	if binary.BigEndian.Uint32(got1[0:4]) != 1 || binary.BigEndian.Uint32(got2[0:4]) != 2 || binary.BigEndian.Uint32(got3[0:4]) != 3 {
		t.Fatalf("replay order broken: %d/%d/%d",
			binary.BigEndian.Uint32(got1[0:4]), binary.BigEndian.Uint32(got2[0:4]), binary.BigEndian.Uint32(got3[0:4]))
	}
	if spy.buffered != 0 || spy.lag != 0 {
		t.Fatalf("after drain: buffered=%d lag=%v", spy.buffered, spy.lag)
	}
	if spy.down {
		t.Error("down flag must clear on recovery")
	}
}

// TestSenderReplayDisabled —— 禁用重放时 down 期间按原语义丢弃计数。
func TestSenderReplayDisabled(t *testing.T) {
	sink := newUDPSink(t)
	s, spy := newReplayTestSender(t, sink.addr, replayPolicy{}) // disabled
	s.recordError()
	s.recordError()
	s.recordError()
	s.Send(dgOf(1, 32))
	if spy.dropN != 1 || spy.buffered != 0 {
		t.Fatalf("disabled replay: drop=%d buffered=%d", spy.dropN, spy.buffered)
	}
}
