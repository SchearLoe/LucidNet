package forwarder

import (
	"time"
)

// replayBuffer —— 目的地断连重放环形缓冲（dd/01 §4.3 + 任务二）：
// 目的地判定 down 期间，下行数据报入缓冲；恢复后按序重放；
// 容量约束「窗口 5s 或 maxBytes 512MB 先到为准」（可配）——超窗或超量
// 丢弃最旧并计数。缓冲条目为发送方持有的独立拷贝（透传复制/代理新分配）。
//
// 非并发安全：由 udpSender 的 order 互斥串行化（Send/drain/Take/Install 同锁）。
type replayBuffer struct {
	items    []replayItem
	head     int   // 队首下标（items[head:] 为有效区，头部淘汰后触发整理）
	bytes    int64 // 有效数据字节数
	window   time.Duration
	maxBytes int64
}

// replayItem —— 缓冲条目；at 为入缓冲时刻（会话重建迁移时保留原值，
// 窗口老化不因迁移重置，杜绝"热更新洗白超龄数据"）。
type replayItem struct {
	data []byte
	at   time.Time
}

// push 入队一条；超窗/超量淘汰最旧并回调计数。window≤0 视为未启用（调用方回退丢弃）。
func (b *replayBuffer) push(item replayItem, now time.Time, onDropped func(int)) {
	if b.window <= 0 {
		if onDropped != nil {
			onDropped(1)
		}
		return
	}
	if int64(len(item.data)) > b.maxBytes {
		// 单条超容量上限：任何缓冲布局都无法容纳，直接计数丢弃
		if onDropped != nil {
			onDropped(1)
		}
		return
	}
	b.evictExpiredLocked(now, onDropped)
	for b.bytes+int64(len(item.data)) > b.maxBytes && b.len() > 0 {
		b.dropOldest(onDropped)
	}
	b.items = append(b.items, item)
	b.bytes += int64(len(item.data))
}

// drain 按序弹出：过期计数淘汰；其余经 sink 送出，sink 返回 false（队列满/
// 限速未放行）即停止——剩余条目留在缓冲，由写入成功后的 top-up 续传。
func (b *replayBuffer) drain(now time.Time, sink func([]byte) bool, onDropped func(int)) {
	for b.len() > 0 {
		item := b.items[b.head]
		if now.Sub(item.at) >= b.window {
			b.dropOldest(onDropped) // 超窗数据：恢复后也不再重放（dd/01 §7.3）
			continue
		}
		if !sink(item.data) {
			return
		}
		b.items[b.head] = replayItem{}
		b.head++
		b.bytes -= int64(len(item.data))
		if b.head == len(b.items) {
			b.items = b.items[:0]
			b.head = 0
		} else if b.head >= 64 && b.head*2 >= len(b.items) {
			b.compactLocked()
		}
	}
}

// take 取走全部条目（会话重建迁移：旧会话提取）。
func (b *replayBuffer) take() []replayItem {
	if b.len() == 0 {
		return nil
	}
	items := make([]replayItem, b.len())
	copy(items, b.items[b.head:])
	b.bytes = 0
	b.items = b.items[:0]
	b.head = 0
	return items
}

// install 装入继承条目（保留原 at）；超窗条目按窗口语义淘汰计数。
func (b *replayBuffer) install(items []replayItem, now time.Time, onDropped func(int)) {
	for _, it := range items {
		if now.Sub(it.at) < b.window {
			b.push(it, now, onDropped)
			continue
		}
		if onDropped != nil {
			onDropped(1)
		}
	}
}

// clear 清空（会话关闭：不计数——会话终止非断连丢弃）。
func (b *replayBuffer) clear() {
	b.items = b.items[:0]
	b.head = 0
	b.bytes = 0
}

// len 有效条目数。
func (b *replayBuffer) len() int { return len(b.items) - b.head }

// oldestAge 最老条目年龄（空缓冲返回 0）——forward_replay_lag_seconds 语义。
func (b *replayBuffer) oldestAge(now time.Time) time.Duration {
	if b.len() == 0 {
		return 0
	}
	if d := now.Sub(b.items[b.head].at); d > 0 {
		return d
	}
	return 0
}

// dropOldest 淘汰最旧一条（容量/超窗共用），回调计数。
func (b *replayBuffer) dropOldest(onDropped func(int)) {
	if b.len() == 0 {
		return
	}
	item := b.items[b.head]
	b.items[b.head] = replayItem{}
	b.head++
	b.bytes -= int64(len(item.data))
	if b.head == len(b.items) {
		b.items = b.items[:0]
		b.head = 0
	} else if b.head >= 64 && b.head*2 >= len(b.items) {
		b.compactLocked()
	}
	if onDropped != nil {
		onDropped(1)
	}
}

// evictExpiredLocked —— 按窗口淘汰过期头部（push/drain 入口调用）。
func (b *replayBuffer) evictExpiredLocked(now time.Time, onDropped func(int)) {
	for b.len() > 0 && now.Sub(b.items[b.head].at) >= b.window {
		b.dropOldest(onDropped)
	}
}

// compactLocked —— 头部淘汰后的底层数组回收（均摊 O(1)，防头部空洞无限增长）。
func (b *replayBuffer) compactLocked() {
	n := copy(b.items, b.items[b.head:])
	for i := n; i < len(b.items); i++ {
		b.items[i] = replayItem{}
	}
	b.items = b.items[:n]
	b.head = 0
}
