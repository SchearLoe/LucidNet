package flb

import (
	"sync"
	"sync/atomic"
	"time"
)

// Health —— collector 本地健康态（dd/01 §2.3：1s×3 次失败标记 down 并本地摘除；
// Master 是分配权威，本地摘除仅快速兜底——超过 restoreAfter 未被 Master 纠正则恢复信 Master，
// 避免脑裂）。
type Health struct {
	mu           sync.RWMutex
	entries      map[string]*entry
	failThresh   int32
	restoreAfter time.Duration
	onChange     func(addr string, down bool)
}

type entry struct {
	fails  atomic.Int32
	down   atomic.Bool
	downAt atomic.Int64 // unix ms
}

// NewHealth 构造（threshold≤0 取 3；restoreAfter≤0 取 60s）。
func NewHealth(threshold int, restoreAfter time.Duration, onChange func(string, bool)) *Health {
	if threshold <= 0 {
		threshold = 3
	}
	if restoreAfter <= 0 {
		restoreAfter = 60 * time.Second
	}
	if onChange == nil {
		onChange = func(string, bool) {}
	}
	return &Health{
		entries:      map[string]*entry{},
		failThresh:   int32(threshold),
		restoreAfter: restoreAfter,
		onChange:     onChange,
	}
}

// IsHealthy 查询（热路径；down 超时自动恢复=信 Master）。
func (h *Health) IsHealthy(addr string, now time.Time) bool {
	h.mu.RLock()
	e, ok := h.entries[addr]
	h.mu.RUnlock()
	if !ok || !e.down.Load() {
		return true
	}
	if now.UnixMilli()-e.downAt.Load() > h.restoreAfter.Milliseconds() {
		// 60s 内 Master 未纠正则恢复（dd/01 §2.3）：重新纳入，等待探测再次判down
		if e.down.CompareAndSwap(true, false) {
			e.fails.Store(0)
			h.onChange(addr, false)
		}
		return true
	}
	return false
}

// RecordOK 成功（写/探测）反馈。
func (h *Health) RecordOK(addr string) {
	h.entry(addr).fails.Store(0)
	h.mark(addr, false)
}

// RecordFail 失败反馈（写错误/探测超时）。
func (h *Health) RecordFail(addr string, now time.Time) {
	e := h.entry(addr)
	if e.fails.Add(1) >= h.failThresh {
		h.mark(addr, true, now)
	}
}

// mark —— 状态迁移（只在变化时回调/打点）。
func (h *Health) mark(addr string, down bool, at ...time.Time) {
	h.mu.RLock()
	e := h.entries[addr]
	h.mu.RUnlock()
	if e == nil {
		return
	}
	if down {
		if e.down.CompareAndSwap(false, true) {
			if len(at) > 0 {
				e.downAt.Store(at[0].UnixMilli())
			} else {
				e.downAt.Store(time.Now().UnixMilli())
			}
			h.onChange(addr, true)
		}
		return
	}
	if e.down.CompareAndSwap(true, false) {
		h.onChange(addr, false)
	}
}

// entry 懒建（无锁竞争路径：仅探测/写错误时进入）。
func (h *Health) entry(addr string) *entry {
	h.mu.RLock()
	e, ok := h.entries[addr]
	h.mu.RUnlock()
	if ok {
		return e
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if e, ok = h.entries[addr]; !ok {
		e = &entry{}
		h.entries[addr] = e
	}
	return e
}

// Snapshot —— 健康态导出（自监控）。
func (h *Health) Snapshot() map[string]bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	out := make(map[string]bool, len(h.entries))
	now := time.Now()
	for addr, e := range h.entries {
		if e.down.Load() && now.UnixMilli()-e.downAt.Load() <= h.restoreAfter.Milliseconds() {
			out[addr] = false
		} else {
			out[addr] = true
		}
	}
	return out
}
