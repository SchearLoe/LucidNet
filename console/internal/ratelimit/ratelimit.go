// Package ratelimit —— 每用户令牌桶限流（docs/dd/05 §6：明细查询类接口 10 QPS/用户）。
package ratelimit

import (
	"math"
	"sync"
	"time"
)

// Bucket —— 单用户令牌桶（懒填充）。
type Bucket struct {
	tokens float64
	last   time.Time
}

// Limiter —— 按 key（user uid）限流。
type Limiter struct {
	mu      sync.Mutex
	rate    float64 // 令牌/秒
	burst   float64 // 桶容量
	buckets map[string]*Bucket
	now     func() time.Time
}

// New 构造；rate>0，burst>=1。
func New(rate float64, burst int) *Limiter {
	if rate <= 0 {
		rate = 10
	}
	if burst < 1 {
		burst = 1
	}
	return &Limiter{
		rate:    rate,
		burst:   float64(burst),
		buckets: make(map[string]*Bucket),
		now:     time.Now,
	}
}

// WithClock 注入时间源（确定性单测）。
func (l *Limiter) WithClock(now func() time.Time) *Limiter {
	l.now = now
	return l
}

// Allow 消费 1 个令牌；超限返回 false（调用方回 429）。
func (l *Limiter) Allow(key string) bool {
	return l.AllowN(key, 1)
}

// AllowN 消费 n 个令牌。
func (l *Limiter) AllowN(key string, n int) bool {
	if n < 1 {
		n = 1
	}
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	b, ok := l.buckets[key]
	if !ok {
		// 防桶数无界增长（uid 有界：活跃用户数）；超 10 万清空重置（简单兜底）。
		if len(l.buckets) > 100000 {
			l.buckets = make(map[string]*Bucket)
		}
		b = &Bucket{tokens: l.burst, last: now}
		l.buckets[key] = b
	}
	elapsed := now.Sub(b.last).Seconds()
	b.tokens = math.Min(l.burst, b.tokens+elapsed*l.rate)
	b.last = now
	if b.tokens < float64(n) {
		return false
	}
	b.tokens -= float64(n)
	return true
}
