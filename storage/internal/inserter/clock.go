package inserter

import "time"

// Clock —— 可注入时钟（批量器 flush 周期确定性单测用，docs/11 §3 表驱动测试）。
type Clock interface {
	Now() time.Time
	NewTicker(d time.Duration) Ticker
}

// Ticker —— Clock.NewTicker 返回的周期信号源。
type Ticker interface {
	C() <-chan time.Time
	Stop()
}

// SystemClock —— 真实时钟实现。
type SystemClock struct{}

// Now 返回当前墙钟时间。
func (SystemClock) Now() time.Time { return time.Now() }

// NewTicker 构造真实周期信号源。
func (SystemClock) NewTicker(d time.Duration) Ticker { return systemTicker{t: time.NewTicker(d)} }

type systemTicker struct{ t *time.Ticker }

func (s systemTicker) C() <-chan time.Time { return s.t.C }

func (s systemTicker) Stop() { s.t.Stop() }
