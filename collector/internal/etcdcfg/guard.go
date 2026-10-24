package etcdcfg

import "sync"

// Guard —— 各配置键已应用版本台账（防乱序回放）。
//
// 两阶段语义（应用成功才记账，坏负载不吞后续同版本重发）：
//
//	if !g.ShouldApply(key, env.Version) { 忽略 + 日志/打点 }
//	… 解析 env.Data 并应用 …
//	g.MarkApplied(key, env.Version)
//
// 判定规则：version > 已应用版本 → 应应用（首见任何 ≥1 版本均可应用）；
// version ≤ 已应用版本（含相等，即同版本重放）→ 忽略。
type Guard struct {
	mu      sync.Mutex
	applied map[string]uint64
	stale   uint64 // ShouldApply 判定为忽略的累计次数（打点）
}

// NewGuard —— 构造空台账。
func NewGuard() *Guard {
	return &Guard{applied: make(map[string]uint64)}
}

// ShouldApply —— key 的 version 是否应应用（不记账）。
// 忽略时累计 stale 计数（供周期打点）。
func (g *Guard) ShouldApply(key string, version uint64) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if version <= g.applied[key] {
		g.stale++
		return false
	}
	return true
}

// MarkApplied —— 应用成功后记账（单调只增；回落写入忽略）。
func (g *Guard) MarkApplied(key string, version uint64) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if version > g.applied[key] {
		g.applied[key] = version
	}
}

// Applied —— key 当前已应用版本（0 = 从未应用）。
func (g *Guard) Applied(key string) uint64 {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.applied[key]
}

// StaleTotal —— 累计忽略的乱序/重放更新数（自监控打点；TODO Prometheus：
// lucid_collector_config_stale_total，docs/11 §9）。
func (g *Guard) StaleTotal() uint64 {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.stale
}
