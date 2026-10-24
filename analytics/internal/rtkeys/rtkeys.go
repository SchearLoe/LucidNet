// Package rtkeys —— Redis 实时键命名契约（docs/09 §6 2026-10-25 裁定：
// /api/v1/stream/* 数据源统一 rt:* 前缀；dd/03 §7 旧文 topn:{dim}:{ts}
// 写法作废，以 09 为准）。
//
// 键名只能经本包构造，禁止散落拼接：
//
//	rt:topn:{dim}:{ts}      滚动 1m/5m Top-K（TTL 10m；ts=窗口起点 epoch 秒）
//	rt:evidence:{attack_id} 攻击证据快照（TTL 24h，dd/03 §6.1）
//
// 当前无 Redis 客户端：Store 接口 + DevStore 内存实现（store.go）供开发/单测，
// M2 以真实客户端实现 Store；消费方（网关 rt:* 轮询）见 09 §6。
package rtkeys

import "strconv"

const (
	// Prefix —— rt:* 实时键统一前缀（09 §6）。
	Prefix = "rt"
	// TopNPrefix —— 滚动 Top-K 键前缀（rt:topn:）。
	TopNPrefix = Prefix + ":topn:"
	// EvidencePrefix —— 攻击证据快照键前缀（rt:evidence:）。
	EvidencePrefix = Prefix + ":evidence:"
)

// TopN —— 滚动 1m/5m Top-K 键：rt:topn:{dim}:{ts}。
// dim 由 TopN 算子定义（须满足 ValidDim，如 src_ip_1m/dst_ip_5m），
// tsSec 为窗口起点 epoch 秒（对齐 09 §6 时间参数单位裁定）。
func TopN(dim string, tsSec int64) string {
	return TopNPrefix + dim + ":" + strconv.FormatInt(tsSec, 10)
}

// Evidence —— 攻击证据快照键：rt:evidence:{attack_id}（dd/03 §6.1）。
func Evidence(attackID string) string {
	return EvidencePrefix + attackID
}
