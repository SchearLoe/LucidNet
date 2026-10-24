package inserter

import (
	"fmt"
	"hash/fnv"
)

// Router —— (day, hash64(exporter)) → shard 分片路由器（docs/dd/04 §1.3）。
// 同一 (day, exporter) 恒定落同一分片；Inserter 写各分片本地表（不走 Distributed
// 额外跳数，docs/hld/04 §3），算法须全集群一致。
//
// 契约注记：docs/dd/04 §1.3 只写了 hash64(exporter) 未指定算法。本实现以
// FNV-1a 64（stdlib、跨节点确定性）对 (day, exporter) 联合键哈希；若需与
// ClickHouse cityHash64 对齐须先改契约文档（见模块 README 契约问题清单）。
type Router struct {
	shards uint64
}

// NewRouter 构造分片路由器；shards 为分片数（docs/hld/04 §3：3 分片起步）。
func NewRouter(shards int) (*Router, error) {
	if shards <= 0 {
		return nil, fmt.Errorf("new router: shard count %d must be positive", shards)
	}
	return &Router{shards: uint64(shards)}, nil
}

// Shards 返回分片数。
func (r *Router) Shards() uint64 { return r.shards }

// ShardFor 返回 0 基分片号。
// key 约定：flows.raw / flows.aggr.minute 用 exporter；attacks.minutes 消息无
// exporter（key=attack_id）、alarms 无 exporter（key=zone_id），骨架分别以
// attack_id、zone_id 作路由键（契约缺口，见模块 README 问题清单）。
func (r *Router) ShardFor(day, key string) uint64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(day))
	_, _ = h.Write([]byte{0x1f}) // (day, key) 联合键分隔符
	_, _ = h.Write([]byte(key))
	return h.Sum64() % r.shards
}
