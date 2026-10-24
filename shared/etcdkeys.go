package shared

// etcd 键空间契约（docs/09 §5 唯一权威；常量即接口，变更须先改 09）
//
// 值信封结构（2026-10-25 裁定）：EtcdKeyZones / EtcdKeyForwardRules /
// EtcdKeyConfigAnalytics / EtcdKeyConfigCollector 四个配置键的值统一为信封：
//
//	{"version": <uint64 单调递增>, "updated_at": <RFC3339 时间>, "data": <业务负载 JSON>}
//
// 消费方（Broker/Collector/Analytics）在 watch 入口须先解信封取 data。
// EtcdKeyAssignFlow（分配表快照）与 /lucid/leader（选主）不适用信封，
// 值结构以 09 §5 及属主模块定义为准。

const (
	// EtcdKeyAssignFlow exporter→collector 一致性哈希分配表快照（非信封，直接 JSON）
	EtcdKeyAssignFlow = "/lucid/assign/flow"
	// EtcdKeyForwardRules R1 转发规则（含 exporter_groups 展开；信封）
	EtcdKeyForwardRules = "/lucid/forward/rules"
	// EtcdKeyZones Zone 配置（PG 同步；信封）
	EtcdKeyZones = "/lucid/zones"
	// EtcdKeyConfigAnalytics Analytics 配置：internal_exclude、检测阈值覆盖、维护静默（信封）
	EtcdKeyConfigAnalytics = "/lucid/config/analytics"
	// EtcdKeyConfigCollector Collector 配置键前缀（信封）；完整键 = 本前缀 + {node}，{node} 由调用方拼接
	EtcdKeyConfigCollector = "/lucid/config/collector/"
)
