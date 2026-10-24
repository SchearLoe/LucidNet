// Package nodecfg —— /lucid/config/collector/{node} 配置负载镜像
// （docs/09 §5：端口 / per-exporter 采样登记表 / 命名正则 / RIB 快照指针）。
//
// 键值为信封（internal/etcdcfg），本包只镜像信封 data 内的业务负载形状；
// 写侧 = Master（master/internal/config），线格式权威。
package nodecfg

import (
	"encoding/json"
	"fmt"
)

// Config —— per-node Collector 配置负载。
type Config struct {
	// Listen / SFlowListen —— UDP 监听（dd/02 §6：本地仅 bind 地址；
	// TODO(hot-reload)：变更需重建 socket，watch 接入后实现）。
	Listen      string `json:"listen,omitempty"`
	SFlowListen string `json:"sflow_listen,omitempty"`

	// ZoneMatch —— zone 匹配面 dst|src（docs/09 §3，默认 dst，禁止 both）；
	// etcd 值覆盖本地 flag 缺省（dd/02 §6 配置全量 etcd）。应用点校验枚举。
	ZoneMatch string `json:"zone_match,omitempty"`

	// SampleRegistry —— per-exporter 采样率倒数登记表（dd/02 §1 定制点 #3：
	// v5 头无采样时依赖此表；1=全采）。
	// TODO(decoder)：接入 v5 解码 per-exporter 采样覆盖。
	SampleRegistry map[string]uint32 `json:"sample_registry,omitempty"`

	// NamingRules —— 接口命名正则表（dd/02 §5.2；PG 正则表镜像，
	// 未下发时用预置规则 snmp.DefaultNamingRules）。
	// TODO(snmp)：转换为 snmp.NamingRule 接入 RuleEngine。
	NamingRules []NamingRule `json:"naming_rules,omitempty"`

	// RIBSnapshotPtr —— RIB 快照指针（dd/02 §3.1：指向最新全量快照版本，
	// RIB Feeder GetSnapshot 拉取用）。
	// TODO(rib)：gRPC 客户端接入后消费。
	RIBSnapshotPtr string `json:"rib_snapshot_ptr,omitempty"`
}

// NamingRule —— 命名正则表条目（dd/02 §5.2）。
type NamingRule struct {
	Pattern string `json:"pattern"`
	// Role —— internal | boundary（enrich.IfRole 文本镜像）。
	Role string `json:"role"`
}

// Parse —— 信封 data 负载 → Config。
//
// 校验：必须为 JSON 对象（裸数组/标量报错）；NamingRule.Role 枚举
// internal|boundary（空 pattern 报错——正则表条目必须可用）；
// ZoneMatch 枚举在应用点（cmd）经 zone.ParseMatchField 校验，此处不重复。
func Parse(data []byte) (Config, error) {
	var c Config
	if err := json.Unmarshal(data, &c); err != nil {
		return Config{}, fmt.Errorf("parse collector node config payload (must be json object): %w", err)
	}
	for i, r := range c.NamingRules {
		if r.Pattern == "" {
			return Config{}, fmt.Errorf("naming_rules[%d]: pattern required", i)
		}
		switch r.Role {
		case "internal", "boundary":
		default:
			return Config{}, fmt.Errorf("naming_rules[%d]: role %q invalid (internal|boundary)", i, r.Role)
		}
	}
	return c, nil
}
