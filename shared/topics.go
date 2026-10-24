package shared

import "encoding/binary"

// Kafka Topic 契约（docs/09 §2 唯一权威；常量即接口，变更须先改 09）

const (
	TopicFlowsRaw        = "flows.raw"        // key=FlowKey(zone_id, exporter)
	TopicFlowsAggrMinute = "flows.aggr.minute" // key=exporter
	TopicAttacksMinutes  = "attacks.minutes"   // key=attack_id
	TopicAlarms          = "alarms"             // key=zone_id
	TopicFlowTemplates   = "flow.templates"     // key=exporter+obsDomain（compact，7d）
	TopicBGPUpdates      = "bgp.updates"        // key=router
	TopicBGPMitigations  = "bgp.mitigations"
	TopicSNMPIfCounters  = "snmp.ifcounters" // key=device
	TopicSyslogsRaw      = "syslogs.raw"      // key=device（M3）
	TopicClusterHB       = "cluster.heartbeat" // key=node
)

// Consumer Group 命名规范：<module>.<purpose>（组名即接口，新增需登记 09 §2）
const (
	GroupAnalyticsDetect   = "analytics.detect"        // flows.raw 检测消费组
	GroupAnalyticsAggregate = "analytics.aggregate"     // flows.raw 聚合消费组
	GroupStorageInserterFlows  = "storage.inserter.flows"  // flows.raw → CH flows_raw（明细15天，R6）
	GroupStorageInserterAggr   = "storage.inserter.aggr"   // flows.aggr.minute → aggr_minute
	GroupStorageInserterAttacks = "storage.inserter.attacks" // attacks.minutes → attack_minutes
	GroupStorageInserterAlarms  = "storage.inserter.alarms"  // alarms → attacks/告警历史
	GroupBGPAlarmLink      = "bgp.alarmlink"           // alarms → LucidBGP 处置联动
	GroupGatewayWS         = "gateway.ws"              // alarms/bgp.mitigations → WS 推送
	GroupMasterHeartbeat   = "master.heartbeat"        // cluster.heartbeat 的 Master 副本消费（可选通道；2026-10-25 裁定登记 09 §2）
)

// FlowKey —— flows.raw 消息 key：zone_id(4B 大端) + exporter（同客户同分区，检测无锁并行）
func FlowKey(zoneID int32, exporter string) []byte {
	k := make([]byte, 4, 4+len(exporter))
	binary.BigEndian.PutUint32(k, uint32(zoneID))
	return append(k, exporter...)
}

// ZoneFromKey —— 从 flows.raw key 还原 zone_id（前 4B 大端）
func ZoneFromKey(key []byte) int32 {
	if len(key) < 4 {
		return 0
	}
	return int32(binary.BigEndian.Uint32(key[:4]))
}

// gRPC 服务地址（docs/09 §4 / docs/dd/08 §2.2 端口基线）
const (
	AddrRibNameLookup = ":9131" // RIB Feeder
	AddrMasterGRPC    = ":9140" // Master
	AddrAgentGRPC     = ":9100" // lucid-agent（Deploy 命令通道，复用 Master.Heartbeat）
)
