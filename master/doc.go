// Package master —— LucidNet 07 集群管理 LucidMaster（lucid-master）。
//
// 职责（docs/hld/07 §1 / docs/dd/07）：
//   - 节点注册/心跳保活/故障判定（gRPC :9140 = shared.AddrMasterGRPC + etcd lease；
//     Kafka cluster.heartbeat 为可选副本通道）
//   - 配置模型与版本化发布（PG 权威 → etcd watch 分发，docs/09 §5 键空间属主）
//   - exporter→collector 一致性哈希分配表（/lucid/assign/flow，WatchAssign 流）
//   - RBAC/多租户/JWT 签发、REST 管理 API（/api/v1/admin/*、/api/v1/auth/*）
//   - 审计（PG audit_log）
//
// 升级编排属 08 LucidDeploy（dd/07 §6）：本模块仅提供排水与配置回滚原语。
// 包根为装配层（Server）；领域实现见 internal/{registry,config,assign,rbac,
// audit,auth,coord,rpc,restapi,masterpb}。
package master
