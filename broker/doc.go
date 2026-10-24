// Package broker —— LucidNet 01 汇聚分流模块 LucidBroker 的模块根文档。
//
// 实际代码组织（docs/11 §2/§3）：
//   - cmd/lucid-broker        进程入口（单二进制 lucid-broker，dd/01 §0）
//   - internal/broker         引擎组装：ingest → flb → collector + forwarder 复制
//   - internal/ingest         UDP 收包（SO_REUSEPORT 多 socket，SO_RCVBUF≥64MB）
//   - internal/flb            exporter→collector 查表分发 + 探活兜底（dd/01 §2）
//   - internal/forwarder      R1 转发规则引擎：匹配/多目的/透传/代理重编码/再采样（dd/01 §3/§4）
//   - internal/flowcodec      代理路径编解码（v5 解码、v5/IPFIX 重编码、FlowRecord proto 编码）
//   - internal/kafkaprod      Kafka 生产（franz-go，flows.raw 等，docs/09 §2）
//   - internal/admin          etcd watch 配置下发（docs/09 §5）+ Master 注册心跳（docs/09 §4）
//   - internal/metrics        Prometheus 指标（docs/11 §9）
//   - internal/config         进程引导配置（env：LUCID_BROKER_*，docs/11 §8）
//   - internal/wire           proto3 线格式原语（gen/go 就绪前的手工编码基座）
//
// 契约：跨模块接口唯一权威 = docs/09-模块间接口契约.md；本模块不实现协议解码主链路
// （Collector 职责），仅在代理重编码路径按需解码。
package broker
