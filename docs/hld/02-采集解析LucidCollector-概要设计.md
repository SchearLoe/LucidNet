# 02 · 采集解析 LucidCollector — 概要设计

> 需求：R3（IPv4/IPv6）、R4（SNMP 推算边界接口、分析去互联）、R2 前置（zone_id 富化）；基础流解码

## 1. 定位与边界

- **做**：NetStream/NetFlow v5/v9/IPFIX/sFlow 解码 → 归一化 FlowRecord → 富化（ASN/Geo/应用/**Zone**/接口角色）→ Kafka；SNMP 采集（资产、接口计数器、拓扑）；接口角色识别（R4）。
- **不做**：分发（Broker）、聚合与检测（Analytics）、存储写入（Storage 的 CH inserter 独立部署于 CH 节点）。

## 2. 子模块与数据流

```
UDP(来自FLB) ─► decoder(模板管理) ─► normalizer ─► enricher ─► producer(Kafka)
                                     (FlowRecord)   ├─ AS/RIB LPM（RIB Feeder gRPC，本地缓存）
                                                    ├─ GeoIP mmdb（本地）
                                                    ├─ app 端口映射（本地）
                                                    ├─ zone 匹配（etcd watch，LPM+精确IP哈希）   ← R2/R3
                                                    └─ if_role 查表（PG interfaces 快照）        ← R4
snmp-agent：poller(30/60s) → VM + PG资产更新；trap接收 → syslogs
            lldp/ospf 收集 → 接口角色识别引擎(R4) → PG interfaces.role
```

## 3. 关键设计点

| 点 | 决策 |
|---|---|
| 解码核心 | fork GoFlow2（BSD-3），修复其模板缓存持久化与华为 NetStream 私有 IE |
| Zone 富化前置（R2） | 采集侧完成 zone_id 打标 → Kafka key 含 zone_id → 检测并行无锁 |
| ifIndex 对齐 | NetStream ifIndex 与 SNMP ifIndex 同命名空间；启动/变更时对账校验（R4 风险点） |
| 双栈（R3） | 解码/归一/富化/LPM/存储全 128bit，显式 ip_version |

## 4. 对外接口

- 消费：UDP 2055/9995/9996/6343（Broker 转入）；gRPC `RibNameLookup`（RIB Feeder）；etcd（zone/配置）。
- 生产：Kafka `flows.raw`；VM 指标；PG 资产/接口表；Prometheus 自监控。

## 5. 关键指标

单节点（2×12C）30w flows/s 常态（压测 50w）；SNMP：2,000 设备 × 60s 轮询周期；模板丢失/未知字段计数必须告警。

## 6. 需求映射

| 需求 | 要点 | 详见 |
|---|---|---|
| R3 | 全链路 128bit 地址 + ip_version 显式字段 | dd/02 §2/§4 |
| R4 | 角色识别：manual > LLDP > IGP > 命名 > 默认；分析侧默认过滤 internal | dd/02 §5 |
| R2 前置 | zone LPM 匹配 ≤0.5µs/条；zone 变更 2s 内生效 | dd/02 §4.3 |
