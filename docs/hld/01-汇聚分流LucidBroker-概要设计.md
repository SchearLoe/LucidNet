# 01 · 汇聚分流 LucidBroker — 概要设计

> 需求：R1（多目的转发+再采样）、集群横向扩展（FLB）；DPDK 报文分流为 M3+ 可选增强

## 1. 定位与边界

- **做**：NetStream/NetFlow/IPFIX/sFlow UDP 报文的接收、按 exporter 分发到采集集群（FLB）、按规则向多目的地转发（Forwarder）。
- **不做**：协议解码（Collector 职责）、报文级处理（M3+ DPDK 子模块另行立项）。

## 2. 子模块

| 子模块 | 职责 |
|---|---|
| **FLB（Flow Load Balancer）** | 收全量流报文 → 查 exporter→collector 一致性哈希表（Master 下发）→ 转发至 Collector；后端探活与自动再平衡 |
| **Forwarder（R1）** | 按转发规则把"原始数据流"复制/重编码到一个或多个第三方目的地；每目的地可独立再采样 |
| Admin Agent | gRPC 接收 Master 规则（哈希表、转发规则），热更新；上报自监控指标 |

## 3. 部署与数据流

```
 exporters(N台设备) ──UDP──► FLB ──UDP──► Collector×4
                              │
                              ├─(复制点)─► Forwarder ──再采样/重编码──► 目的地1..n (第三方系统)
                              │
                              └─ 若无 Forwarder 规则，流量不复制（零开销）
```

- FLB 与 Forwarder 同进程（`lucid-broker`），默认仅 FLB 生效；启用 Forwarder 规则后按规则复制。
- 单节点 25G×2 网卡；UDP 收发全走 SO_REUSEPORT 多进程。

## 4. 对外接口

| 接口 | 方向 | 说明 |
|---|---|---|
| gRPC `BrokerAdmin` | Master→Broker | WatchRoutes（哈希表）、WatchForwardRules（R1 规则） |
| Prometheus `/metrics` | 监控 | 每规则/每目的地收发速率、丢弃、再采样比例 |
| UDP 9995/9996/6343/2055… | exporters→Broker | 流协议入口（端口可配） |

## 5. 关键指标

- FLB：单节点 ≥150w UDP pps 转发；节点故障切换 <3s（探测 1s×3）。
- Forwarder 透传：≥100w pps；代理重编码（含再采样）：≥30w records/s（详见 DD §6 性能账）。

## 6. 需求映射

| 需求 | 实现要点 | 详见 |
|---|---|---|
| R1 多目的转发 | 规则：匹配源IP（exporter）/分组 → destinations[] | dd/01 §3 |
| R1 再采样 | 每目的地独立 sample 配置（透传模式不支持，代理模式支持） | dd/01 §4 |
