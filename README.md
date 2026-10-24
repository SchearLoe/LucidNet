# LucidNet

**网络流量智能分析平台** — 基于 NetStream / NetFlow / IPFIX / sFlow、SNMP、BGP/BMP 多源数据，提供网络流洞察、流量波动分析与秒级攻击检测处置的一体化产品。

> 对标 Genie Networks GenieATM / FLB；采集核心基于 [GoFlow2](https://github.com/netsampler/goflow2)，BGP 能力基于 [gobgp](https://github.com/osrg/gobgp)。

## 核心能力

- **网络流洞察**：分钟级多维流量矩阵、TopN、15 天明细钻取，IPv4/IPv6 双栈
- **流量波动分析**：动态基线（minute-of-week 分位数）、突变检测、客户域总流量波动告警
- **秒级攻击检测与处置**：客户级（300 客户 × 1000 IP）秒级 DDoS 检测、扫段攻击分析、分钟级攻击详情与原始日志取证、经 BGP（黑洞 / Flowspec）一键处置闭环
- **数据分发**：原始数据流按源 IP/分组多目的转发，支持逐目的地再采样

## 性能目标

10 台服务器集群 ≥ 100 万 flows/s 持续处理；采集单节点 30w fps（压测 50w）。

## 仓库结构

```
docs/
├── LucidNet-总体架构规划.md        总体架构 v0.2（需求追踪矩阵 R1-R9、容量规划、里程碑）
├── 00-公共数据模型与接口规范.md     proto / Kafka topic / ClickHouse DDL / REST 约定
├── 09-模块间接口契约.md          跨模块接口唯一权威（Kafka/gRPC/etcd/PG/端口/裁定记录）
├── hld/ 01~08                     各模块概要设计
│   ├── 01-汇聚分流LucidBroker       FLB 流负载均衡 + 多目的转发/再采样
│   ├── 02-采集解析LucidCollector    流解码归一化富化 + SNMP/接口角色识别
│   ├── 03-流式分析LucidAnalytics   分钟聚合 + Zone 秒级检测引擎
│   ├── 04-存储LucidStorage         ClickHouse 明细 15 天冷热分层
│   ├── 05-展示与报表LucidConsole   攻击中心 + 15 天明细查询 + 自定义报表
│   ├── 06-BGP路由管理LucidBGP      gobgpd 管理 + 告警联动处置闭环
│   ├── 07-集群管理LucidMaster      节点/配置/RBAC/自监控
│   └── 08-部署与升级LucidDeploy   拓扑一键安装 · 滚动升级 · 灰度回滚
└── dd/ 01~08                      各模块详细设计（可直接指导开发）
```

## 技术栈

Go（数据面/服务）+ Java 17 / Spring Boot（LucidBGP）+ C（DPDK，M3+）+ React 18 / TypeScript（前端）；Kafka / ClickHouse / VictoriaMetrics / Redis(Valkey) / etcd / PostgreSQL。

## 路线图

| 阶段 | 内容 |
|---|---|
| M0 | PoC：goflow2 → Kafka → ClickHouse 链路，单机 50w fps 压测 |
| M1 | MVP：分流/采集集群、IPv6、接口角色识别、核心看板 |
| M2 | 检测与取证：秒级 Zone 检测、扫段、攻击详情与导出、10 节点 100w fps 验收 |
| M3 | 报表中心、Flowspec 处置、多租户、容量预测 |

## License（双许可）

本项目采用 **AGPL-3.0-only + 商业双许可**，版权所有 © SchearLoe：

- **AGPL-3.0（免费）**：可自由使用、修改、部署，但衍生作品与对外提供的服务必须同样按 AGPL-3.0 完整开源（含网络服务，AGPL §13）。
- **商业许可（付费）**：闭源商用、产品集成、SaaS 托管等无法满足 AGPL 义务的场景，需获得版权人商业授权——通过 [github.com/SchearLoe](https://github.com/SchearLoe) 联系洽谈。

详见 [LICENSE](LICENSE)、[docs/商业授权说明.md](docs/商业授权说明.md) 与 [CONTRIBUTING.md](CONTRIBUTING.md)（贡献即同意双许可条款）。
