# 06 · BGP 路由管理 LucidBGP — 概要设计

> 需求：R9（基于私有仓库 `SchearLoe/rsbgp-console` 改名适配，模块命名已确认 **LucidBGP**）+ R2/R9 处置闭环
> 来源项目形态（实测读取自 rsbgp-console `gobgpd-v4.10.0` 分支 README）：Java 17 + Spring Boot 3.3 后端（把 GoBGP gRPC 60 个 RPC 全量代理为 REST，WatchEvent→SSE）+ React 17 前端（14 页面全中文），面向抗 DDoS 处置闭环，单 jar 部署，分支按适配的 gobgpd 版本命名。

## 1. 定位与边界

- **做**：gobgpd 守护进程的管理面（邻居/策略/RPKI/BMP/MRT/TCP-AO）、BGP 会话监控、**告警联动处置**（黑洞注入 RFC7999 community、限时自动撤销、处置记录）、处置事件回执（供 Analytics 闭环验证）、RIB 数据导出（供富化）。
- **不做**：流分析（Analytics）、告警检测（Analytics 是告警源）；Looking Glass 公开查询页（M3+ 可选）。

## 2. 组成

| 组件 | 形态 | 说明 |
|---|---|---|
| gobgpd | osrg/gobgp v4.10.0 守护进程 | 空 TOML 启动，全部运行态经 gRPC 配置（与 rsbgp-console 模型一致）；双实例主备 |
| **LucidBGP**（rsbgp-console 改名） | Java 17 单 jar（内嵌前端） | 管理控制台 + REST/SSE；端口 18081 |
| **RIB Feeder**（新增，Go） | 独立小服务 | 订 gobgpd WatchEvent/ListPath → 双栈 LPM 内存 RIB → gRPC `Lookup` 供 Collector 富化；增量推 Kafka `bgp.updates` |

## 3. 集成点（与 rsbgp-console 现状差异）

1. 认证：原无认证 → 接 LucidNet JWT（网关反代校验 + iframe SSO 一次性 token）。
2. 告警入口：原有 `POST /api/alarms` 保留（外部系统直调）；**新增 Kafka `alarms` 消费者**（Analytics 攻击事件自动进入"告警联动"页）。
3. 处置回执：新增生产者写 Kafka `bgp.mitigations`（动作/网段/时效/结果）→ Analytics 攻击状态机联动 + PG `mitigations` 镜像。
4. 多租户：告警与处置记录挂 `tenant/zone_id` 字段，租户数据隔离。

## 4. 保留不动的部分

- 60 RPC 的 REST 代理层、SSE 事件桥、连接方向控制（共享策略 web-direction-export/import + 邻居集合）、处置过滤（web-mitig-st）、限时撤销调度器（15s 粒度）、已知 gobgpd 工作副本限制的规避实现（详见 DD §7）。

## 5. 需求映射

| 需求 | 要点 | 详见 |
|---|---|---|
| R9 | 改名清单 + 集成改造 | dd/06 §2/§3 |
| R2/R9 | 攻击→处置→回执闭环 | dd/06 §5 |
