# 07 · 集群管理 LucidMaster — 概要设计

> 职责横切所有模块：节点管理、配置分发、负载分配、RBAC/租户、自监控、审计

## 1. 定位与边界

- **做**：集群唯一控制面——节点注册/心跳/角色编排、配置（etcd）权威与版本化下发、exporter→collector 哈希分配计算、用户/租户/RBAC/JWT、配置库（PostgreSQL）管理、升级编排、审计。
- **不做**：数据面任何转发/计算；分析类告警（Analytics）。

## 2. 组成

| 组件 | 说明 |
|---|---|
| `lucid-master` | Go 单实例（etcd 选主，双实例热备），REST+gRPC |
| etcd 集群 | 3 节点（复用部署于 Kafka/分析节点），配置/分配表/选主 |
| PostgreSQL | 配置权威库（devices/zones/rules/users/reports/mitigations 镜像…，见 00 §5） |
| 用户体系 | 账号/角色/权限点（RBAC），JWT 签发（15min）+ 刷新 |

## 3. etcd 键空间（权威配置 → 各模块 watch）

```
/lucid/nodes/{id}                 节点档案+心跳 lease
/lucid/assign/flow                exporter→collector 分配表（版本化快照）   ← Broker/Collector 消费
/lucid/config/collector/{node}    采集配置（端口/采样登记/命名正则/zone快照指针）
/lucid/config/analytics           检测开关/阈值覆盖/internal_exclude…
/lucid/zones                      Zone 配置（PG 同步，采集富化消费）
/lucid/forward/rules              R1 转发规则快照（Broker 消费）
/lucid/leader                     master 选主
```

## 4. 关键机制

| 机制 | 设计 |
|---|---|
| 节点生命周期 | 注册（启动自报角色/容量）→ lease 心跳 10s → 失联 30s 标 degraded、90s 触发再平衡 |
| 负载分配 | Master 计算一致性哈希表（160 虚拟节点/物理节点，容量权重=核数），版本化发布；节点增减仅迁移 ~1/N exporter |
| 配置版本 | 每次变更 version++，节点 ACK 回执；未 ACK 节点计数告警；支持一键回滚（保留最近 20 版本） |
| 升级 | 滚动：先 Broker→Collector（逐台，流量迁移走分配表）→ Analytics → Storage（副本轮换）→ Console/Master；DPDK 节点维护窗口 |
| 审计 | 全部写操作（who/when/diff/ip）入 PG `audit_log`，Console 可查 |

## 5. 自监控
- Prometheus 抓取全部节点（各模块自带 exporter）；大盘：全链路速率/丢包/lag/磁盘水位；告警通道与业务告警分离（短信+独立值班 webhook）。
- 自身故障演练：Master 宕机时数据面零影响（各模块用最后已知配置），仅配置变更不可用。

## 6. 部署拓扑
第 10 台机器：lucid-master + PostgreSQL(主) + Redis(主) + VictoriaMetrics + Console 静态资源 + Kafka 第 3 副本；etcd 3 节点借 Analytics×2 + Storage×1。
