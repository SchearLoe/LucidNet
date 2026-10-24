# 03 · 流式分析 LucidAnalytics — 概要设计

> 需求：R2（秒级客户级 DDoS 检测，300 客户×1000 IP）、R5（分钟级攻击详情）、R7（扫段攻击、客户总流量波动告警）；基础：分钟聚合/TopN/基线

## 1. 定位与边界

- **做**：Kafka `flows.raw` → 分钟级多维聚合（写 CH）、实时 TopN、动态基线、**Zone 秒级检测引擎**（R2/R7）、攻击事件与分钟详情生成（R5）、告警发布、与 LucidBGP 处置回执关联（R9）。
- **不做**：长周期离线建模（M3 容量预测，独立批任务）、查询与存储（CH inserter 归 Storage 部署）。

## 2. 算子拓扑

```
flows.raw(Kafka, key含zone_id)
  ├─► Aggregator    分钟多维聚合 → CH aggr_minute（内部互联过滤R4在此）
  ├─► TopN          滚动 Top-K → Redis(实时) + CH
  ├─► Baseline      分钟基线学习/比对（zone级+全局维度级）
  └─► Detector      ★Zone 秒级检测引擎
        ├─ 环形秒窗（bps/pps/newflows/flag比/端口分布/熵）
        ├─ 规则组：泛洪类|反射类|扫段(R7)|波动(R7)
        ├─ 状态机：候选→确认→持续→恢复 → AttackEvent
        └─ 每分钟固化为 AttackMinute(R5) + 证据快照
alarms ←─ Detector/Baseline ─→ LucidBGP(消费处置联动)
```

## 3. 关键设计决策

| 决策 | 理由 |
|---|---|
| 检测状态全部在内存（环形窗口），不做秒级落库 | 300 客户规模内存 <4GB；攻击证据按需固化，避免写入风暴 |
| zone_id 在 Kafka key 前缀 → 同客户全部记录同分区 | 检测无锁并行；客户扩容靠加分区 |
| 检测粒度 1s，确认 2/3 窗口 | "秒级"诉求 = 首告警延迟 ≤5s（1s 窗 + 2 确认窗 + 传播） |
| 扫段(R7)用 per-/24(v4)、/64(v6) HyperLogLog distinct-dst | 固定 2KB/段，防扫段攻击内存被目的 IP 扇出打爆 |
| 明细数据只读不回查 | 攻击取证走 Storage 导出任务（dd/04），分析层无 CH 查询依赖 |

## 4. 部署

2 节点（2×24C/256G）；`lucid-analytics` 单二进制；算子与 Kafka consumer group 同进程；Leader 选举（etcd）负责基线固化/告警去重等单实例职责。

## 5. 关键指标

- 输入 100w fps 下检测路径 P99 处理延迟 <100ms；攻击确认延迟 ≤5s。
- 基线：7 天学习期；分钟聚合延迟 ≤90s（跨分钟边界+批量写）。
- 容量：300（可扩 1,000）客户 × 1,000 IP 检测内存 <4GB。

## 6. 需求映射

| 需求 | 要点 | 详见 |
|---|---|---|
| R2 | Zone 引擎/规则组/内存预算 | dd/03 §3–§5 |
| R5 | AttackEvent/AttackMinute/证据 | dd/03 §6 |
| R7 | 扫段算法 + zone 波动告警 | dd/03 §4.2/§5 |
