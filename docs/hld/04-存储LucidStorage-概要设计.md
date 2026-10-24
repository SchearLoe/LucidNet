# 04 · 存储 LucidStorage — 概要设计

> 需求：R6（原始日志 15 天 + Web 条件查询）、R5（攻击时段原始日志导出）；承载聚合/攻击/指标/导出归档

## 1. 定位与边界

- **做**：ClickHouse 集群（明细+聚合+攻击）、VictoriaMetrics、Redis、MinIO 的规划、写入（inserter）、查询代理（query API）、异步导出任务。
- **不做**：分析计算（Analytics）、页面（Console 调 query API）。

## 2. 存储矩阵

| 存储 | 数据 | 保留 | 介质 |
|---|---|---|---|
| ClickHouse | flows_raw 明细 | **15 天**（R6）：热 3 天 NVMe + 冷 12 天 HDD 卷 | NVMe+HDD 混合存储策略 |
| ClickHouse | aggr_minute / aggr_hour | 13 个月 / 3 年 | NVMe |
| ClickHouse | attacks / attack_minutes / baseline | 1 年 / 6 个月 / 8 周 | NVMe |
| VictoriaMetrics | 接口/设备/集群指标 | 13 个月 | 本地盘 |
| Redis | 实时 TopN/证据/任务状态 | TTL ≤24h | 内存 |
| MinIO | 导出产物（R5）/报表产物（R8） | 30 天 | HDD |

## 3. ClickHouse 集群拓扑

3 分片（3 节点各 1 分片），`flows_raw` 双副本（跨节点），聚合表双副本；Distributed 表 `flows_raw_all` 等；inserter 按 `(day, exporter)` 哈希定向分片（写本地表，避免 Distributed 额外跳数）。

## 4. 对外接口

| 接口 | 消费方 | 说明 |
|---|---|---|
| `Inserter.Write(batch)` gRPC | Analytics / Collector 模板流 | 批量写，幂等批次号 |
| `QueryService` gRPC→REST 网关 | Console | 明细查询（R6，强约束）/聚合查询/攻击查询 |
| `ExportService` | Console | 异步导出任务（R5） |

## 5. 关键指标

- 明细写入 100w rows/s 集群（单分片 35w）；查询：15 天内任意 6h 窗口 + 5 条件，P95 <5s；导出 1 亿行 ≈ 10 分钟。
- 磁盘水位 80% 告警，85% 自动触发"降采样/缩短 TTL"预案。

## 6. 需求映射

| 需求 | 要点 | 详见 |
|---|---|---|
| R6 | 15 天 TTL 冷热分层 + Web 条件查询约束 | dd/04 §2/§3 |
| R5 | 攻击时段导出：格式化文本/CSV，异步任务 | dd/04 §5 |
