# 04 · 存储 LucidStorage — 详细设计

## 1. ClickHouse 物理设计

### 1.1 卷与存储策略
```sql
DISK hot  TYPE NVMe  PATH /ch/hot   -- 每节点 2×7.68T (RAID0)
DISK cold TYPE HDD  PATH /ch/cold   -- 每节点 8×20T (RAID0/单盘均可)
STORAGE POLICY hot_cold = hot, cold   -- TTL 到期自动迁移（move_factor 0.2，后台 2 线程）
```
容量账（100w fps，压缩 20B/行）：热 3 天 ≈ 4–6.6TB/副本 ×2；冷 12 天 ≈ 16–26TB/副本 ×2 → 3 节点每节点：NVMe 15.4TB（余量 ✓）、HDD 160TB（余量 ✓）。**均值流量打六折后余量 >40%**。

### 1.2 表（DDL 主体见 00 §4，此处补关键参数）
- `flows_raw`：`SETTINGS index_granularity=8192, storage_policy='hot_cold'`；bloom_filter(src_ip/dst_ip, 0.01) granularity 4；`minmax(bytes)` granularity 4（攻击时段按体量粗筛）。
- 物化视图链：`flows_raw → mv_aggr_minute → mv_aggr_hour`（-State 聚合函数链式 MergeState）；**互联过滤不进入物化视图**（原始表保留全量，R4 过滤是查询/分析语义，数据层不物理删除——取证需要全量）。
- 副本：ReplicatedMergeTree，`insert_quorum=1, insert_quorum_parallel=1`（吞吐优先）；`max_part_delay_for_merge` 监控。

### 1.3 分片路由
- `Inserter` 维持 `(day, hash64(exporter)) → shard` 映射，写各分片本地表（HTTP native 协议批量 `INSERT SELECT` 不用，直接 binary block）；
- 批次：≥50,000 行或 2s flush（单分片 <10 并发 insert）；幂等批次号写入 block info 的额外列 `_batch_id UInt64`（ReplacingMergeTree 语义不适用于明细——明细不重写，幂等仅靠批次追踪表 PG `export_batches`，失败整批重发）。

## 2. 明细查询（R6：15 天 Web 条件查询）

### 2.1 查询约束（防打爆，产品层面显式提示）
| 约束 | 默认 | 上限 |
|---|---|---|
| 时间窗 | 15 分钟 | **6 小时**（超过引导走异步导出） |
| 条件 | ≥1 个维度条件（IP/前缀/端口/协议/zone/设备/接口） | 8 个 |
| 返回行数 | 1,000（分页） | 同步 10,000 |
| 并发 | 每用户 2 | 全局 16（排队） |

### 2.2 查询 API（REST，经 Console 网关）
```
POST /api/v1/flows/search
{ "time_start":…, "time_end":…,
  "filters":{"src_ip":"1.2.3.0/24","dst_port":443,"proto":6,
             "zone_id":101,"device_id":7,"in_if":12,"ip_version":6},
  "order_by":"bytes","desc":true, "page":1,"page_size":100,
  "fields":["time_second","src_ip","src_port","dst_ip","dst_port","proto","bytes","packets","tcp_flags","in_if","out_if","sample_rate"] }
→ {total_estimate, rows:[…], query_id}
```
- SQL 生成：白名单字段→列名映射，禁止任意 SQL；自动下推 `WHERE time_second BETWEEN` + 分区裁剪 + 索引（bloom for ip）。
- `total_estimate`：`uniqExact` 超 1,000 万截断显示 ">10M"；深分页只允许按 (`time_second`, `_batch`) 游标（`page>50` 时强制游标模式）。
- v4/v6（R3）：`ip_version` 条件 + `IPv6NumToString(IPv4NumToString(...))` 展示函数按族格式化。

### 2.3 典型查询性能模型
最劣模式（仅 IP 条件 + 6h 窗）：扫描 6h×全 exporter 的 bloom 命中 granule ≈ 时间分区剪裁后 5–8% granule → 3 分片并行 ≈ P95 5–8s，符合指标；带 exporter/接口条件时 <1s。

## 3. 聚合与攻击查询
- 矩阵/TopN/报表全部走 `aggr_minute(_all)`（-Merge 补齐）；`attacks` 按 (zone_id, start_ms) 主键直查；`attack_minutes` 按 attack_id 点查（R5 详情页 <200ms）。

## 4. VictoriaMetrics / Redis / MinIO
- VM：单节点（vmsingle）起步，13 个月，`-retentionPeriod=13m`；采集链路：Collector/Analytics/Master → vmagent（汇聚）→ VM。
- Redis：主从 + Sentinel；库划分 db0 实时 TopN / db1 攻击证据 / db2 任务状态；持久化 AOF everysec。
- MinIO：单机 8×20T 之一复用（独立进程，容量预算 10TB）；bucket：`exports/`（R5/R6 产物）、`reports/`（R8）。

## 5. 异步导出（R5 攻击取证 + R6 大窗口）

### 5.1 任务模型
```
POST /api/v1/export/jobs
{ "type":"flows",                     // flows|attack_flows|aggr|attacks
  "attack_id":"01J…",                 // attack_flows 时自动填充窗口+zone
  "time_start":…,"time_end":…,        // ≤72h
  "filters":{同 2.2，可加 top_sources 联动},
  "format":"text|csv|jsonl",          // text=00 §7 格式化文本（默认）
  "sample":"raw|downscale_10x" }      // 巨量导出可选降采样
→ 202 {job_id}
GET /api/v1/export/jobs/{id} → {status:queued|running|progress:0.42|done,url,expires_at}
```

### 5.2 执行器（`lucid-exporter` worker，2 并发/节点）
1. 按 (day, exporter) 切片生成子查询队列；游标流式读取（`max_block_size=65536`，`max_threads=8`/子查询）。
2. 写临时文件（本地 NVMe，spill 上限 200GB/任务）→ 按行格式化（text/csv/jsonl）→ 分卷 2GB/卷 → 上传 MinIO（`exports/{job}/{part}.txt.gz`）。
3. 进度 = 已完成切片/总切片（Redis HINCRBY）；失败切片重试 3 次；任务中断可续（游标持久化）。
4. 文件头写入条件元数据（00 §7 可追溯要求）。

### 5.3 性能与限额
- 单任务吞吐目标 ≥15 万行/s（网络直读冷盘受限时 ≥8 万）；1 亿行 ≈ 11–19 分钟。
- 全局并发导出任务 ≤4；单用户日导出量配额（默认 200GB，超限审批）——防止把 15 天明细当数据外带通道刷爆 IO。
- 攻击联动（R5）：Console 攻击详情页 → `type=attack_flows`，预填 `(zone, start-1min, end+1min, Top 源∈filters 可选)`。

## 6. 备份与生命周期
- 配置库 PG：每日全备 + WAL 归档；CH 聚合表：每周 freeze 快照到 MinIO（明细不备份——源头可再生，容灾靠副本）；MinIO 导出产物 30 天生命周期删除。
- 磁盘预案：水位 85% → 按序执行 ① 降采样开关开（Analytics 配合） ② TTL 热段 3→2 天 ③ 告警升级人工。

## 7. 测试要点
1. R6 验收：15 天前的数据自动清除（TTL merge 验证）；任意 6h+3 条件查询 P95 <5s（100w fps 灌注数据集）。
2. R5 导出：attack_flows 全链路（详情页→任务→MinIO→下载），格式与 00 §7 逐字段断言；中断续跑。
3. 冷热迁移：第 4 天数据物理落在 cold 卷（system.parts 验证）。
4. 副本故障：kill 单 CH 节点，写入零中断（inserter 摘除+副本补写），查询降级不超时。
