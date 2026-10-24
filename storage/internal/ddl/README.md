# internal/ddl —— ClickHouse DDL（migrations/ch/）

> 列定义唯一权威 = `docs/00-公共数据模型与接口规范.md §4`；读写矩阵 = `docs/09-模块间接口契约.md §8`。
> 文件命名遵循 `docs/11 §7`（CH DDL 变更走 `migrations/ch/`；禁止修改已合入的历史迁移）。

## 占位参数

所有文件使用三个占位符，部署时替换：

| 占位符 | 含义 | 典型值 |
|---|---|---|
| `{cluster}` | ON CLUSTER 集群名（remote_servers 配置） | `lucid` |
| `{shard}` / `{replica}` | Replicated 表 ZooKeeper 宏（每节点 macros 配置） | `01` / `ch01-r1` |

## 部署顺序（严格按序；对应 dd/08 §4.2 S4 数据初始化）

1. **0000**：每节点写入 `storage.xml`（磁盘 hot/cold + 策略 hot_cold），重启 CH 生效——节点级配置，不经 SQL；
2. **0001–0006**：本地表 `ON CLUSTER` 依次建 `flows_raw → aggr_minute → aggr_hour（含 MV mv_aggr_hour_aggr_minute）→ attacks/attack_minutes → baseline → alarm_history`；
3. **0007**：Distributed `_all` 包装表（本地表全部就绪后）；
4. 验证：`system.tables` / `system.replicas` / `system.disks` / `system.storage_policies`（各文件尾注附语句）。

## 写入通道与物化视图裁定（09 优先）

- CH 写入方唯一 = **Inserter**（Kafka 消费，09 §2/§8）：flows.raw→flows_raw、flows.aggr.minute→aggr_minute、attacks.minutes→attack_minutes、alarms→attacks/alarm_history；
- **不建** `flows_raw → mv_aggr_minute`：09 §8 裁定 aggr_minute 来源 topic；dd/04 §1.2/00 §4 尾注的"从 flows_raw 滚动"与之冲突，已按 09 执行并登记契约问题（storage/README.md）；
- baseline 为例外通道：Analytics Leader 每小时经 CH HTTP 接口低频直写（09 §8 注）。

## 已知契约缺口（详见 storage/README.md 问题清单）

- flows_raw 无 `zone_side / src_geo / dst_geo / bgp_next_hop` 列（FlowRecord 字段落库丢失）；
- `tcp_flags/tos` DDL UInt8 vs proto uint32 截断；
- 告警历史表（0006 alarm_history）无契约 DDL，本目录文件为 Storage 侧提案。
