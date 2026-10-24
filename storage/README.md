# storage —— LucidStorage 模块（walking skeleton）

> 设计：docs/hld/04、docs/dd/04；接口权威：docs/09（§2 Kafka / §8 CH 读写矩阵）、docs/00（§4 DDL / §7 导出文本格式）。
> 模块路径 `github.com/SchearLoe/lucidnet/storage`；零第三方依赖（联调桩全部接口化 + 内存假实现）。

## 目录

```
storage/
├── cmd/lucid-inserter/     # CH 写入唯一通道（Kafka 消费→分片路由→批量落表，dd/04 §1.3）
├── cmd/lucid-exporter/     # 异步导出 worker + 查询/导出 HTTP API（dd/04 §2.2/§5）
├── internal/ddl/           # migrations/ch/*.sql（00 §4 DDL + dd/04 §1.1/§1.2 参数；部署顺序见其 README）
├── internal/inserter/      # 消费/批量/路由/映射/幂等（dd/04 §1.3）
├── internal/query/         # /api/v1/flows/search SQL 构建器 + HTTP（dd/04 §2）
└── internal/export/        # 导出任务模型/状态机/执行器/格式化器（dd/04 §5、00 §7）
```

## 运行（本机空跑，无需 CH/Kafka/PG/Redis）

```bash
cd storage
go build ./... && go test ./...

# Inserter 空跑：注入四类契约消息 → 桩 Sink 打印落库日志 → 尾刷退出
go run ./cmd/lucid-inserter -demo

# Exporter 空跑：演示任务（text 格式打到 stdout）+ HTTP API 常驻
go run ./cmd/lucid-exporter -demo -demo-rows 6
curl -s -X POST :9152/api/v1/flows/search -d '{"time_start":1771901100,"time_end":1771902000,"filters":{"zone_id":101}}'
curl -s -X POST :9152/api/v1/export/jobs -d '{"type":"flows","time_start":1771901100,"time_end":1771904700}'
```

两个 cmd 均支持 SIGINT/SIGTERM 优雅退出（inserter 尾刷积压；exporter 排空 HTTP）。

## 实现状态

### 已实现 + 已单测

| 包 | 内容 | 测试 |
|---|---|---|
| inserter | `Batcher`（≥50,000 行或 2s flush，注入 Clock；dd/04 §1.3） | batcher_test：阈值/周期/尾刷/错误上抛 |
| inserter | `Router`（(day, FNV-1a64(exporter)) → shard，确定性） | router_test：确定性/散布/边界 |
| inserter | `MapFlowRecord/MapAggrMinuteRow/MapAttackMinuteRow/MapAttackEvent/MapAlarm/MapAlarmEnvelope`（16B IP→CH IPv6 语义注释在 sink.go/mapping.go） | mapping_test：逐字段+全部校验分支 |
| inserter | `Consumer` 接口 + ChannelConsumer（close 无 panic 竞态）、`Codec` 接口 + ProtoCodec 桩、`Deduper` + MemoryDeduper（FIFO 淘汰）/PGDeduper 桩、`Sink` + CHSink 桩/MemorySink、`Pipeline`（毒丸跳过、flush 失败不提交位点、shutdown 尾刷） | consumer/codec/dedup/sink/pipeline_test |
| query | SQL 构建器：字段/排序白名单、时间窗 ≤6h、≥1 ≤8 条件、分区裁剪、深分页 >50 强制游标、v4 前缀归一化 ::ffff:/120、游标元组谓词 | builder_test：SQL 字符串逐段断言 |
| query | `SearchHandler`（{code,msg,data} 信封，code 0/40000/50000） | http_test |
| export | text/csv/jsonl 格式化器（00 §7 逐字段：定宽、头部条件注释、v4 映射还原显示、TCP flags 符号串、sample 列） | format_test + testdata/golden/ 黄金比对（复刻 00 §7 示例两行） |
| export | 任务模型 + 状态机（queued→running→done/failed）、72h 窗、进度接口（Redis 桩）、游标续跑桩、执行器（重试 3、ctx 取消可续） | job/runner_test |
| export | 任务 API（POST /api/v1/export/jobs 202、GET /{id} 404/200） | http_test |
| ddl | migrations/ch/0000-0007（存储策略模板/flows_raw 双层 TTL+bloom+minmax/aggr_minute/aggr_hour+MV/attacks/attack_minutes/baseline/alarm_history/Distributed） | SQL 评审（CH 实例验收见 dd/04 §7） |

### 桩（TODO，标注 dd/04 章节）

| 桩 | 替换为 | 章节 |
|---|---|---|
| `inserter.ProtoCodec`（ErrCodecUnavailable） | proto+lz4 解码（gen/go + lz4） | dd/04 §1.3、09 §2 |
| `inserter.CHSink`（日志计数） | clickhouse-go/v2 native batch 直写分片本地表，insert_quorum=1 | dd/04 §1.2/§1.3 |
| `inserter.ChannelConsumer` | franz-go/segmentio 真实消费组（组名 shared.* 已登记） | dd/04 §1.3、09 §2 |
| `inserter.PGDeduper` | pgx → PG export_batches（DDL 属主 Master，09 §7） | dd/04 §1.3 |
| `query.SearchHandler` rows/total_estimate | clickhouse-go 执行 + uniqExact 截断 ">10M" | dd/04 §2.2 |
| `export.Runner` WriterFactory（单 writer→stdout） | NVMe 临时文件 + 分卷 2GB + MinIO 上传 exports/{job}/{part}.txt.gz | dd/04 §5.2 |
| `export.Runner` URL（对象键拼串） | MinIO 预签名 URL（24h 有效） | dd/04 §5.1、00 §6 |
| `export.MemoryStore/Progress/Cursor` | PG export_jobs / Redis db2（HINCRBY）/ 游标持久化 | dd/04 §5.2 |
| `export.SequenceSource` | CH 游标流式读取（(day, exporter) 切片、max_block_size=65536） | dd/04 §5.2 |
| exporter `-addr :9152` | 端口未登记 dd/08 §2.2 基线（9110-9160 metrics 段），待裁定 | dd/08 §2.2 |
| Prometheus 指标 | lucid_storage_insert_batch_bytes 等（命名 docs/11 §9） | dd/04 §1 |

## 契约问题清单（只报告，未改 docs；对应 09 §0 变更流程）

1. **aggr_minute 写入通道矛盾**：09 §8 裁定来源 topic `flows.aggr.minute`（MV 上卷），但 00 §4 尾注与 dd/04 §1.2 写"物化视图从 flows_raw 滚动（mv_aggr_minute）"。本实现按 09 执行（Inserter 直写 + 仅 mv_aggr_hour_aggr_minute 上卷），未建 mv_aggr_minute 避免双写。
2. **告警历史表无 DDL**：dd/04 §1.3 要求 alarms→"attacks 与告警历史"、09 §6 要求 Storage 提供 /api/v1/alarms，但 00 §4/09 §8 均未定义表与保留期。internal/ddl/0006_alarm_history.sql 为 Storage 侧提案（暂定 6 个月）。
3. **flows_raw 缺列**：FlowRecord 的 zone_side/src_geo/dst_geo/bgp_next_hop 在 00 §4 DDL 无对应列，明细落库即丢失（zone_side 是方向换算唯一依据，丢失影响取证）。
4. **tcp_flags/tos 截断**：proto uint32 位掩码（含 NS/ECE/CWR）vs DDL UInt8，>0xFF 按位截断（MapFlowRecord 有注释与测试）。
5. **深分页游标键 `_batch` 不存在**：dd/04 §2.2 游标按 (time_second, _batch)，但 00 §4 flows_raw 无 _batch 列；实现以表 ORDER BY 全键元组为游标（internal/query/cursor.go 注释）。
6. **路由哈希算法未指定**：dd/04 §1.3 只写 hash64(exporter) 未定算法；实现取 FNV-1a 64（stdlib 跨节点确定）。若要求与 CH cityHash64 对齐需先改契约。且 attacks.minutes/alarms 消息无 exporter（key=attack_id/zone_id），(day, exporter) 路由模型不覆盖，骨架以 attack_id/zone_id 为路由键。
7. **flows.raw 无 batch_id**：09 §2 幂等按 batch_id + export_batches，但 flows.raw 消息体 FlowRecord 无该字段——失败重放（≤24h Kafka 保留）会重复行，无去重通道；聚合/攻击批次不受影响。
8. **00 §7 flags 符号串未定义位序**：示例混用 ".A.S."（5 位）与 "SYN"（助记）；实现固化"单 bit→助记 / 组合→8 位点串 CEUAPRSF（高位→低位）"，以 testdata/golden 为基准。
9. **IPv4 展示两处歧义**：00 §1 说展示层按 ip_version 决定格式，00 §7 示例显示映射形 `::ffff:1.2.3.4`；实现按 §7 示例保留映射形（FormatIP 注释）。
10. **TTL 口径**：09 §8"热3+冷12"（共 15 天）与任务描述"3 天热+15 天冷"字面冲突；按 00 §4 DDL 权威实现（3 天迁冷、15 天删除）。
11. **export_jobs/export_batches DDL 属主**：09 §7 定为 Master（M2 待办 #2 迁仓库级 migrations/），Storage 侧只持接口；联调时需 Master 先建表。
12. **导出端口未登记**：exporter HTTP `-addr`（默认 :9152）不在 dd/08 §2.2 端口基线表内（该段为 metrics 预留），待登记。

## 备注

- 全部错误 `fmt.Errorf("...: %w", err)` 包裹；命名遵循 docs/11；测试表驱动。
- Windows/Git Bash + go1.27.3 验证：`go build ./...`、`go vet ./...`、`go test ./...` 全绿（-race 需 gcc，本机不可用）。
