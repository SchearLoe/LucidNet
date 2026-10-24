# LucidAnalytics（流式分析）—— walking skeleton

模块 `github.com/SchearLoe/lucidnet/analytics`｜二进制 `lucid-analytics`｜设计文档：`docs/dd/03-流式分析LucidAnalytics-详细设计.md`、`docs/hld/03`｜接口契约：`docs/09-模块间接口契约.md`（唯一权威）。

## 结构

```
cmd/lucid-analytics/     组装入口：Source → Pipeline(单消费者) → Detector+Aggregator+FSM → alarms
internal/consume/        流源抽象：JSONL 回放（开发）+ Kafka 消费组桩（franz-go, TODO）+ Pipeline
internal/aggregate/      分钟聚合器（完整实现）：维度键 xxhash64、:00+90s grace、过期丢弃、AggrMinuteBatch
internal/detector/       Zone 秒级检测引擎（R2/R7）：ring60/ring5m、SYN Flood、SWEEP(HLL)、ANOMALY(EWMA+MAD)、srcAgg+CMS 桩
internal/detector/…      依赖子包 internal/hll（紧凑 HyperLogLog，2^14 寄存器 4bit 打包）
internal/fsm/            攻击状态机（dd/03 §6.1 全转移路径）+ ULID
internal/alarm/          alarms 发布接口：内存 channel 开发实现 + Kafka 桩；AttackEvent→AlarmEnvelope
internal/rtkeys/         Redis 实时键契约（09 §6 rt:* 前缀）：TopN/证据键构造+TTL、Store 接口+内存桩
```

## 运行

```bash
export PATH="/c/Users/11277/go-sdk/go/bin:$PATH"
cd analytics && go build ./... && go test ./...

# 演示（生成 30s 合成流量并按时钟节流回放：SYN Flood + /24 扫段 + 平稳对照）
go run ./cmd/lucid-analytics -mode=demo

# 开发：回放自定义 JSONL（每行一条 FlowRecord JSON，按时间戳节流）
go run ./cmd/lucid-analytics -mode=dev -jsonl=path/to/flows.jsonl

# Kafka 模式（桩：消费与生产均未实现，返回 not implemented）
go run ./cmd/lucid-analytics -mode=kafka -brokers=10.0.0.1:9092 -group=analytics.detect
```

环境变量（flag 同名优先）：`LUCID_ANALYTICS_MODE` / `LUCID_ANALYTICS_JSONL` / `LUCID_ANALYTICS_KAFKA_BROKERS` / `LUCID_ANALYTICS_GROUP`（docs/11 §8）。

## 并发模型（结构保证，非锁）

检测/聚合/FSM 状态全部只被 `consume.Pipeline` 主循环 goroutine 访问（dd/03 §1：
同客户全部记录固定同一 goroutine）。源 goroutine 仅向通道投递记录；秒级 tick 与记录
在同一 select 循环串行分派。本机无 gcc（-race 不可用），以结构 + 计数一致性测试覆盖
（`consume.TestPipelineConcurrentProducers`）。

## 实现范围与取舍

| 项 | 状态 | 说明 |
|---|---|---|
| 分钟聚合（dd/03 §2） | 完整+单测 | 维度=(exporter,device,in_if,out_if,dir,zone,src_as,dst_as,proto,dst_port,app)；`InternalFilterDrop` 互联过滤（09 §3 裁定：in/out 均 internal 才丢）；方向仅由 `shared.DirectionFromZoneSide` 推导；90s grace/过期丢弃；注入时钟确定性单测 |
| ring60/ring5m（dd/03 §3.1） | 完整+单测 | SecBucket 全字段清单；dst_ent/src_card 以每秒 HLL(p=8) 基数近似熵增量件 |
| SYN Flood（dd/03 §4.1） | 完整+单测 | ratio>0.7 ∧ newflows>T(5000/s) ∧ bps≥基线×3，3 连续 1s 窗 2/3 命中；无基线时比率条件退化为绝对阈值（§5 冷启动兜底）；表驱动覆盖 命中/不命中/抖动不确认 |
| SWEEP 扫段（dd/03 §4.2） | 完整+单测 | per-/24(v4)、/64(v6) × 协议；自实现 HLL 2^14 寄存器（4bit 打包 8KB，任务口径；dd 预算表 2KB/段按 2^12，待契约对齐）；distinct_dst≥max(32,基线×0.3[桩 32]) ∧ per_dst_avg<3 ∧ 源集中度(distinct_src/distinct_dst)<0.2；两连续窗确认；窗口翻转快照修复评估滞后丢窗；LRU 4,096 cell |
| ANOMALY 波动（dd/03 §4.3） | 完整+单测 | EWMA(α=0.1)+滑窗 60s MAD，\|x−ewma\|>8×max(MAD, 0.1×ewma) 连续 3s（全平窗口 MAD 下限防整数噪声，自定口径）；暴涨/骤降 direction 标注；同 zone 5 分钟抑制；方向翻转重置连击（单秒尖峰后 EWMA 回落不续接为骤降）；分钟级确认通道（②）桩 TODO |
| FSM（dd/03 §6.1/§6.3） | 完整+单测 | CANDIDATE→CONFIRMED→RECOVERED→CLOSED、3s 静默关闭、120s 恢复、60s 展示、60s 合并窗沿用 ULID、MITIGATING（bgp.mitigations applied/withdrawn/failed）、基线×1.3 持续 60s→RESOLVED、反弹重置计时；RECOVERED/RESOLVED 与 shared.AttackStatus 映射差异已在 state.go 注明 |
| srcAgg + CMS 桩（dd/03 §3.1） | 实现降级路径+桩 | 每源 pkts/bytes/dstIPs(HLL p=6)/ports(set16)；上限 50,000，超限走 `CountMinSketch` 接口桩（TODO M2 CM16×65536） |
| alarms 发布（09 §2） | 接口+内存实现+Kafka 桩 | topic=shared.TopicAlarms；severity/category 映射；AttackEvent 信封 |
| Redis 实时键（09 §6 2026-10-25 裁定） | 键契约+桩 | 统一 `rt:*` 前缀（dd/03 §7 旧文 `topn:{dim}:{ts}` 作废）：`rt:topn:{dim}:{ts}`（TTL 10m）、`rt:evidence:{attack_id}`（TTL 24h）集中定义于 `internal/rtkeys`，键名只经该包构造；`Store` 接口+DevStore 内存桩，`alarm.AttackEmitter` 已将 evidence_json 落 `rt:evidence:{attack_id}` |
| flows.raw 消费（dd/03 §1） | 接口+JSONL 回放+Kafka 桩 | 组名白名单校验（analytics.detect / analytics.aggregate，09 §2） |

## TODO（M2，标注 dd/03 章节）

1. Kafka 接入：franz-go 消费（§1：分区并行 ≤96、每分区 PartitionState、批 5,000）与 alarms/aggr/attack-minutes 生产（09 §2：proto+lz4、linger=50ms）。
2. 规则组补全：ACK/RST、UDP 弥散/固定端口、ICMP/分片、反射放大 REFLECTION（§4.1）；扫段慢扫 60s 复检（阈值减半 slow=true，§4.2）与 v6 跨 /64 第二层 /48 聚合（§4.2 v6 适配）。
3. 基线引擎（§5）：minute-of-week t-digest+MAD、7 天学习、每小时固化 CH baseline、Learning 期绝对阈值兜底接线（`detector.BaselineProvider`）。
4. TopN（§7）：滚动 1m/5m Top-K 堆+桶衰减，经 `rtkeys.Store.SetTopN` 写 `rt:topn:{dim}:{ts}`（TTL 10m；09 §6 裁定键名，旧写法 `topn:{dim}:{ts}` 作废）。
5. AttackMinute 分钟详情固化（§6.2）：攻击期间每分钟一行+end 标记，`alarm.Publisher.PublishAttackMinutes` 已留接口。
6. 证据快照（§6.1）：evidence_json 已落 `rt:evidence:{attack_id}`（TTL 24h，09 §6）；M2 换真实 Redis 实现并补全快照内容（Top 源 100/端口分布/熵曲线/基线对照曲线）；MITIGATING 效果评分 mitigation_effect（§6.3）。
7. etcd 配置 watch（09 §5：/lucid/config/analytics 信封解包：internal_exclude、阈值覆盖、维护静默）+ Leader 选举（§4 部署）。
8. Prometheus 指标（docs/11 §9：lucid_analytics_*）与 trace 贯穿（x-lucid-trace-id）。
9. 性能验收（§9：100w fps、P99<100ms、kill -9 再平衡）。

## 已发现的契约问题（只报告，不改 docs）

1. **FlowRecord 无分片信息**（proto 2.1）：ICMP/分片 Flood 规则（dd/03 §4.1）无法判定 frag_pkts，SecBucket.FragPkts 恒 0。
2. **TCP flag 位常量未进 shared**：detector 内自定义（IP 标准位序 SYN=0x02 等），建议 shared 增加镜像常量。
3. **AttackStatus 枚举缺 RECOVERED/RESOLVED 区分**（00 §2.3 / dd/03 §6.1）：RECOVERED 映射为 AttackConfirmed 展示、RESOLVED 映射 AttackMitigated；dd 图中两态语义在跨模块枚举中不可区分。
4. **sweep cell 内存口径冲突**：任务指令 2^14 寄存器=8KB/cell（×4,096=32MB/zone）vs dd/03 §3.2 预算表 2KB/段（≈2^12）；当前按任务指令实现。
5. **dd/03 §4.2 "源集中度<0.2" 无定义**：实现取 distinct_src/distinct_dst<0.2（少源多点），需设计裁定。
6. **ANOMALY 分钟级确认通道（§4.3 ②）依赖基线引擎**，骨架仅秒级通道（①）。
7. **rt:* 键常量建议镜像进 shared**：Redis 实时键是跨模块契约（09 §6：Analytics 写、网关轮询/Console 读），与 topic/etcd 键同类；现集中在本模块 `internal/rtkeys`（本任务无权改 shared），建议按 09 §5 shared 镜像先例登记后迁移。
