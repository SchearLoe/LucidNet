# 03 · 流式分析 LucidAnalytics — 详细设计

> 语言 Go；二进制 `lucid-analytics`；输入 Kafka `flows.raw`（key=`zone_id+exporter`）

## 1. 消费与并行

- Consumer group `analytics`；并行单元 = Kafka 分区；每分区独立 `PartitionState`（本地聚合 + zone 检测窗口）。
- 并行度上限 96；客户（zone_id）在 key 首字段 → **同一客户全部流量固定在同一 goroutine**，检测状态无锁。
- 消费批量 5,000 条/批；`zone_id=0`（未命中客户）的记录只进全局聚合路径，不进 Zone 引擎。

## 2. 分钟聚合器（Aggregator）

### 2.1 聚合维度与度量
维度见 00 §4 `aggr_minute`；分组键哈希（xxhash64）→ 本地 map 累加 → 分钟翻转（:00+90s grace 收迟到的同分钟记录）→ 批量写 CH（经 Storage 的 inserter 接口）。

### 2.2 互联接口过滤（R4）
聚合入口统一执行：`internal_exclude=true`（默认，etcd 全局配置）→ 丢弃 `if_role` 位图中 in 或 out 任一侧为 internal 的记录；全局视图算子（如"全网总量"看板）订阅 `internal_exclude=false` 的旁路（成本 ×1.3，仅全局维度启用，zone 维度不需要）。

### 2.3 方向语义
客户视角：`in`=从 boundary 接口流入（out_if 命中客户绑定接口或 zone 命中 dst）→ 客户收到的流量；`out` 反之。实现：zone_id>0 且 dst 命中 → in；src 命中 → out；二者同区（区内互访）单独计 `intra`（默认不计入客户总量）。

## 3. Zone 秒级检测引擎（R2 核心）

### 3.1 窗口结构（每 zone 独立）

```
ZoneState（每客户一份，惰性创建）
├── ring60 [60]SecBucket           // 1s 粒度环形，覆盖 60s
│     SecBucket: bps,pps,flows,newflows,syn,synack,ack,rst,
│                 udp_pkts,tcp_pkts,icmp_pkts,frag_pkts,
│                 dst_ent(目的IP熵增量件),src_card(源基数HLL4)
├── ring5m [300]SecBucketLite      // 5m 轻量桶（仅bps/pps/newflows），供短基线
├── srcAgg map[uint64(srcIPhash)]SrcStats  // 每源: pkts,bytes,dstIPs(HLL4),ports(set16)
│     上限 50,000 源；超限 → 整体降级 Count-Min Sketch（CM16×65536），精度1%
├── sweep  map[Prefix24]SweepCell  // 扫段结构（R7），上限 4,096 段（LRU）
├── entropy 滑动分量              // 源/目的 IP 熵（增量计算）
└── fsm  AttackFSM 实例列表        // 每个活跃攻击类型一个状态机
```

### 3.2 容量预算（R2：300 客户起步，按 1,000 客户设计余量）

| 项 | 单 zone | 1,000 zone |
|---|---|---|
| ring60+ring5m | ≈40KB | 40MB |
| srcAgg（常态 2,000 源×80B，攻击上限 50,000） | ≈0.2–4MB | 0.2–4GB |
| sweep（4,096×2KB） | ≈8MB | 8GB → 攻击态惰性分配，常态 0 |
| 合计 | 常态 <0.3MB，攻击态 <12MB | 常态 <0.3GB，攻击态 <12GB（2×256G 节点可承受；300 客户时 <4GB，满足指标） |

### 3.3 每记录处理路径（追加式，≤1µs/条）
`bytes+=；packets+=；newflows += is_new(流表首包: 简化为 flows++ 与流ID去重近似——用 (src,dst,proto) 分钟级 LRU 8K 判定首包)；flag 计数；熵分量更新；srcAgg 追加；sweep 目的段 HLL 插入`。

## 4. 检测规则组（可配置 `detect_policies`，阈值均有默认+按 zone 覆盖）

### 4.1 泛洪类（R2）
| 类型 | 判定（在 3 个连续 1s 窗口上） |
|---|---|
| SYN Flood | `syn/(syn+synack) > 0.7` 且 `newflows > T_syn`（默认 5,000/s）且 bps ≥ 基线×3 |
| ACK/RST Flood | 对应 flag pkts > T_ack 且平均包长 < 200B |
| UDP Flood | udp_pkts > T_udp 且 dst 端口集中度 <0.3（弥散型）或命中固定端口 |
| ICMP/分片 Flood | icmp_pkts/frag_pkts > T 且超基线×5 |
| 反射放大（REFLECTION） | 目的端口 ∈{53,123,111,1900,11211,389,161,19,53-chargen} 且 源 IP 基数 >1,000 且 (疑似响应方向 bps / 该源历史请求 bps) > 8 |

阈值 T 默认为**绝对阈值 + 基线偏离**双条件（`abs AND ratio`），避免小客户被绝对阈值漏判、大客户被相对阈值误报。

### 4.2 扫段攻击（R7）
判定（10s 滑窗，每 zone 每 /24(v4)、/64(v6)）：
```
SWEEP 当 distinct_dst(HLL) ≥ max(32, /24内活跃IP基线×0.3)     // 段内大范围触达
      且 per_dst_avg_pkts < 3                                // 每目的微量（与泛洪区分）
      且 (目的IP熵↑ 或 源集中度<0.2)                          // 少源多点
输出: 段前缀、命中目的数、Top 源、触达速率（新目的IP/s）
```
- ICMP 扫段/半开 SYN 扫段自动归类（协议维度区分 TCP/UDP/ICMP SWEEP）。
- 慢扫（分钟级）：60s 桶复检一次，阈值减半，灵敏度标记 `slow=true`。
- v6 适配（R3）：/64 内按后缀 64bit HLL；跨 /64 扫段按 /48 聚合第二层判定。

### 4.3 客户总流量波动（R7）
- 双通道：① 秒级——zone bps 的 EWMA(α=0.1) 突变，`|x−ewma| > 8×MAD` 连续 3s → 波动候选；② 分钟级——基线引擎（§5）偏离 >99 分位持续 3 分钟 → 波动确认。
- 类型 `ANOMALY`（区分暴涨/骤降：骤降常为业务故障/路由切换，单独标注 `direction=drop`）。
- 抑制：维护中的 zone（Console 标记，etcd）静默；同 zone 5 分钟内不重复告警。

## 5. 基线引擎

- 键：`(zone_id, 维度组)` 与 `(全局维度键)`；粒度 minute-of-week（7×24×60 槽）。
- 概要：每键 t-digest（压缩 100 个质心）存 8 周滚动 + MAD。
- 学习期 7 天（冷启动期用绝对阈值兜底）；节假日/割接例外窗口（Console 维护表）。
- 存储：内存 + 每小时固化 CH `baseline` 表（重启恢复）；打分 `score=|x−median|/(3×MAD+ε)`。

## 6. 攻击状态机与分钟详情（R5）

### 6.1 FSM
```
CANDIDATE ─(规则连续命中 2/3 s)─► CONFIRMED ─(连续 120s 无命中)─► RECOVERED(保持展示60s后关闭)
     │                                    │
     └─(3s 未再命中)─► 关闭(不展示)        └─(处置回执R9到达)─► MITIGATING（速率下降<30%基线 → RESOLVED）
```
- 每攻击一个 `AttackEvent`（ULID）；同 zone 同类型 60s 内合并（取更重证据）。
- 证据快照（Redis, TTL 24h）：Top 源 100（IP/pps/bps）、端口分布、flag 比、熵曲线、基线对照曲线。

### 6.2 分钟详情（AttackMinute，R5）
- 攻击期间每分钟固化一行（00 §2.3）：bps/pps（in/out 双向）、new_flows、syn/udp 比、Top 源/端口；写 CH `attack_minutes`。
- 停止条件后补最后一行 `end` 标记；Console 攻击详情页按分钟表格+曲线展示，"导出原始日志"按钮携带 `(zone, 时间窗, Top源可选)` 跳转 Storage 导出任务（dd/04 §5，产出格式化文本）。

### 6.3 处置联动（R9）
- CONFIRMED 事件 → Kafka `alarms` → LucidBGP 消费进入"告警联动"页；
- LucidBGP 下发处置 → `bgp.mitigations` 事件（action/网段/时效）→ Detector 将关联 zone FSM 置 MITIGATING，并持续评估（bps 降到基线×1.3 以下且维持 60s → 事件 RESOLVED，回写 `mitigation_effect` 评分，供处置模板优化）。

## 7. TopN / 实时接口
- 滚动 1m/5m Top-K（大小 1,000 的堆 + 桶衰减）；写 Redis（`topn:{dim}:{ts}`，TTL 10m）供 Console 实时页轮询。

## 8. 输出与容错
- 延迟数据（Kafka 回放）：>5m 的记录只进聚合不进检测（防历史重放误告警）。
- 节点故障：分区重平衡后 ZoneState 冷启动（损失 ≤60s 检测记忆，聚合窗口 grace 90s 内不受影响）；状态不做跨节点复制（可接受，写入成本论证见 §9）。
- 幂等：CH 聚合用 ReplacingMergeTree 语义 + 幂等批次号。

## 9. 性能验证清单（M2 验收）
1. 100w fps 灌注（含 30% v6）：检测路径 P99 <100ms；聚合延迟 <90s。
2. 300 客户 × 1,000 IP 模拟 + 10 客户并发攻击（SYN/UDP/扫段/反射各类型）：全部 ≤5s 首告警，误报 <5%（演练靶场）。
3. 单客户 100Gbps 打满：srcAgg 降级路径正确（CM 精度抽检）。
4. kill -9 单分析节点：分区再平衡 <30s，期间聚合缺口 <2 分钟（重建+grace 补偿）。
