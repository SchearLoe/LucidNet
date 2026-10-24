# 01 · 汇聚分流 LucidBroker — 详细设计

> 需求：R1（原始数据流按源 IP/分组多目的转发，转发支持再采样）；语言 Go；单二进制 `lucid-broker`

## 1. 进程结构

```
lucid-broker
├── ingest        N×UDP listener（SO_REUSEPORT，每 CPU 一进程模型：RSS+AFFINITY）
├── flb           exporter→collector 分发（一致性哈希）
├── forwarder     R1 规则引擎（透传复制 + 代理重编码）
├── admin         Master gRPC 注册/心跳 + etcd watch（assign 哈希表 / forward 规则）；版本化热更新
└── metrics       Prometheus exporter
```

收包路径：`ingest → flb → collector`（必经）；Forwarder 规则命中时在 flb 前复制一份给 forwarder，未配置规则时零额外开销（规则哈希表空表 O(1) 判断）。

## 2. FLB（流负载均衡）

1. **分配表**：`map[exporterIP]collectorAddr`，由 Master 计算并经 etcd watch 推送（含单调 revision）；Broker 本地全量缓存，切换原子替换（RWMutex 读写锁或 atomic.Pointer）。
2. **一致性哈希**：Master 侧实现（dd/07 §4），虚拟节点 160/物理节点；Broker 只执行查表，保持无状态。
3. **探活**：Broker 对 collector 做 1s 间隔 UDP/ICMP 探测（3 次失败标记 down 并本地摘除，同时上报 Master），Master 是分配权威，Broker 本地摘除仅作快速兜底，避免脑裂（60s 内 Master 未纠正则恢复信 Master）。
4. **未知 exporter**（表未覆盖新设备）：按源 IP 哈希落到任意 collector，同时打点 `flb_unknown_exporter` 告警，等待 Master 分配。
5. **缓冲**：`SO_RCVBUF ≥ 64MB`；溢出计数（`ErrQInDropped`）每 exporter 维度暴露，联动告警"采集侧丢包"。

## 3. Forwarder 规则模型（R1）

> 语义确认：**"按源 IP"指流报文的发送方（exporter/设备源 IP）**，分组=exporter 集合；如需按"流记录内部源 IP"分发，本设计在代理模式下提供可选内容过滤条件（§3.2 规则 4）。

### 3.1 规则结构（存 PostgreSQL，Master 下发 etcd 快照）

```yaml
forward_rules:
- id: 42
  name: "核心路由器→省清洗中心+集团分析"
  match:                       # 匹配条件（AND）
    exporters: ["10.1.1.1", "10.1.1.2"]     # 源IP列表
    exporter_groups: ["core-routers"]       # 或分组（组=exporter集合，PG维护）
  destinations:
  - { addr: "172.16.0.10:9995", protocol: passthrough }   # 透传：零改动复制
  - { addr: "172.16.0.11:9995", protocol: netflow5,
      resample: { mode: deterministic, rate: 10 } }        # 代理：1:10 再采样
  - { addr: "172.16.0.12:4739",  protocol: ipfix,
      resample: { mode: random, rate: 5 } }
  enabled: true
```

### 3.2 规则语义

1. 匹配顺序：规则按 `priority` 升序，命中即复制（**一条原始报文可同时喂多个规则**——满足"多目的"）。
2. `exporters` 与 `exporter_groups` 取并集；单规则 exporter 数量上限 10,000（分组展开后）。
3. 每目的地独立 `resample`；**passthrough 不支持 resample**（无法在原始报文内安全抽稀），配置校验阶段直接拒绝。
4. 代理模式可选内容过滤 `flow_filter`（proto/src_prefix/dst_prefix/ports），不匹配记录被丢弃后再编码——满足"按流内源 IP 分流"的扩展场景。
5. 规则变更热生效（≤2s），长连接（代理模式 template 会话）平滑切换：新规则用新 session id，旧会话 flush 后关闭。

### 3.3 分组管理

`exporter_groups`：命名集合，CRUD 经 Console → Master → etcd；组变更触发规则重算（展开缓存：`map[exporter]→[ruleIDs]`）。

## 4. 再采样与重编码（代理模式）

### 4.1 采样算法

| 模式 | 算法 | 用途 |
|---|---|---|
| `deterministic` | `hash(flowkey 5元组+proto) % rate == 0` 保留 | 可复现，同一流在多次转发中判定一致，下游聚合无偏 |
| `random` | 每条记录 `rand() < 1/rate` 保留 | 实现最简，短流方差大 |

- `effective_sample_rate = exporter_sample_rate × resample_rate`，写入输出报文的采样字段。
- hash：FNV-1a 64bit（快、够散）；流键含 src/dst/port/proto（不含时间，保证同流同判）。

### 4.2 输出编码

| protocol | 编码 | 采样率写回 |
|---|---|---|
| `netflow5` | v5 头（SYSUPTIME/UNIX_SECS/SEQUENCE 按目的地独立维护）+ ≤30 记录/包 | v5 头无采样字段 → 采样率由"目的地登记表"线下同步（限制已在文档标注）；推荐下游用 IPFIX |
| `ipfix` | 自有 Template（固定 field specifier 集，Observation Domain=规则目的地id，Template ID=256 起每会话独立）+ Data Set | 写标准 IE：`samplingPacketInterval(305)/samplingPacketAlgorithm(304)` |
| `passthrough` | 原报文逐字节复制 | 不支持再采样 |

### 4.3 会话管理（IPFIX）

- 每目的地一个 `session`：独立序列号、模板重发定时器（600s 或按需）、UDP `send buffer 4MB`、令牌桶限速（默认 1Gbps，防打爆下游）。
- 目的地不可达：缓存最近 5s 报文（环形 512MB），恢复后重放；连续 down >60s 则丢弃并告警 `forward_dest_down`。

## 5. 可靠性与运维

- 规则持久化：PG（权威）+ etcd（分发）；Broker 只读缓存，重启 30s 内恢复（etcd snapshot + version 对齐）。
- 自监控指标（节选）：`flb_pps / flb_drop_total / forward_records{rule,dest} / forward_resample_ratio{dest} / forward_dest_down / forward_replay_lag`。
- 审计：规则变更经 Master 审计日志（who/when/diff）。

## 6. 性能账

| 路径 | 单节点（2×12C）估算 | 依据 |
|---|---|---|
| FLB 转发 | 150–200w pps | 纯 UDP 转发 + 一次 map 查表，~700ns/包 |
| Forwarder 透传复制×1 目的地 | 额外 100w pps | sendmmsg 批量发送 |
| Forwarder 代理重编码 | 30–50w records/s | 解码 v9/IPFIX ≈1µs/条 + 重编码 ≈1µs/条 + 内存分配 |

100w fps 场景：Forwarder 规则若匹配全量，代理模式需评估独立部署（占用 2 采集节点级别的资源）——写入容量规划注意项。

## 7. 测试要点

1. R1 验收用例：1 规则×2 目的地（透传+1:10 再采样），比对目的地收包：透传=原样、代理=记录数≈1/10 且采样率字段正确。
2. FLB 节点 kill -9：分配表切换 <3s，期间仅丢 UDP 秒级数据。
3. 目的地断连重放：5s 缓冲无丢失；60s 后正确丢弃并告警。
4. 规则热更新：连接中的会话平滑，序列号不回退。
