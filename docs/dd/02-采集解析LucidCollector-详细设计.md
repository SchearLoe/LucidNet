# 02 · 采集解析 LucidCollector — 详细设计

> 语言 Go；二进制 `lucid-collector`；单节点目标 30w flows/s（富化后入 Kafka）

## 1. 解码层（fork GoFlow2 定制清单）

| # | 定制点 | 说明 |
|---|---|---|
| 1 | 模板缓存持久化 | 原 GoFlow2 模板在内存，重启丢失 → 模板变化时追加写 Kafka `flow.templates`（compact log）+ 本地 WAL；启动重放（模板有效期 v9 默认无超时，IPFIX 模板活跃期可配，默认 24h 重验证） |
| 2 | 华为 NetStream 私有 IE | v9 选项模板中的 `bytesOut32/destinationInterfaceIndex` 等标准 IE 已覆盖；对华为私有 IE（field type ≥ 233 的常见项：`ingressVRFID/physicalInIfIndex` 等）做映射表 `vendor/huawei.go`，未识别 IE 计数 `flow_unknown_ie{exporter}` 并保留原始 TLV 透传到 `evidence` |
| 3 | 采样字段归一 | v5：头无采样（依赖 exporter 配置登记表）；v9：OPTIONSCOPE_SAMPLER + IE 305/306；sFlow sampleProbability；统一折算 `sample_rate` |
| 4 | IPv6（R3） | v9/IPFIX 的 IPv6 field（27/28）、v6 option exporter；sFlow v6 报文头解析 |
| 5 | 观测域 | 缓存 key = (exporter IP, observationDomainId)，模板/采样状态均按此隔离 |

**模板丢失防护**：60s 内收到 data record 但无对应模板 → 缓冲最近 30s 报文（环形 1GB），模板到达后回放；持续缺失则丢弃 + 告警 `flow_template_missing{exporter}`（严重级）。

## 2. 归一化

- 产出 `FlowRecord`（见 00 §2.1）。字段映射表（节选，完整表放 `docs/mapping.md`）：

| FlowRecord | v5 | v9/IPFIX IE | sFlow |
|---|---|---|---|
| time_start_ms | unix_secs+sysuptime 差 | FIRST_SWITCHED(152) | flowStart |
| in_if/out_if | INPUT/OUTPUT_SNMP | 10/14 | input/output ifIndex |
| src_as/dst_as | SRC_AS/DST_AS | 16/17 | srcAS/dstAS |
| tcp_flags | TCP_FLAGS(6) | 6 | TCP flags |
| sample_rate | 登记表 | 305/306+option | probability 折算 |

- 方向语义：NetStream 有 input/output 两个 ifIndex，FlowRecord 保留原始对 `(in_if,out_if)`；"方向"换算在 Analytics 做（00 §8）。

## 3. 富化流水线（顺序执行，总预算 ≤2µs/条）

### 3.1 ASN/前缀（RIB Feeder）
- gRPC `Lookup(ip) → {asn, prefix, peer_as}`；**本地缓存**：全量 RIB 快照（每日/变更推送，IPv4+IPv6 合计 ≤150 万前缀，radix 内存 ≤3GB）+ 增量订阅；查询本地 radix ≈200ns，gRPC 仅在缓存未命中/回填时使用。
- RIB Feeder 不可用：降级用旧快照（打点 `enrich_rib_stale`），超 10min 告警。

### 3.2 Geo / 应用
- GeoIP：mmdb 全内存 mmap（v4/v6 单库），≈100ns。
- 应用映射：`{proto,port}→app_id` 静态表（PG 下发，1 万条），LRU 数组直查。

### 3.3 Zone 匹配（R2，关键路径）
- 数据结构：**两级**——单 IP（掩码全长）哈希表 `map[hash128]zone_id`；前缀按族分 radix 树（v4/v6 各一棵）。
- 300 客户×1000 条：哈希/radix 合计内存 <10MB，查询 ≤0.5µs；命中即写 `zone_id`，未命中 0。
- 一条 IP 同属多 zone：配置校验禁止重叠（Master 保存时校验，冲突返回错误）；强制场景允许 `zone_priority`，取小 id。
- 变更生效：etcd watch → 原子换树（copy-on-write 指针替换），≤2s。
- 匹配面全局可配 `zone_match=dst|src`（默认 dst：客户=被监测方，攻击场景看目的侧；src 模式用于以"源客户"为监测对象）。命中写 `zone_id` + `zone_side`（1=dst 命中 2=src 命中），**一条记录只标一个客户域**——方向推导的唯一依据，见 09 契约 §3。

### 3.4 接口角色打标（R4）
- 本地缓存 PG `interfaces` 快照（device_id+ifIndex → role），写 `if_role` 位图（bit0 in 边界 / bit1 out 边界）。
- unknown 角色按 boundary 处理（宁可多算，由 UI 标"待确认"），分析侧可全局开关。

## 4. Kafka 生产

- `franz-go`；`key = zone_id(4B big-endian) + exporter`；`linger 50ms / batch 64KB / lz4 / acks=leader`（分析层幂等，不需要 all）。
- 背压：producer 队列 >100MB 时丢弃最旧批次并计数 `flow_backpressure_drop`（UDP 语义端到端保持，宁可丢旧不阻塞解码）。

## 5. SNMP 采集与接口角色识别（R4）

### 5.1 轮询
- `gosnmp` v3（v2c/v3 认证）；调度：per-device worker，接口计数器（ifHCInOctets/ifHCOutOctets/ifHCInUcastPkts/ifHCOutUcastPkts/ifInErrors/ifOutDiscards）30s 周期（可按设备调 60s）；设备健康（CPU/内存/温度）60s；光功率 300s。
- 写 VictoriaMetrics `lucid_if{device,ifindex}`；同时生产 `snmp.ifcounters` 审计流。
- 2,000 设备预算：40 并发 worker，单轮 30s 内完成（SNMP P50 8ms/OID walk 批）。

### 5.2 接口角色识别算法（R4）

输入（walk 周期 6h，变更触发即时重算）：
- ifTable/ifXTable：ifDescr、ifAlias、ifType、ifSpeed、ifOperStatus
- IP-MIB ipAddrTable：接口 ↔ IP（L3 判据之一）
- LLDP-MIB：lldpRemSysName + lldpRemPortId（邻居发现）
- OSPF-MIB ospfIfTable / ISIS-MIB（IGP 邻接）

判定优先级（首中即定，`role_source` 记录依据）：

| 优先级 | 规则 | 判定 |
|---|---|---|
| 1 | PG 人工标记 `manual` | 按标记（运维在 Console 修正） |
| 2 | LLDP 邻居 sysName ∈ 纳管设备清单 | `internal`（互联） |
| 3 | OSPF/ISIS 邻接存在 | `internal` |
| 4 | ifDescr/ifAlias 命中命名规则（PG 正则表，预置：`(?i)(to-|Z_|ge.*core|-agg-|LAG)` → internal；`(?i)(cust|client|eth-trunk.*c[0-9]+)` → boundary） | 对应角色 |
| 5 | 默认 | `boundary` + `unknown` 标记（UI 黄色提示人工确认） |

- 环回/管理口（ifType=softwareLoopback / ifDescr 含 Mgmt）→ `internal`（不参与业务计量）。
- 输出写 PG `interfaces(role, role_source, evidence_json)`；快照推送 Collector/Analytics（etcd）。
- **对账校验**（防 ifIndex 漂移）：每日对每设备取 Top 流量 ifIndex 的 flow 聚合速率 vs SNMP 同 ifIndex 速率，皮尔逊相关 <0.5 或接口名比对失败 → 告警 `ifindex_mismatch{device}` 转人工映射表 `manual_if_map`。

### 5.3 分析联动（R4 的"分析时去除互联"）
- Analytics 消费 FlowRecord 时按 `if_role` 位图过滤：`internal_exclude=true`（默认）时丢弃 **in 与 out 均为 internal** 的记录——纯互联链路流量在互联两端设备各导出一次、双计；而 boundary↔internal 是客户↔骨干的正常路径，**保留**（语义裁定见 09 契约 §9-④）。开关全局+按报表级可覆盖（个别"全网总量"视图需含互联时使用）。

## 6. 自监控与运维

- 指标：`flow_decode{exporter} / flow_enrich_zone_hit_ratio / snmp_poll_lag{device} / kafka_producer_queue` 等 40+ 项。
- 配置：全部 etcd（含 per-exporter 采样登记表、命名正则表）；本地无配置文件（除 bind 地址）。
- 部署：裸机 systemd（GOMAXPROCS=24, GOMEMLIMIT=100GiB）；非 DPDK 场景可容器化。

## 7. 测试要点

1. 双栈回放：v4/v6 混合 pcap（NetStream v9 华为/思科 + sFlow v5 + IPFIX）→ FlowRecord 字段逐一断言（R3）。
2. Zone 热更：运行中增删客户 IP，2s 生效，旧流不回溯。
3. 模板丢失回放：缓冲-回放正确性；告警触发。
4. 角色识别：LLDP/命名/默认四类样例 + 人工覆盖优先；对账告警注入。
5. 性能：50w fps 灌注 30 分钟，P99 处理延迟 <50ms、零 backpressure drop。
