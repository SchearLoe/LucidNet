# LucidCollector（采集解析）— Walking Skeleton

模块路径 `github.com/SchearLoe/lucidnet/collector`；设计文档 docs/hld/02、docs/dd/02；
接口语义唯一权威 docs/09-模块间接口契约.md（§2 Kafka / §3 FlowRecord 字段 / §4 gRPC / §5 etcd）。

## 运行方式

```bash
cd collector
go build ./...
go test ./...          # 全部单测 + e2e 冒烟

# 本地开发（console 输出 + zone/RIB 快照文件）：
go run ./cmd/lucid-collector \
  -listen :2055 \
  -out console \
  -zones-file zones.json \
  -zone-match dst \
  -rib-file rib.json

# 文件留档（JSON 行，flows.raw 开发替身）：
go run ./cmd/lucid-collector -out file -out-file flows.jsonl -zones-file zones.json

# sFlow 端口（与 NetFlow v5 版本号冲突，按端口分流，见 internal/decoder 注释）：
go run ./cmd/lucid-collector -listen :2055 -sflow-listen :6343
```

flags（骨架本地配置；生产为 etcd watch，dd/02 §6；环境变量约定 `LUCID_COLLECTOR_*`，docs/11 §8）：

| flag | 缺省 | 说明 |
|---|---|---|
| `-listen` | `:2055` | NetFlow v5/v9/IPFIX UDP（hld/02 §4；node 配置可覆盖） |
| `-sflow-listen` | 禁用 | sFlow UDP（生产 `:6343`；node 配置可覆盖） |
| `-node` | 主机名 | 节点 ID（`/lucid/config/collector/{node}` 键尾） |
| `-out` | `console` | `console` / `file` / `kafka`（kafka=franz-go 桩，Produce 返回 not implemented） |
| `-out-file` | `flows.jsonl` | `out=file` 输出文件（JSON 行追加） |
| `-kafka-brokers` | — | `out=kafka` 时必填 |
| `-zones-file` | — | `/lucid/zones` **值快照（信封 JSON）**，etcd watch 开发替身 |
| `-node-config-file` | — | `/lucid/config/collector/{node}` 值快照（信封 JSON），开发替身 |
| `-zone-match` | `dst` | `dst` / `src`（docs/09 §3，**禁止 both**；node 配置可覆盖） |
| `-rib-file` | — | RIB 快照 JSON（RibNameLookup 开发替身；缺省 gRPC 桩） |
| `-snmp` | 关 | 启动 SNMP 轮询调度器（gosnmp 桩，无设备空转，仅演示组装位） |

### etcd 值信封（docs/09 §5 2026-10-25 裁定）

`/lucid/zones`、`/lucid/forward/rules`、`/lucid/config/analytics`、`/lucid/config/collector/{node}`
四个配置键的值统一为信封（`/lucid/assign/flow` 与 `/lucid/leader` 不适用）：

```json
{"version": 3, "updated_at": "2026-10-25T08:00:00Z", "data": <业务负载 JSON>}
```

collector 侧消费规则（`internal/etcdcfg`）：

- 配置入口**先解信封再取 `data`**，裸 payload（无信封字段）一律报错——与 Master 写侧约定一致；
- `version` ≤ 已应用版本（乱序回放/同版本重发）→ 忽略本次更新并日志/计数（`Guard.StaleTotal`，防乱序回放）；
  守卫为两阶段（`ShouldApply` 判定 + 应用成功后 `MarkApplied`），坏负载不吞同版本重发；
- `updated_at` 仅记录（日志字段），不参与应用判定；
- 文件快照（`-zones-file` / `-node-config-file`）即 etcd 值原文替身，走同一入口。

zones.json（信封）与 node-config.json（信封）示例：

```json
{"version": 3, "updated_at": "2026-10-25T08:00:00Z",
 "data": [{"id":7,"name":"cust-a","tenant":"t1","ips":[{"prefix":"203.0.113.0/24"}],"policy_id":1}]}
```
```json
{"version": 2, "updated_at": "2026-10-25T08:00:01Z",
 "data": {"listen": ":2055", "zone_match": "dst",
          "sample_registry": {"10.0.0.1": 1000},
          "naming_rules": [{"pattern": "(?i)(to-|-agg-)", "role": "internal"}],
          "rib_snapshot_ptr": "rib@20261025"}}
```

rib.json（RIB 快照，**非 etcd 键**，RibNameLookup gRPC 的开发替身，不走信封）：

```json
[{"prefix":"203.0.113.0/24","asn":64512,"peer_as":64500}]
```

优雅退出：SIGINT/SIGTERM → 关 UDP socket → 等处理协程落地 → producer Flush（10s 超时）→ Close → 终态计数日志。

## 包结构

```
cmd/lucid-collector/    main.go 组装（dispatcher → decoder → enrich → producer；signal 优雅退出；信封配置入口）
internal/decoder/       NetFlow v5 完整实现；v9/IPFIX/sFlow goflow2 fork 桩；模板缓存 + WAL
internal/zone/          双栈 Zone 匹配器（R2 关键路径：单 IP 哈希 + v4/v6 radix LPM + COW 热更新）
internal/enrich/        富化流水线编排（ASN→Geo→App→Zone→IfRole）+ RIB 客户端
internal/etcdcfg/       etcd 配置值信封解码（09 §5 裁定）+ 版本守卫（防乱序回放）
internal/nodecfg/       /lucid/config/collector/{node} 负载镜像（端口/采样登记表/命名正则/RIB 指针）
internal/producer/      flows.raw 生产接口（franz-go 桩 + console/file 开发实现）
internal/snmp/          轮询调度器 + gosnmp 桩 + 接口角色识别引擎（dd/02 §5.2 优先级表）
```

## 已实现 / TODO（对照 dd/02 章节）

### 已实现（含单测）

| 能力 | 位置 | dd/02 |
|---|---|---|
| NetFlow v5 完整解码（头 + 记录全字段映射；unix_secs/sysuptime 换算含 32bit uptime 回绕修正；v4→`::ffff:` 16B 映射；ip_version=4 恒定，v5 无 v6） | `internal/decoder/netflow_v5.go` | §1/§2 |
| 模板缓存接口 + 内存实现（key=(exporter, obsDomain, templateId) 观测域隔离；v9 无超时 / IPFIX 24h 惰性过期） | `internal/decoder/template.go` | §1 定制点 #1/#5 |
| 双栈 Zone 匹配：单 IP 哈希 + v4/v6 两棵路径压缩 radix LPM；`zone_match=dst\|src`（默认 dst，禁止 both）；同前缀多 zone 取小 id；copy-on-write 原子换树热更新；随机压测 vs 暴力参照 40 轮 | `internal/zone/` | §3.3 |
| 富化流水线编排（顺序 ASN→Geo→App→Zone→IfRole，预算注释 ≤2µs/条）；zone_id/zone_side 单写；if_role 位图（bit0/bit1，unknown 按 boundary）；互联过滤语义引用 `shared.InternalFilterDrop`（仅 in 与 out 均 internal 丢弃） | `internal/enrich/pipeline.go` | §3/§3.4 |
| RibNameLookup 客户端：接口 + gRPC 桩（:9131）+ 本地快照文件开发实现（LPM；线性扫，生产换 radix） | `internal/enrich/rib.go` | §3.1 |
| Geo/App 开发桩（mmdb mmap 与 PG 静态表接入位） | `internal/enrich/geo.go` `app.go` | §3.2 |
| 接口角色快照（COW 原子换表） | `internal/enrich/ifrole.go` | §3.4 |
| flows.raw 生产接口：key=`shared.FlowKey(zone_id, exporter)`；参数 linger 50ms / batch 64KB / lz4 / acks=leader / 背压 100MB（常量即契约）；console/file JSON 行开发实现 | `internal/producer/` | §4 |
| SNMP 轮询调度器（per-device 到期表 + 40 worker 限并发；计数器 30s / 健康 60s / 光功率 300s；错误计错不外抛；审计流 CountersSink 接口） | `internal/snmp/scheduler.go` | §5.1 |
| 接口角色识别引擎：manual > 环回/管理口 > LLDP∈纳管清单 > IGP 邻接 > 命名规则（dd/02 预置正则）> 默认 boundary+unknown；role_source + evidence_json | `internal/snmp/role.go` | §5.2 |
| **etcd 配置值信封消费（09 §5 2026-10-25 裁定）**：严格解信封（裸 payload 报错，payload 解析全部在解包之后）；两阶段版本守卫（≤已应用版本忽略 + stale 计数；应用成功才记账）；updated_at 仅记录 | `internal/etcdcfg/` | 09 §5 |
| **per-node 配置**：`/lucid/config/collector/{node}` 负载镜像（端口/采样登记表/命名正则/RIB 快照指针）；zone_match 与监听地址 etcd 值覆盖本地 flag，即时生效 | `internal/nodecfg/` + `cmd/lucid-collector/main.go` applyNodeConfig | 09 §5 |
| main 组装：版本分流 dispatcher、双端口（NetFlow/sFlow）、信封配置入口（zones/node-config）、JSON 单行日志、周期计数、优雅退出；e2e 冒烟测试（UDP v5 → 信封配置富化 → file 输出断言） | `cmd/lucid-collector/` | — |

### TODO（桩/未接通，标注落点）

| 事项 | 位置 | dd/02 |
|---|---|---|
| v9/IPFIX/sFlow 解码（fork GoFlow2）：flowset 遍历、IE 展开、IPv6（IE 27/28）、采样归一（IE 305/306 + sFlow probability） | `internal/decoder/goflow2.go`（5 个定制点落点索引见文件头注释） | §1 |
| 华为 NetStream 私有 IE 映射表（enterprise 2011；`flow_unknown_ie{exporter}` 计数 + TLV 透传 evidence） | `internal/decoder/huawei.go` | §1 定制点 #2 |
| 模板丢失防护：60s 无模板数据报环形缓冲（1GB/30s）+ 回放 + `flow_template_missing{exporter}` 告警 | `internal/decoder/goflow2.go` replayBuffer | §1 |
| 模板 WAL 真实实现：本地 WAL fsync → Kafka `flow.templates`（compact，key=exporter+obsDomain）→ 启动重放 | `internal/decoder/wal_kafka.go` | §1 定制点 #1 |
| franz-go 生产者（kgo 客户端、proto+lz4 序列化、背压丢最旧批次计数） | `internal/producer/producer.go` | §4 |
| gosnmp 轮询器（v2c/v3、ifHC* walk、健康/光功率 OID）+ PG devices 设备清单接入 | `internal/snmp/poller.go` | §5.1 |
| 角色识别数据面：ifTable/LLDP/OSPF walk（6h 周期）→ RoleEvidence 填充；识别结果写 PG `interfaces(role, role_source, evidence_json)`；etcd 快照推送 | `internal/snmp/role.go` | §5.2 |
| ifIndex 对账校验（防漂移：flow 速率 vs SNMP 速率皮尔逊相关 <0.5 告警 → manual_if_map） | `internal/snmp/role.go` TODO(role-pipeline) | §5.2 |
| etcd watch 循环（/lucid/zones、/lucid/config/collector/{node} 增量推送到 applyZonesSnapshot/applyNodeConfig；/lucid/assign/flow 非信封另行消费）——信封解码与版本守卫已就位，差 watch 接线 | `cmd/lucid-collector/main.go`（文件快照为开发替身） | §6 / 09 §5 |
| node 配置字段接线：采样登记表 → v5 per-exporter 采样覆盖；命名正则表 → snmp.RuleEngine；RIB 快照指针 → RIB Feeder 拉取；监听地址变更热重载（重建 socket） | `internal/nodecfg/` 注释 + `cmd/lucid-collector/main.go` | §1 #3 / §5.2 / §3.1 |
| Prometheus 指标（lucid_collector_*，40+ 项）与结构化 JSON logger（含 `config_stale_total` 打点） | `cmd/lucid-collector/main.go`（原子计数 + JSON 行日志为骨架替身） | §6 |
| RIB 真实路径：gRPC RibNameLookup（Lookup/GetSnapshot/WatchSnapshot）+ 本地 radix 缓存 + `enrich_rib_stale` 降级告警 | `internal/enrich/rib.go` | §3.1 |
| GeoIP mmdb / PG 应用映射表 / PG interfaces 快照真实数据源 | `internal/enrich/` | §3.2/§3.4 |
| SO_REUSEPORT 多 socket 并行解码（单节点 30w flows/s） | `cmd/lucid-collector/main.go` | §1/§6 |

## 约束遵循说明

- docs/11：包名无黑名单词；文件 snake_case；错误 `%w` 包裹；typed enum（`zone.MatchField`、`enrich.IfRole`、`decoder.TemplateEventKind` 等）；指标/日志命名按 §9 注释标注。
- 跨模块依赖仅经 `shared/`（FlowRecord/Topic/FlowKey/ZoneSide/IfRole/EtcdKey* 常量）、09 契约接口（RibNameLookup 桩）与 Master 写侧信封线格式（`internal/etcdcfg` 消费侧镜像）。
- 全部代码可移植（无 Linux 专有调用，无需 `//go:build linux` 隔离）。
