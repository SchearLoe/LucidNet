# 06 · BGP 路由管理 LucidBGP — 详细设计

> 基础：私有仓库 `SchearLoe/rsbgp-console`（分支 `gobgpd-v4.10.0`）。本设计 = 改名 + 集成改造 + 新增组件（RIB Feeder、Flowspec 路线），**不推翻既有实现**。

## 1. 仓库与命名策略

- **独立仓库**（建议）：`rsbgp-console` fork 改名为 `lucidbgp`。理由：其"分支=适配的 gobgpd 版本"模型（README 分支模型节）与 LucidNet 主仓的发版节奏冲突，独立演进、按版本发布 jar 更安全。LucidNet 主仓以发布物（jar 镜像）+ 版本清单引用。
- 改名清单（一次性，独立 commit）：

| 项 | 原 | 新 |
|---|---|---|
| 仓库名 | rsbgp-console | lucidbgp |
| Maven artifactId / jar | rsbgp-console-4.0.0.jar | lucidbgp-1.0.0-lucidnet.jar |
| Java 包 | com.gobgp.web | com.lucidnet.bgp |
| Spring 应用名/端口 | rsbgp-console / 18080 | lucidbgp / 18081 |
| 前端标题/登录品牌 | RSBGP Console | LucidNet · 路由与处置 |
| 健康检查/指标前缀 | rsbgp.* | lucidbgp.*（Prometheus 抓取路径新增 `/actuator/prometheus`） |
| proto 副本目录 | backend/src/main/proto/api（gobgpd v4.10.0） | 不动（分支模型保留） |

## 2. 集成改造（Spring Boot 侧）

### 2.1 认证与租户
- 新增 `LucidAuthFilter`（servlet filter，order 最高）：校验网关注入的 `X-Lucid-JWT`（网关已验签，透传 claims：user/tenant/roles）；无网关直连模式（运维旁路）用 Basic + 白名单 IP。
- iframe SSO（dd/05 §5）：`POST /api/bgp/sso {one_time_token}` → LucidBGP 校验（Master 签发 HMAC，5min）→ 颁发会话 cookie。
- 数据模型追加：`alarms`、`mitigations` 表加 `tenant, zone_id` 列；REST 输出按 JWT 租户过滤。

### 2.2 告警双入口
```
入口A（保留）：POST /api/alarms          ← 外部系统/Console"一键处置"直调
入口B（新增）：Kafka consumer @alarms topic ← Analytics AttackEvent 自动进入
              （spring-kafka；只消费 category=attack & severity>=2）
幂等：alarm_id 唯一键；处置后状态回写（处置中/已处置）经入口A/B 同一服务层。
```

### 2.3 处置回执（新增生产者）
处置动作（下发/到期撤销/手动撤销/失败）→ 组装 `MitigationEvent` → Kafka `bgp.mitigations`；同时镜像 PG `mitigations`（Master 建表，LucidBGP 直写只读账号之外的独立 schema，或经 Master API——**选直写独立 schema**，减少运行时耦合，DDL 由 Master 迁移管理）。

### 2.4 处置能力扩展路线
- 现状（保留）：向全局 RIB 注入 RFC7999 BLACKHOLE community 路由；长期/限时（15s 调度器自动撤销）；模板保存复用。
- **M3：Flowspec**（gobgpd 支持 Flowspec NLRI）：处置表单增加"精细模式"——匹配 dst 前缀 + 端口/协议/包长 + 动作（traffic-rate 限速到 X bps / discard / redirect-next-hop 到清洗中心）。复用既有 PathBuilder 增设 `FlowspecBuilder`（api.Path 的 FlowspecNLRI 构造）；撤销走既有 DeletePath。验收含路由器侧 flowspec 路由生效与限速效果（分析侧速率曲线对照）。

## 3. gobgpd 部署与高可用

- 部署：2 实例（主备），与 Analytics 同节点（Linux bare-metal systemd；gobgpd ≈ 空载时 <100MB）。
- 会话：与出口/核心路由器建 iBGP（或 RR 客户端），处置路由经 BGP 通告；BMP 会话由「Integrations」页配置指向路由器 BMP server（rsbgp-console 已有 List/Add/DeleteBmp）→ RIB Feeder 消费。
- 主备：gobgpd-A 活跃（邻居 established），B 冷备；切换脚本经 LucidMaster 编排（stop A → start B → 邻居重建）；处置路由表（LucidBGP 记录）在新实例重放注入（`lucidbgp resync` 子命令，扫描 PG mitigations 生效记录重新 AddPath）。
- GR（Graceful Restart）开启，主备切换期间路由器侧无撤销抖动。

## 4. RIB Feeder（新增 Go 服务，`lucid-rib-feeder`）

```
gobgpd(gRPC :50051) ── WatchEvent(best-path) ──► Feeder
                                                ├─ 双栈 radix RIB（v4/v6，全表 ≤150w 前缀，内存 ≤3GB）
                                                │   └─ gRPC 服务 RibNameLookup（:9131）：
                                                │       Lookup(ip)→{asn,prefix,peer_as,ts}
                                                │       GetSnapshot() / WatchSnapshot()   ← Collector 缓存快照源
                                                ├─ 快照接口 GetSnapshot()（每日+变更推 Collector）
                                                └─ 增量 → Kafka bgp.updates（路由-流量关联分析用，M2+）
```
- 快照格式：自定义 wire（前缀表 + 版本号）；Collector 拉取周期 60s+watch 通知。
- 撤销处理：withdraw 即时删 radix 节点（O(前缀长)）；Lookup 一致性 SLA：更新传播 ≤1s。

## 5. 攻击→处置→验证闭环（R2/R9 联动）

```
Analytics Detector CONFIRMED
  → Kafka alarms
    → LucidBGP 告警联动页（列表置顶）
      → 运维点选（仅 Established 连接可下发）→ 表单预填（zone/攻击网段/Top源可选）
        → AddPath BLACKHOLE(或M3 Flowspec)
          → bgp.mitigations 事件
            → Analytics FSM→MITIGATING；速率回落评估
              → RESOLVED + mitigation_effect 评分（回写 alarms topic）
                → LucidBGP 记录页显示效果标签（有效/部分/无效）
```
自动处置（默认关闭）：`auto_policy` 按 zone+攻击类型配置（如 SYN_FLOOD>10Gbps 自动下发限时 30min 黑洞）；必须有全局熔断（单日自动处置 ≤20 次，超限转人工）。

## 6. 与既有功能的边界（不改动清单）

连接管理（全参数/方向控制/179 探测）、状态监控（5s 刷新/失败原因/前缀计数/收发记录 SSE/flops）、Rib 查询（GLOBAL/LOCAL/ADJ_IN/ADJ_OUT/VRF + exact/longer/shorter）、Policy 全套、RPKI、TCP-AO、MRT/Zebra、Settings——除包名/品牌/端口外零改动。

## 7. 继承的 gobgpd 工作副本限制（rsbgp-console README 实测结论，适配时不许"优化掉"）

1. 策略骨架（web-direction-export/import、web-mitig-st）**首次需要时一次性挂载**，此后仅做定义集成员级增删——并发处置的隔离粒度受限（选中任一处置连接的对端会收到全部活跃处置路由），已知限制写入产品手册。
2. 同一语句内"community AND 邻居集合"双 ANY 条件不生效——继续依赖 blocked 邻居集合方案。
3. 定义集运行时更新必须成员级增删（Add/DeleteDefinedSet 成员列表），禁用 replace=true。
4. WatchEvent 表监听按需开启（有 SSE 订阅者才开，空闲断开）。

## 8. 测试与验收

1. 改名回归：REST 全量（rsbgp-console 既有 API-INVENTORY.md 60 RPC 映射逐一冒烟）、SSE、处置全流程不回归。
2. 集成：Console iframe SSO；Kafka 告警进入联动页；处置回执 Analytics FSM 状态流转；租户隔离（A 租户看不到 B 的告警/处置）。
3. 主备：kill gobgpd-A → B 提升 → `lucidbgp resync` 重放 → 路由器侧黑洞路由仍生效（<5min RTO）；GR 期间无路由抖动。
4. Flowspec（M3）：路由器收到 flowspec 且限速生效，Analytics 曲线回落验证。
5. RIB Feeder：全表 100w 前缀注入，快照下发 <30s；Lookup P99 <1µs；withdraw 传播 <1s。
