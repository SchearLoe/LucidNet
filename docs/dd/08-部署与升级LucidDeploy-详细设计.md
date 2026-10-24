# 08 · 部署与升级 LucidDeploy — 详细设计

> 组件语言：lucid-agent / lucidctl / Deploy Engine 为 Go；交付目标 OS：Linux x86_64（内核 ≥5.10；DPDK 节点 ≥5.15）

## 1. 制品与版本规范

### 1.1 版本号
`vMAJOR.MINOR.PATCH[-rcN]`（SemVer）：MAJOR=不兼容变更/大重构，MINOR=新功能（配置 schema 可演进，只增不删），PATCH=缺陷修复。兼容矩阵存 PG `upgrade_matrix`（随包发布 manifest 声明 `upgrade_from`），规则：相邻 MINOR 直升；跨大版本必须经中转版本；rc 版禁止生产升级目标。

### 1.2 离线制品包（唯一交付物）

```
lucidnet-v1.0.0-linux-amd64.tar.gz
├── manifest.yaml              # 见 1.3
├── bin/                       # 全部自研组件
│   ├── lucid-agent  lucid-broker  lucid-collector  lucid-analytics
│   ├── lucid-master lucid-gateway lucid-rib-feeder lucid-exporter
│   ├── lucid-reporter  lucidctl
│   └── thirdparty/{clickhouse,kafka,etcd,postgres,vm,valkey,minio,gobgpd}/…
├── jars/lucidbgp-1.0.0-lucidnet.jar
├── web/console-dist.tar.gz    # 前端静态资源
├── migrations/                # PG schema + CH DDL + etcd 初始数据（按版本增量）
├── scripts/                   # agent 可执行白名单脚本（见 §3.3）
└── README-RELEASE.md
```

### 1.3 manifest.yaml（节选）

```yaml
version: v1.0.0
build: { commit: "...", date: "2026-11-01T00:00:00Z" }
compat: { upgrade_from: ["v0.9.*"] }          # 兼容矩阵
files: [ { path: bin/lucid-broker, sha256: "..." } ]   # 全文件清单
infra:                                        # bundled 模式的中间件版本
  clickhouse: 24.8.5.5   kafka: 3.8.0   etcd: 3.5.16
  postgresql: "16.4"  valkey: 8.0.0  victoriametrics: 1.102  minio: RELEASE.2026-01
external_mode:                               # external 模式时校验现场版本
  clickhouse: ["24.3+", "24.8+", "25.x"]
  kafka: ["3.6+"]
```

## 2. 节点环境基线（安装规范）

### 2.1 目录与 systemd

```
/opt/lucidnet/
├── releases/<version>/          # 每版本完整目录（bin/etc/web/…）
├── current -> releases/v1.0.0   # 原子软链（升级/回滚 = 切软链 + restart）
└── agent/                       # agent 自身（独立目录，不随业务升级）
/var/lib/lucidnet/<comp>/        # 数据（collector 模板 WAL、exporter spill…）
/var/log/lucidnet/<comp>/        # 日志（logrotate 策略随包）
/etc/lucidnet/agent.yml          # agent 唯一本地配置（Master 地址+token）
systemd: lucid-agent.service（随系统起）；
        lucid-<comp>.service 由 agent 按角色生成/托管
```

### 2.2 端口基线（全集群统一规划，安装时预检占用）

| 端口 | 用途 | 端口 | 用途 |
|---|---|---|---|
| 9100 | lucid-agent gRPC | 9000/8123/9009 | ClickHouse native/HTTP/interserver |
| 2055/9995/9996/6343 | Broker/Collector UDP 业务口 | 9092 | Kafka |
| 9131 | RIB Feeder gRPC（RibNameLookup） | 2379/2380 | etcd |
| 9110–9160 | 各组件 metrics（步进 10，9131 除外） | 8429 | vmagent（预留） |
| 9140/9141 | Master gRPC/HTTP | 5432 | PostgreSQL |
| 80/443 | 网关/Console | 8428 | VictoriaMetrics |
| 18081 | LucidBGP（本机） | 9300/9301 | MinIO API/Console（避开 CH 9000） |
| 50051 | gobgpd gRPC（本机） | | |

### 2.3 系统基线预检项（S0）
时钟同步（chrony，偏差 <100ms）、`vm.max_map_count≥262144`、`net.core.rmem_max≥67108864`、文件句柄 ≥100w、SWAP 关闭、时间区、磁盘挂载点与容量（storage 节点 NVMe/HDD 按 topology 指定设备名核对）、端口占用、防火墙放行清单、（DPDK 节点：IOMMU/大页，M3+）。

## 3. lucid-agent（节点执行单元）

### 3.1 通道与安全
- 与 Master gRPC 双向流（注册复用 Master.Heartbeat，dd/07 §1）；mTLS（集群 CA 由 S2 生成，agent bootstrap 时注入）。
- bootstrap：`lucidctl bootstrap --master https://10.1.0.41:9141 --token <一次性令牌>`（token 由 Console/首次安装生成，单节点单次有效，10min 过期）；agent 上线即换发节点证书。
- agent 自升级：从制品仓库拉新版本到 `/opt/lucidnet/agent/releases/`，自重启（systemd watchdog 保证 30s 内回来）。

### 3.2 命令模型
```
Command { id, node, playbook, step, params, timeout, dry_run }
Result   { id, code, stdout_tail, metrics, duration }
```
幂等：每 step 有稳定 ID 与前置条件断言（如"目录存在才执行解压"），重试/续跑安全；超时默认 600s（可覆盖）；并发：每节点串行执行（保证状态可推理）。

### 3.3 可执行白名单（安全边界）
agent 只执行包内 `scripts/` 与内置原子操作（下载/校验/解压/软链切换/systemd 操作/目录清理/健康探测），**不提供任意 shell**；playbook 步骤引用脚本名+参数（JSON），脚本本身随制品签名分发。所有命令执行入审计（dd/07 §1 审计表）。

## 4. 一键安装流水线（lucidctl install / Console 安装向导）

### 4.1 拓扑文件 topology.yml（页面表单等价生成）

```yaml
cluster_name: lucid-prod
mode: bundled                    # bundled | external（external 需登记现场中间件地址与版本）
offline_pkg: /data/lucidnet-v1.0.0-linux-amd64.tar.gz
ntp: 10.0.0.1
nodes:
- { host: 10.1.0.11, roles: [broker, collector], auth: {user: root, password_ref: keyring} }
- { host: 10.1.0.12, roles: [broker, collector] }
- { host: 10.1.0.21, roles: [analytics, kafka, etcd, gobgpd] }
- { host: 10.1.0.31, roles: [storage], disks: { hot: nvme0n1, cold: sdb-sdi } }
- { host: 10.1.0.41, roles: [master, gateway, pg, valkey, vm, minio, kafka] }
settings:
  clickhouse: { shards: 3, replicas: 2 }
  kafka: { rf: 3 }
  timezone: Asia/Shanghai
```

### 4.2 阶段流水线（每阶段含步骤/前置断言/验收门禁；状态持久化 PG `deploy_jobs`，断点续跑）

| 阶段 | 内容 | 门禁（全绿才进下一阶段） |
|---|---|---|
| S0 预检 | §2.3 全项 + 制品校验 + 拓扑合法性（角色组合/端口/盘位） | 0 失败项；警告可豁免（记录） |
| S1 基础设施 | etcd 集群 → PG → Valkey → Kafka → ClickHouse → VM → MinIO（bundled 安装或 external 登记探活） | etcd 健康、PG 可连、Kafka 0 队列、CH 各节点 system.replicas 正常 |
| S2 控制面 | Master（选主）→ 网关/Console → 各节点 agent bootstrap + 证书 | 全部节点 agent online；Console 可登录 |
| S3 数据面 | Broker+Collector → Analytics + RIB Feeder + gobgpd/LucidBGP → inserter/exporter/reporter | 各组件 /healthz、指标可见、LucidBGP 连上 gobgpd |
| S4 数据初始化 | migrations：PG schema、CH DDL 与物化视图、Kafka topic 创建、etcd 初始配置、默认 admin 账号（首次登录强制改密） | CH 表存在、topic 列表一致 |
| S5 验收 | 健康清单 + 注入测试流（lucidctl 自带发送器模拟 3 台 exporter 5k fps ×10min） | 端到端：flows_raw 有行、分钟聚合出现、自监控大盘无红项 |

### 4.3 失败处置
单节点失败：流水线暂停 → 修复后 `install --resume --only-node <host>` 或页面"重试该节点"；阶段失败：保留已完成状态，幂等续跑。全程产物：`deploy_jobs` + 每节点执行日志（页面可查）。

## 5. 升级流水线（lucidctl upgrade / Console 升级向导）

### 5.1 主流程

```
① 上传/放置新版本包 → manifest 校验（SHA256 全清单 + 签名）
② 兼容矩阵校验（upgrade_from 匹配；external 模式中间件版本核对）
③ 预检：磁盘水位（所有节点 <80%）、CH 无异常副本/合并积压、Kafka 消费 lag 正常、
   全节点 agent online、无进行中的配置变更
④ 自动备份（升级保护点，保留最近 3 份）：
   PG 全量 dump；etcd snapshot；CH schema freeze（DDL 导出）；
   当前版本清单（软链位置+配置版本）；Kafka topic 配置
⑤ Canary：每角色选 1 台低权重节点先升（顺序见 5.2），观察 15min 门禁
⑥ 滚动全量：逐台「排水 → 停服务 → 切软链 → 起新版本 → 健康检查 → 门禁 → 恢复流量」
⑦ schema 迁移：新版本 migrations 在 Master 升级后统一执行（只增不删，见 5.4）
⑧ 完成：更新集群版本号，出升级报告（各节点耗时/门禁快照/异常清单）
```

### 5.2 滚动顺序与各角色要点

| 序 | 角色 | 要点 |
|---|---|---|
| 1 | 网关/Console | 双实例轮换（若有）；静态资源与后端同包 |
| 2 | Master | 备先升→选主切换→升另一台（单台则维护窗口内直升，数据面不受控面影响） |
| 3 | RIB Feeder | 升级期间 Collector 用旧 RIB 快照（dd/02 §3.1 降级策略） |
| 4 | Broker+Collector | **逐台排水**（Master 分配表迁移，dd/07 §3 迁移协议），流量迁完才停服；模板随首包重建 |
| 5 | Analytics | 逐台：分区再平衡稳定（lag 归零）后下一台；升级期间检测窗口由存活节点承担 |
| 6 | Storage（CH inserter/exporter 轮换 + CH 本体小版本滚动，见 §6） | 副本追平才下一台 |
| 7 | gobgpd/LucidBGP | 主备切换 + resync 重放处置路由（dd/06 §3），处置零中断是验收项 |
| 8 | 基础设施件 | 默认**不动**（独立通道，见 §6） |

### 5.3 门禁指标（每节点升级后 5–15min 观察窗）

| 指标 | 阈值 |
|---|---|
| 组件 /healthz 与日志 ERROR | 全绿 / 零新增 |
| UDP 丢包速率（flb/collector） | 与升级前基线持平 |
| Kafka 消费 lag | 回落到升级前 ±10% |
| CH system.replicas absolute_delay | = 0 |
| 检测引擎心跳 + 攻击事件流 | 正常（演练注入 1 条测试攻击应被检出） |
| LucidBGP 邻居 established 数 | 与升级前一致 |

任一门禁失败 → **自动回滚该节点**（切回旧软链 + 旧配置版本，≤3min）→ 流水线暂停等待人工决策（页面可：重试 / 跳过该节点 / 全量回滚）。Canary 阶段失败 → 直接终止，零影响。

### 5.4 Schema 与数据兼容（回滚可行性的根基）
- PG/CH/etcd 迁移脚本规则：**只新增**（表/列/键/索引），**不删除、不改类型不改语义**；废弃项标 `deprecated`，保留 ≥2 个 MINOR 版本后由专门的清理任务删（页面确认后执行）。
- FlowRecord 等 proto 演进规则同 00 §2（字段只增不改）。
- 因此任意时刻二进制回滚后与新 schema 兼容（旧代码忽略新列）。

### 5.5 回滚
`lucidctl rollback [--to v1.0.0]`（默认上一版本）：逐节点切软链+旧配置版本+重启（不重迁数据）；etcd 配置经 Master 版本回滚（dd/07 §5）；Kafka/CH 不回滚（兼容性由 §5.4 保证）。

## 6. 基础设施组件升级策略（独立通道，默认关闭随包升级）

| 组件 | 策略 |
|---|---|
| etcd | 小版本滚动（逐台替换二进制重启，quorum 保持）；大版本需离线迁移工具，走专项维护窗口 |
| Kafka | 滚动按 broker；跨版本需先确认消息格式兼容（本产品消息全 protobuf 版本化，风险低）；**先升全部 broker 再升客户端** |
| ClickHouse | 滚动逐副本；规则：升前 `system.replicas` 追平、禁止跳过不兼容版本（manifest external 声明）；新版本观察 24h 再升下一台生产集群 |
| PostgreSQL | 主从轮换（先升从→切换→升原主）；大版本走 pg_dump/restore 离线迁移 |
| Valkey/VM/MinIO | 滚动重启即可（无状态或单机） |

基础设施升级一律在业务低峰窗口（页面预约），且与产品版本升级**不得同日**（故障归因隔离）。

## 7. Console 部署中心（页面）

| 页面 | 内容 |
|---|---|
| 部署总览 | 集群版本、各节点卡片（角色/版本/agent 状态/排水开关）、最近部署任务列表 |
| 安装向导 | 表单生成 topology → 执行 S0–S5 可视化（阶段进度、每节点步骤状态、日志抽屉）→ 失败节点重试 |
| 升级向导 | 上传包 → 预检报告（红绿灯）→ 备份进度 → Canary/滚动分步执行，支持「暂停/继续/回滚」按钮与门禁指标实时小图 |
| 版本管理 | 制品仓库列表（版本/时间/签名状态）、兼容矩阵、历史升级报告 |
| 审计 | 全部部署/升级操作记录（who/when/what/result），含 CLI 与页面 |

权限：部署操作独立权限点 `deploy:install / deploy:upgrade / deploy:rollback`（dd/07 §4 权限清单补充），默认仅平台管理员持有；升级需二次确认（输入集群名）。

## 8. lucidctl 命令清单（主控节点）

```
lucidctl bootstrap   --master <url> --token <t>          # 节点侧一次性注册 agent
lucidctl install     -f topology.yml [--offline-pkg p] [--resume] [--only-node h]
lucidctl precheck    [-f topology.yml | --cluster]        # 安装前/升级前预检
lucidctl upgrade     --to v1.1.0 [--canary-only] [--pause-after <role>]
lucidctl rollback    [--to v1.0.0] [--node h]
lucidctl status / doctor                                 # 集群版本与健康总览 / 深度诊断
lucidctl upload-pkg  <tar.gz>                            # 上传制品到仓库（校验+登记）
```

## 9. 验收用例

1. 全新 10 节点 bundled 安装 ≤2h；S3 人为断网一台 → 续跑恢复完成。
2. 断点续跑：S1 中途 kill lucidctl → `--resume` 从断点继续，无重复安装副作用。
3. PATCH 滚动升级：注入门禁失败（人为停 CH 副本）→ 该节点自动回滚 + 流水线暂停；恢复后重试成功；全程数据面损失仅该采集节点排水窗口。
4. MINOR 升级含新增列迁移：升后功能正常，随后整体回滚到旧版本仍正常运行（验证 §5.4）。
5. gobgpd/LucidBGP 升级：处置路由全程未撤销（抓包验证 BGP 无 withdraw 风暴）。
6. 页面操作与 CLI 等价性：安装/升级/回滚各走一遍页面路径，产物一致。
