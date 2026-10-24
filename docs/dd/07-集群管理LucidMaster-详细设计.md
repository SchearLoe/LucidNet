# 07 · 集群管理 LucidMaster — 详细设计

> 语言 Go；`lucid-master`；依赖 etcd 3.5 / PostgreSQL 16

## 1. gRPC/REST 接口

```protobuf
service Master {
  rpc RegisterNode(NodeInfo) returns (Ack);            // 启动注册，返回分配的角色配置
  rpc Heartbeat(stream NodeStat) returns (stream Cmd); // 双向：指标上行 / 命令下行(重载配置/排水)
  rpc PublishConfig(ConfigScope) returns (Version);    // 内部（Console 触发的变更入口）
  rpc WatchAssign(stream AssignType) returns (stream AssignTable);
}
```
REST（Console 用，经网关）：`/api/v1/admin/{nodes|devices|zones|policies|forward_rules|users|roles|tenants|audit|versions}`，全部走 PG + etcd 双写（PG 权威 → 事务后发 etcd 增量，失败补偿重试队列）。

## 2. 节点模型

```sql
CREATE TABLE nodes(
  id TEXT PRIMARY KEY, role TEXT,      -- broker|collector|analytics|storage|master|bgp
  host TEXT, cores INT, mem_gb INT, nics JSONB,
  state TEXT DEFAULT 'online',         -- online|draining|maintenance|offline
  version TEXT, joined_at TIMESTAMPTZ, last_hb TIMESTAMPTZ);
```
- 排水（draining）：Console 一键 → 分配表摘除该 collector → 迁移完成（Kafka lag 归零）→ 允许维护；升级流程强制先排水。
- 容量权重：`weight = cores/24 * nic_speed/25G`；分配表计算输入。

## 3. 分配算法（exporter→collector）

```
输入: exporters[](活跃, 含速率观测值), collectors[](在线, weight)
哈希环: 每物理节点 vnode = 160 * weight
分配: hash(exporter_ip) → 环上顺时针 → collector
约束: 单 collector 承载 ≤ 其 weight 份额 × 1.2；超载 exporter（>5w fps）独占绑定
输出: AssignTable{version, map[exporter]collector} → etcd /lucid/assign/flow
触发: 节点上下线/权重变化/新 exporter 发现/手工 pin；防抖 30s 合并一次变更
```
迁移过程：双写期（新旧 collector 同 exporter 由 FLB 逐流切换，模板随首包重建；v9 模板 60s 内未到则 Broker 复制到新节点触发学习）→ 稳定 120s 后旧节点释放。

## 4. RBAC 与多租户

```sql
tenants(id, name)
users(id, tenant_id, name, passwd_hash, is_platform_admin)
roles(id, tenant_id, name, perms JSONB)   -- 权限点: zone:read zone:edit flow:query flow:export
                                          -- attack:read attack:handle report:* bgp:* admin:*
user_roles(user_id, role_id)
```
- 平台管理员（租户隔离豁免）/租户管理员/安全操作员/只读观察者四类预置角色。
- JWT：HS256（Master 与网关共享密钥，LucidBGP 用公钥验签——RS256 密钥对，私钥仅 Master 持有），claims：`{uid, tenant, roles, exp}`。
- 资源隔离：zone/device/report 按 tenant_id 列过滤（网关注入），LucidBGP/Storage 按租户 claim 过滤（dd/06 §2.1、dd/04 §2）。

## 5. 配置版本与发布

- 变更流：Console API → Master 校验（schema+业务规则：zone IP 重叠 R2 校验、转发规则 passthrough×resample 拒绝 R1）→ PG 事务 → etcd 发布（version++）→ 节点 ACK（Heartbeat 通道）→ 全 ACK 标 active；180s 未全 ACK：回告警，保留旧版本运行（已 ACK 节点继续新版本，差异窗口记录）。
- 回滚：`POST /versions/{n}/rollback`（etcd 历史版本 + PG 配置快照双恢复）。

## 6. 升级编排（滚动）

顺序：FLB/Broker → Collector（排水轮换）→ Analytics（分区重平衡稳定后下一台）→ CH（副本轮换，`system.replicas` 追平）→ Master/Console/gobgpd（主备切换 dd/06 §3）。
- 版本兼容矩阵（PG `upgrade_matrix`）：跨版本配置 schema 迁移脚本随发布物；大版本不跳级。

## 7. 故障场景与演练清单（M2 验收）

| 场景 | 预期 |
|---|---|
| kill -9 单 Collector | 90s 内 exporter 迁移完成；期间仅该节点 UDP 丢（秒级数据） |
| FLB 节点宕机 | exporter 侧 UDP 重传语义（无）→ 数据丢失窗口 = 探测+切换 ≤3s（dd/01 §2.3） |
| Analytics 单节点宕机 | Kafka 分区重平衡 <30s；聚合缺口 <2 分钟（dd/03 §8） |
| CH 单节点宕机 | 副本接管，写入零中断（dd/04 §7.4） |
| Master 宕机 | 数据面零影响；配置变更只读；备 15s 接管（etcd 选主） |
| etcd 多数派丢失 | 集群只读保护（拒绝配置变更），数据面继续运行 |

## 8. 自监控大盘（Grafana，随产品内置）

1. 采集链路：每 collector flows/s、UDP 溢出、模板缺失、Kafka lag；
2. 分析链路：检测延迟 P99、攻击引擎内存、误报率（人工标注回流）；
3. 存储：CH parts 数/合并延迟/磁盘水位/TTL 迁移速率；
4. 处置链路：LucidBGP 邻居状态、处置下发成功率、回执闭环率（dd/06 §5）；
5. 业务 SLI：攻击首告警延迟、攻击详情页可用性、导出任务成功率。
