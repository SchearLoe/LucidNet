# 05 · 展示与报表 LucidConsole — 详细设计

## 1. 前端工程

- 目录：`frontend/`（monorepo，pnpm workspace：`web`（主控台）、`shared`（类型/proto 生成）、`charts`（矩阵热力等封装组件））。
- proto 类型：`buf generate` 从 `proto/lucidnet/v1` 生成 TS 类型，与后端契约同源。
- 权限：路由级（页面白名单）+ 控件级（`<Auth code="zone:edit">`）；JWT 刷新 15min 滑动。

## 2. 明细查询页（R6）

```
┌ 过滤区 ────────────────────────────────────────────┐
│ 时间范围[15m▾ ≤6h]  源IP/前缀  目的IP/前缀  端口  协议 │
│ 客户域[▾] 设备[▾] 接口[▾] IP版本[全部|v4|v6▾](R3)    │
│                          [查询] [导出(异步任务)]      │
├ 结果表（虚拟滚动，默认 1,000 行，列可配）──────────────┤
│ start│src│sport│dst│dport│proto│pkts│bytes│flags│if_in/out│sample│
│ 行点击 → 流上下文面板（同五元组±端口 5 分钟窗二次查询）│
└─────────────────────────────────────────────────────┘
```
- 交互约束与 dd/04 §2.1 一致：时间窗 >6h 时"查询"按钮变为"创建导出任务"；总数显示 `>10M` 截断提示。
- 结果表支持"添加全部到导出条件"（把当前过滤镜像到 Export Job 表单）。

## 3. 攻击中心与详情（R2/R5/R7/R9）

### 3.1 列表页
- 实时（WS 推送）：攻击中置顶、按置信度/速率排序；列：客户域、类型（含 SWEEP 扫段/ANOMALY 波动，R7）、峰值 bps/pps、开始时间、状态机徽章（候选/确认/处置中/已缓解）、处置入口。
- 筛选：客户域/类型/时间段/状态；CSV 导出。

### 3.2 详情页（R5 核心）
```
① 头部：攻击ID·客户域·类型·置信度·状态·峰值；[一键处置(→LucidBGP)] [导出原始日志]
② 速率曲线：bps/pps/new_flows 双轴 1 分钟粒度，叠加基线带(中位数±MAD)与攻击起止竖线
③ ★分钟明细表（AttackMinute）：每分钟 bps_in/out·pps·newflows·syn比·udp比·Top源(悬停)·Top端口
④ 证据面板：Top 源 100 表、端口分布条形、flag 占比、熵曲线、（扫段时）触达段列表与目的数
⑤ 原始日志联动（R5）：预填 [zone+时间窗±1min+Top源可选] → 创建导出任务 → 跳转任务中心/下载
⑥ 处置轨迹（R9）：时间线——告警发布→LucidBGP 下发（动作/网段/时效）→速率回落→缓解确认
```

## 4. 报表中心（R8）

### 4.1 报表 DSL（JSON，PG `reports` 表；模板市场预置 12 个：日报/周报/月报/攻击月报/客户带宽/接口利用/AS 互联…）
```json
{
  "id": "rpt-cust-weekly", "name": "客户周报", "scope": "zone",
  "dataset": {
    "source": "aggr_minute",
    "dimensions": ["minute","zone_name","app_name"],
    "metrics": [{"field":"bytes","agg":"sum","fmt":"bps","label":"带宽"},
                {"field":"flows","agg":"sum","label":"流数"}],
    "filters": [{"field":"zone_id","op":"in","value":"$zones"}],
    "time_range": {"type":"relative","value":"-7d","granularity":"hour"}
  },
  "layout": [
    {"type":"kpi","metrics":["bytes"]},
    {"type":"line","x":"minute","series":["zone_name"]},
    {"type":"table","dims":["zone_name","app_name"],"sort":"bytes:desc","top":20},
    {"type":"attack_summary"}                      // 内置攻击汇总块
  ],
  "params": [{"name":"$zones","type":"zone_multi","default":"all"}],
  "schedule": {"cron":"0 9 * * 1","output":["pdf","xlsx"],"mail":["ops@x.com"],"retention_days":90}
}
```

### 4.2 自定义设计器
- 四步向导：数据集（维度/指标/过滤，全部来自白名单枚举，无 SQL 逃逸；高级模式允许"受限 SQL"仅限 `aggr_*` 表+只读用户+超时 30s）→ 布局（KPI/折线/柱/饼/表/矩阵块拖拽）→ 参数（时间/zone 等占位符）→ 调度与分发。
- 预览实时执行（限流：设计器查询并发 4，超时 15s）。

### 4.3 渲染与分发
- `lucid-reporter`（Go 服务）：cron 触发 → 生成中间 JSON 数据 → 模板引擎（html/template）渲染 HTML → XLSX（excelize）/PDF（headless Chromium 单例池，2 并发）→ MinIO `reports/` → 邮件（SMTP）/站内通知；记录 `report_instances`（参数快照+产物链接+行数+耗时）。
- 大报表保护：单元格上限 50 万；超限自动截断+提示走导出任务。

## 5. LucidBGP 内嵌（R9）
- Console 路由 `/bgp/*`：iframe 指向 LucidBGP 前端（独立部署，见 dd/06 §4）；URL 免登（LucidBGP 校验一次签名 token，5min 有效，`POST /api/bgp/sso` 换取）。
- 攻击详情页"一键处置"：直接调 LucidBGP `POST /api/bgp/alarms`（带 attack_id/zone/top_sources），LucidBGP 处置表单预填（复用 rsbgp-console 既有"告警联动"能力）。

## 6. 网关（lucid-gateway）
- 聚合路由：`/api/v1/*`（自身）→ Master/Storage/Analytics 各后端 gRPC 转 REST（grpc-gateway）；`/api/bgp/*` 反代 LucidBGP（Spring Boot）。
- 统一：JWT 校验、租户注入、限流（明细查询类接口令牌桶 10 QPS/用户）、审计（写操作全记）、OpenAPI 聚合文档 `/swagger`。

## 7. 测试要点
1. R5 全链路 UI 演练：攻击注入（靶场）→ 列表告警 → 详情分钟表与曲线 → 导出原始日志下载比对。
2. R6 查询页：6h+多条件首屏 ≤6s；>6h 阻断并引导导出；深分页游标模式。
3. R8：自定义报表从设计到邮件送达；PDF/XLSX 内容快照测试；50 万单元格截断。
4. 权限矩阵：只读租户账号对 5/6/7 类操作按钮全部不可见+接口 403。
