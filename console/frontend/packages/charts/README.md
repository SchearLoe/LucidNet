# @lucid/charts

图表封装包（docs/dd/05 §1 monorepo 之 charts：矩阵热力等封装组件）。

TODO(M2)：
- ECharts 5 主题（`theme.json` 从 docs/10 §3.1 token 生成，禁止页面内传色值）；
- 流量矩阵热力（单色蓝 5 档 ramp + 攻击红覆盖，图例显示分档阈值）；
- 速率曲线（双轴：左 bps 右 pps/new_flows；基线带 = 中位数±MAD；攻击区间红色竖带）；
- `lucid-icons` symbol sprite 接入（docs/10 §2：业务图标经 svgr 生成，禁止页面手写内联 SVG 路径）。

M1 阶段总览页使用纯 KPI 卡片 + 表格，不引入图表依赖。
