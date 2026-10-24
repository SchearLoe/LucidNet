# @lucid/charts

图表封装包（docs/dd/05 §1 monorepo 之 charts；docs/10 §3.6 图表规范）。

已交付（M2 第一批）：

- **lucid ECharts 主题**（`theme.ts`）：运行时读取 `--lucid-*` CSS 变量生成
  （docs/10 §4），回落值与 `packages/shared/tokens.css` 逐字对应；`ensureLucidTheme(dark)`
  幂等注册并返回主题名。入蓝/出橙/攻击红/基线灰全部经 token 桥（`tokens.ts`），
  **禁止页面内传色值**（docs/10 §3.6 / §11-4 前端禁内联色值扫描，本包例外）。
- **AttackMinuteChart**（`AttackMinuteChart.tsx`）：攻击详情分钟曲线 ——
  左轴 bps（入蓝）、右轴 pps/new_flows（出橙）、基线带（中位数灰实线 + ±MAD
  半透明带，点带 `baseline`/`baseline_mad` 即渲染）、攻击起止红竖带/竖线、
  采样副标题“※ 估算（采样率 N:1）”、tooltip 十字准线。

TODO（后续批次）：

- 流量矩阵热力（单色蓝 5 档 ramp + 攻击红覆盖，图例显示分档阈值）；
- `lucid-icons` symbol sprite 接入（docs/10 §2：业务图标经 svgr 生成；
  现阶段图标名仅以 lucid-icons 域前缀 kebab-case 字符串登记于 `web/src/menus.ts`）；
- 主题监听 `prefers-color-scheme` / `[data-theme]` 变更自动 `refreshLucidTheme`。
