// Package report —— lucid-reporter 报表渲染与分发（R8，docs/dd/05 §4）。
//
// M1 仅占位：自定义报表属 M3 里程碑。规划要点（实现时勿丢）：
//   - 报表 DSL：JSON 定义（PG reports 表；模板市场预置 12 个）；数据集
//     维度/指标/过滤全部走白名单枚举，禁止 SQL 逃逸；高级模式“受限 SQL”
//     仅限 aggr_* 表 + 只读用户 + 超时 30s；
//   - 渲染链：cron 触发 → 中间 JSON → html/template → XLSX(excelize) /
//     PDF(headless Chromium 单例池，2 并发) → MinIO reports/ → SMTP/站内通知；
//   - report_instances 记录参数快照 + 产物链接 + 行数 + 耗时；
//   - 大报表保护：单元格上限 50 万，超限截断并提示走导出任务；
//   - 预览限流：设计器查询并发 4、超时 15s。
package report
