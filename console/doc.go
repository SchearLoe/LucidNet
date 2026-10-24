// Package console —— LucidConsole（05 展示与报表，docs/hld/05 + docs/dd/05）。
//
// 本模块承载两类 Go 组件（前端 SPA 见 frontend/，pnpm workspace）：
//
//	lucid-gateway（cmd/lucid-gateway）—— API 网关 + WebSocket 实时推送：
//	  - /api/v1/* 单点接入：JWT(HS256) 鉴权与租户注入（docs/dd/07）、权限码
//	    <domain>:<action> 检查（docs/11 §8）、{code,msg,data} 统一信封（docs/00 §6）；
//	  - 自有展示查询：客户域实时视图（R2）、攻击列表/详情/分钟明细（R5/R7）、
//	    告警列表（R7）；历史与分钟点查经 upstream 转发 Storage（docs/09 §6）；
//	  - R6 明细查询/导出转发 Storage QueryService/ExportService（6h 窗约束 +
//	    10 QPS/用户令牌桶，docs/dd/04 §2.1、docs/dd/05 §6）；
//	  - WS /api/v1/stream/{alarms|attacks|events}：消费 Kafka alarms /
//	    bgp.mitigations（消费组 gateway.ws，docs/09 §2）→ hub 广播。
//	lucid-reporter（cmd/lucid-reporter）—— R8 报表渲染与分发（M3 占位）。
//
// 契约归属：路由与消息以 docs/09-模块间接口契约.md 为唯一权威；本模块不直读
// ClickHouse/PG 业务表，展示数据一律经接口获取。
package console
