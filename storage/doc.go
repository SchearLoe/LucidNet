// Package storage —— LucidNet 存储（LucidStorage）组件。
//
// 覆盖：ClickHouse 写入（inserter，CH 写入唯一通道 = Kafka 消费，docs/09 §8）、
// 明细查询（query，R6）、异步导出（export，R5）与 CH DDL（internal/ddl）。
// 设计见 docs/hld/04、docs/dd/04；模块 README 含运行说明与 TODO 清单。
package storage
