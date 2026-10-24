-- 0003 —— aggr_hour 小时聚合表 + minute→hour 上卷物化视图（docs/00 §4：同构，TTL 3 年）
-- 链式 MergeState 语义（dd/04 §1.2）：源列已是 AggregateFunction 态，MV 用
-- sumMerge/countMerge 归并后再入目标同类型列。
CREATE TABLE IF NOT EXISTS aggr_hour ON CLUSTER '{cluster}'
(
    hour      DateTime,                   -- 小时对齐 epoch 秒（同构：minute→hour）
    exporter  LowCardinality(String),
    device_id UInt32,
    in_if     UInt32,
    out_if    UInt32,
    direction UInt8,
    zone_id   Int32,
    src_as    UInt32,
    dst_as    UInt32,
    proto     UInt8,
    dst_port  UInt16,
    app_id    UInt32,
    bytes     AggregateFunction(sum, UInt64),
    packets   AggregateFunction(sum, UInt64),
    flows     AggregateFunction(count)
)
ENGINE = ReplicatedAggregatingMergeTree('/ch/lucid/{shard}/aggr_hour', '{replica}')
PARTITION BY toYYYYMM(hour)
ORDER BY (hour, exporter, in_if, zone_id, proto, dst_port)
TTL hour + INTERVAL 36 MONTH
SETTINGS index_granularity = 8192;

-- mv_<目标表>_<来源>（docs/11 §7 物化视图命名）
-- 部署顺序：先建 aggr_hour（上文）再建本视图（同文件内顺序即正确）。
CREATE MATERIALIZED VIEW IF NOT EXISTS mv_aggr_hour_aggr_minute ON CLUSTER '{cluster}'
TO aggr_hour AS
SELECT
    toStartOfHour(minute)                AS hour,
    exporter,
    device_id,
    in_if,
    out_if,
    direction,
    zone_id,
    src_as,
    dst_as,
    proto,
    dst_port,
    app_id,
    sumMerge(bytes)   AS bytes,
    sumMerge(packets) AS packets,
    countMerge(flows) AS flows
FROM aggr_minute
GROUP BY hour, exporter, device_id, in_if, out_if, direction, zone_id, src_as, dst_as, proto, dst_port, app_id;
