-- 0005 —— baseline 基线表（docs/00 §4；09 §8 注：例外通道——Analytics Leader
-- 每小时低频直写 CH HTTP 接口，不经 Inserter；TTL 8 周）。
CREATE TABLE IF NOT EXISTS baseline ON CLUSTER '{cluster}'
(
    metric_key String,                          -- 指标键（如 zone:101:bps_in）
    slot       DateTime,                        -- 基线槽（小时对齐）
    digest     AggregateFunction(quantileTDigest, Float64),
    mad        Float64,                         -- 中位绝对差
    samples    UInt32
)
ENGINE = ReplicatedAggregatingMergeTree('/ch/lucid/{shard}/baseline', '{replica}')
ORDER BY (metric_key, slot)
TTL slot + INTERVAL 8 WEEK;
