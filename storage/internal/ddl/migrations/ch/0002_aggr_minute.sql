-- 0002 —— aggr_minute 分钟聚合表（docs/00 §4；TTL 13 个月）
-- 写入方唯一 = Inserter（docs/09 §8：消费 flows.aggr.minute，AggrRow 携带
-- -State 聚合中间态，docs/09 §2）；hour 上卷见 0003 的物化视图。
--
-- 契约冲突裁定（按 09 优先）：docs/00 §4 尾注与 dd/04 §1.2 写"物化视图从
-- flows_raw 滚动"，与 09 §8"来源 topic flows.aggr.minute（MV 上卷）"冲突——
-- 按 09：Inserter 消费 topic 直写本表，MV 仅做 minute→hour 上卷（0003）。
-- 不建 mv_aggr_minute（避免与 topic 通道双写）。
CREATE TABLE IF NOT EXISTS aggr_minute ON CLUSTER '{cluster}'
(
    minute    DateTime,                   -- 分钟对齐 epoch 秒
    exporter  LowCardinality(String),
    device_id UInt32,
    in_if     UInt32,
    out_if    UInt32,
    direction UInt8,                      -- 客户视角方向（ZoneSide 推导，docs/09 §3；0=unknown 1=in 2=out 3=intra）
    zone_id   Int32,
    src_as    UInt32,
    dst_as    UInt32,
    proto     UInt8,
    dst_port  UInt16,
    app_id    UInt32,
    bytes     AggregateFunction(sum, UInt64),   -- -State 中间态；读侧 sumMerge 补齐（dd/04 §3）
    packets   AggregateFunction(sum, UInt64),
    flows     AggregateFunction(count)
)
ENGINE = ReplicatedAggregatingMergeTree('/ch/lucid/{shard}/aggr_minute', '{replica}')
PARTITION BY toYYYYMM(minute)
ORDER BY (minute, exporter, in_if, zone_id, proto, dst_port)
TTL minute + INTERVAL 13 MONTH
SETTINGS index_granularity = 8192;
