-- 0004 —— attacks / attack_minutes 攻击两表（docs/00 §2.3/§4；docs/dd/04 §3）
-- attacks 来源 = alarms topic 的 AlarmEnvelope.Attack 子集（docs/09 §8），
-- 写入方唯一 = Inserter；attack_minutes 来源 = attacks.minutes topic。
-- R5 详情页点查 <200ms：attack_minutes 按 (attack_id, minute) 主键直查。
CREATE TABLE IF NOT EXISTS attacks ON CLUSTER '{cluster}'
(
    attack_id     String,                 -- ULID
    zone_id       Int32,
    zone_name     String,
    attack_type   UInt8,                  -- docs/00 §2.3 枚举 1..8
    target_prefix String,                 -- 受害前缀/关键目标（文本）
    start_ms      Int64,
    end_ms        Int64,
    peak_bps      Int64,
    peak_pps      Int64,
    confidence    Float32,                -- 0-1
    top_sources   Array(String),          -- 证据：Top 源（≤100）
    evidence_json String,                 -- 特征快照（端口分布/flag 比/熵…）
    status        UInt8,                  -- 1候选 2确认 3处置中 4已缓解 5误报关闭
    mitigation_id String,                 -- LucidBGP 处置关联（R9）
    ingested_at   DateTime DEFAULT now()  -- 落库时刻（重放/多行合并依据）
)
ENGINE = ReplicatedMergeTree('/ch/lucid/{shard}/attacks', '{replica}')
PARTITION BY toYYYYMMDD(toDateTime(intDiv(start_ms, 1000)))
ORDER BY (zone_id, start_ms)              -- docs/dd/04 §3：按 (zone_id, start_ms) 主键直查
TTL toDateTime(intDiv(start_ms, 1000)) + INTERVAL 1 YEAR;

CREATE TABLE IF NOT EXISTS attack_minutes ON CLUSTER '{cluster}'
(
    attack_id   String,
    minute      DateTime,                 -- minute_epoch 秒，分钟对齐
    bps_in      Int64,
    pps_in      Int64,
    bps_out     Int64,
    pps_out     Int64,
    new_flows   UInt64,
    syn_ratio   Float32,
    udp_ratio   Float32,
    top_sources Array(String),
    top_ports   Array(UInt32)
)
ENGINE = ReplicatedMergeTree('/ch/lucid/{shard}/attack_minutes', '{replica}')
PARTITION BY toYYYYMM(minute)
ORDER BY (attack_id, minute)              -- R5 详情页按 attack_id 点查
TTL minute + INTERVAL 6 MONTH;
