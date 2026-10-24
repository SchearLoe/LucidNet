-- 0006 —— alarm_history 告警历史表（契约缺口占位：docs/dd/04 §1.3 要求
-- alarms → "attacks 与告警历史"、docs/09 §6 要求 Storage 提供 /api/v1/alarms
-- 告警历史读取，但 docs/00 §4 / docs/09 §8 均未定义该表 DDL 与保留期——
-- 本文件为 Storage 侧提案，待契约评审后以 docs 09/00 为准修订）。
-- 写入方唯一 = Inserter（alarms topic 的 AlarmEnvelope.Alarm 子集，docs/09 §8）。
CREATE TABLE IF NOT EXISTS alarm_history ON CLUSTER '{cluster}'
(
    alarm_id    String,
    source      LowCardinality(String),   -- analytics|bgp|system
    severity    UInt8,                    -- 1提示 2警告 3严重
    category    UInt8,                    -- 1攻击 2波动 3设备 4系统
    raise_ms    Int64,
    clear_ms    Int64,                    -- 0=未清除
    subject     String,
    detail_json String,
    zone_id     Int32,
    attack_id   String,                   -- 可选关联
    ingested_at DateTime DEFAULT now()
)
ENGINE = ReplicatedMergeTree('/ch/lucid/{shard}/alarm_history', '{replica}')
PARTITION BY toYYYYMM(toDateTime(intDiv(raise_ms, 1000)))
ORDER BY (zone_id, raise_ms, alarm_id)
TTL toDateTime(intDiv(raise_ms, 1000)) + INTERVAL 6 MONTH;  -- 保留期暂定 6 个月（契约缺口，待裁定）
