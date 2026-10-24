-- 0007 —— Distributed 读侧包装表（docs/hld/04 §3：3 分片；Inserter 写各分片
-- 本地表绕过 Distributed 跳数，查询/导出统一走 _all 表）。
-- sharding_key 仅作 Distributed 自身INSERT时的路由提示（Inserter 不使用）；
-- 读路径不依赖 sharding_key。部署顺序：本地表全部就绪后再执行本文件。
CREATE TABLE IF NOT EXISTS flows_raw_all ON CLUSTER '{cluster}'
AS flows_raw
ENGINE = Distributed('{cluster}', 'lucid', 'flows_raw', cityHash64(exporter));

CREATE TABLE IF NOT EXISTS aggr_minute_all ON CLUSTER '{cluster}'
AS aggr_minute
ENGINE = Distributed('{cluster}', 'lucid', 'aggr_minute', cityHash64(exporter));

CREATE TABLE IF NOT EXISTS aggr_hour_all ON CLUSTER '{cluster}'
AS aggr_hour
ENGINE = Distributed('{cluster}', 'lucid', 'aggr_hour', cityHash64(exporter));

CREATE TABLE IF NOT EXISTS attacks_all ON CLUSTER '{cluster}'
AS attacks
ENGINE = Distributed('{cluster}', 'lucid', 'attacks', rand());

CREATE TABLE IF NOT EXISTS attack_minutes_all ON CLUSTER '{cluster}'
AS attack_minutes
ENGINE = Distributed('{cluster}', 'lucid', 'attack_minutes', rand());

CREATE TABLE IF NOT EXISTS alarm_history_all ON CLUSTER '{cluster}'
AS alarm_history
ENGINE = Distributed('{cluster}', 'lucid', 'alarm_history', rand());

-- baseline 不建 Distributed：唯一读方 = Analytics 基线回显走本地表/HTTP 接口
--（09 §8 例外通道），跨分片读需求出现时再补（模块 README TODO）。

-- 验证：
--   SELECT database, name, engine FROM system.tables WHERE database = 'lucid' ORDER BY name;
--   SELECT name, is_leader, is_readonly, queue_size FROM system.replicas WHERE database = 'lucid';
