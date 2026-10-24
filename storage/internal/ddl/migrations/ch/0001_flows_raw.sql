-- 0001 —— flows_raw 明细表（docs/00 §4；docs/dd/04 §1.2）
-- R6：15 天保留（热 3 天 NVMe + 冷 12 天 HDD，TTL 双层）；写入方唯一 = Inserter
--（docs/09 §8：消费 flows.raw，见 §2 写入通道契约）。
--
-- 占位参数：{cluster} = 集群名（部署替换为 lucid）；{shard}/{replica} 为 CH 宏。
-- 互联过滤不在此层物理删除（docs/dd/04 §1.2：R4 过滤是查询/分析语义，取证需全量）。
CREATE TABLE IF NOT EXISTS flows_raw ON CLUSTER '{cluster}'
(
    time_second  DateTime,                   -- 流开始秒（epoch 秒，分区/排序键）
    time_ms      UInt16,                     -- 毫秒余数 0-999（time_second*1000+time_ms = ms）
    exporter     LowCardinality(String),     -- exporter IP 文本
    device_id    UInt32,                     -- 资产库设备 ID（0=未知）
    in_if        UInt32,                     -- SNMP ifIndex 命名空间（docs/09 §3）
    out_if       UInt32,
    src_ip       IPv6,                       -- 16B；IPv4 以 ::ffff:a.b.c.d 映射存储（docs/00 §1，无膨胀）
    dst_ip       IPv6,
    src_port     UInt16,
    dst_port     UInt16,
    proto        UInt8,                      -- IP 协议号
    ip_version   UInt8,                      -- 4/6（写者填充，不靠推导，docs/00 §1）
    packets      UInt64,
    bytes        UInt64,
    tcp_flags    UInt8,                      -- 契约缺口：proto 位掩码 uint32 >0xFF 截断（模块 README）
    tos          UInt8,
    sample_rate  UInt32,                     -- 全链路采样率倒数（1=全采，docs/09 §3）
    src_as       UInt32,
    dst_as       UInt32,
    app_id       UInt32,
    zone_id      Int32,                      -- 0=未命中；一条记录只标一个客户域（docs/09 §3）
    if_role      UInt8,                      -- bit0 in=boundary / bit1 out=boundary（docs/09 §3）
    INDEX bf_src src_ip TYPE bloom_filter GRANULARITY 4,   -- docs/00 §4：IP 等值/范围粗筛
    INDEX bf_dst dst_ip TYPE bloom_filter GRANULARITY 4,
    INDEX mm_bytes minmax(bytes) TYPE minmax GRANULARITY 4 -- docs/dd/04 §1.2：攻击时段按体量粗筛
)
ENGINE = ReplicatedMergeTree('/ch/lucid/{shard}/flows_raw', '{replica}')
PARTITION BY toYYYYMMDD(time_second)
ORDER BY (time_second, exporter, zone_id, in_if, out_if, proto, dst_port, src_ip)
TTL time_second + INTERVAL 3 DAY TO VOLUME 'hot',   -- 第 3 天迁冷盘（docs/dd/04 §1.1）
    time_second + INTERVAL 15 DAY TO VOLUME 'cold'  -- 第 15 天删除（R6；总 15 天=热3+冷12）
SETTINGS storage_policy = 'hot_cold',
         index_granularity = 8192,
         insert_quorum = 1,            -- docs/dd/04 §1.2 吞吐优先
         insert_quorum_parallel = 1;

-- 契约缺口（模块 README 问题清单，只报告不改 docs）：
-- 1. FlowRecord.zone_side / src_geo / dst_geo / bgp_next_hop 无对应列，落库即丢失；
-- 2. dd/04 §2.2 深分页游标引用的 _batch 列不存在（本表排序键即游标依据，实现见 internal/query）。
