// redis.go —— RealtimeReader 的 Redis 实现（R2 客户域实时视图）。
//
// 键规范（唯一权威：docs/00 §6 + docs/09 §6 末尾补充裁定 2026-10-25：
// 统一 rt:* 前缀，dd/03 的 topn:{dim}:{ts} 写法作废；时间戳 epoch 秒）：
//
//	{prefix}zone:{zone_id}   HASH（或 STRING=JSON 对象，二者兼容读）
//	  bps_in / bps_out / pps_in / pps_out   float，客户视角速率（docs/00 §8）
//	  sample_rate                            uint，全链路采样率倒数（1=全采）
//	  ts                                     epoch 秒（裁定口径；>1e11 防御性视为毫秒）
//	  zone_name                              string（可缺省，前端回退 "Zone {id}"）
//	{prefix}topn:{dim}       TopN 近端键 —— 本接口不消费（WS TopN 另行接线）
//
// 写方为 Analytics Leader（并行开发中）；读方容忍 HASH 与 JSON STRING 两种载体，
// 以便写方落地期间字段名/载体微调不破坏网关。
//
// 降级策略（不得 500，docs/dd/05 §6 网关聚合原则）：
//   - Redis 连接/命令错误（未部署、网络抖动、超时）→ 回落构造时注入的内存实现；
//   - 键不存在 / SCAN 空结果（含 TTL 过期）→ 返回空快照（nil 错误，Redis 在即口径权威）；
//   - 单个键损坏（非法 zone_id / 非法 JSON）→ 跳过该键并记日志，不影响其余行。
package store

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/SchearLoe/lucidnet/console/internal/query"
)

// redisCallTimeout —— 单次调用的硬超时：Redis 故障时把对 /api/v1/zones/realtime
// 的额外延迟封顶，超时按错误走内存回落。
const redisCallTimeout = 2 * time.Second

// DefaultRedisKeyPrefix —— docs/09 §6 裁定的 rt:* 统一前缀。
const DefaultRedisKeyPrefix = "rt:"

// RedisRealtime —— query.RealtimeReader 的 Redis 实现（生产数据源）。
type RedisRealtime struct {
	rdb      redis.UniversalClient
	prefix   string               // 形如 "rt:"（须以冒号结尾）
	fallback query.RealtimeReader // Redis 错误时的内存回落（可为 nil → 空快照）
	log      *slog.Logger
}

// 编译期接口断言。
var _ query.RealtimeReader = (*RedisRealtime)(nil)

// NewRedisRealtime 构造；prefix 为空取 DefaultRedisKeyPrefix。
func NewRedisRealtime(rdb redis.UniversalClient, prefix string, fallback query.RealtimeReader, log *slog.Logger) *RedisRealtime {
	if prefix == "" {
		prefix = DefaultRedisKeyPrefix
	}
	if !strings.HasSuffix(prefix, ":") {
		prefix += ":"
	}
	if log == nil {
		log = slog.Default()
	}
	return &RedisRealtime{rdb: rdb, prefix: prefix, fallback: fallback, log: log}
}

// Prefix 返回生效键前缀（诊断/测试用）。
func (r *RedisRealtime) Prefix() string { return r.prefix }

// Close 释放底层连接池。
func (r *RedisRealtime) Close() error { return r.rdb.Close() }

// ZoneRealtime 实现 query.RealtimeReader：SCAN {prefix}zone:* → 逐键解析 →
// 按 zone_id 升序（与内存实现输出口径一致，前端渲染稳定）。
func (r *RedisRealtime) ZoneRealtime(ctx context.Context) ([]query.ZoneTraffic, error) {
	ctx, cancel := context.WithTimeout(ctx, redisCallTimeout)
	defer cancel()

	keys, err := r.scanZoneKeys(ctx)
	if err != nil {
		return r.degrade(err)
	}

	rows := make([]query.ZoneTraffic, 0, len(keys))
	for _, key := range keys {
		z, perr := r.readZone(ctx, key)
		if perr != nil {
			r.log.Warn("rt:zone key malformed, skipped", "module", "gateway", "key", key, "err", perr)
			continue
		}
		if z != nil {
			rows = append(rows, *z)
		}
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].ZoneID < rows[j].ZoneID })
	// 空结果=键未写/TTL 过期：返回空快照（不回落），Redis 在即实时口径权威。
	return rows, nil
}

// degrade Redis 层错误 → 内存回落（无 fallback 则空快照），错误本身不上抛（不得 500）。
func (r *RedisRealtime) degrade(err error) ([]query.ZoneTraffic, error) {
	r.log.Warn("redis realtime unavailable, falling back to memory", "module", "gateway", "err", err)
	if r.fallback != nil {
		return r.fallback.ZoneRealtime(context.Background())
	}
	return []query.ZoneTraffic{}, nil
}

// scanZoneKeys 游标扫描 {prefix}zone:*。
func (r *RedisRealtime) scanZoneKeys(ctx context.Context) ([]string, error) {
	var keys []string
	var cursor uint64
	for {
		batch, next, err := r.rdb.Scan(ctx, cursor, r.prefix+"zone:*", 200).Result()
		if err != nil {
			return nil, err
		}
		keys = append(keys, batch...)
		cursor = next
		if cursor == 0 {
			return keys, nil
		}
	}
}

// readZone 解析单个 rt:zone 键；键在解析期消失（过期竞态）返回 (nil, nil)。
func (r *RedisRealtime) readZone(ctx context.Context, key string) (*query.ZoneTraffic, error) {
	typ, err := r.rdb.Type(ctx, key).Result()
	if err != nil {
		return nil, err
	}
	fields := map[string]string{}
	switch typ {
	case "hash":
		m, err := r.rdb.HGetAll(ctx, key).Result()
		if err != nil {
			return nil, err
		}
		for k, v := range m {
			fields[k] = v
		}
	case "string":
		raw, err := r.rdb.Get(ctx, key).Result()
		if err != nil {
			return nil, err
		}
		dec := json.NewDecoder(strings.NewReader(raw))
		dec.UseNumber() // 保留大整数精度（ts 毫秒量级）
		var m map[string]any
		if err := dec.Decode(&m); err != nil {
			return nil, fmt.Errorf("json payload: %w", err)
		}
		for k, v := range m {
			fields[k] = anyToString(v)
		}
	default:
		return nil, fmt.Errorf("unsupported type %q", typ)
	}

	zoneID, err := strconv.ParseInt(strings.TrimPrefix(key, r.prefix+"zone:"), 10, 32)
	if err != nil {
		return nil, fmt.Errorf("zone id: %w", err)
	}
	return &query.ZoneTraffic{
		ZoneID:     int32(zoneID),
		ZoneName:   fields["zone_name"],
		BpsIn:      fieldFloat(fields, "bps_in"),
		BpsOut:     fieldFloat(fields, "bps_out"),
		PpsIn:      fieldFloat(fields, "pps_in"),
		PpsOut:     fieldFloat(fields, "pps_out"),
		SampleRate: uint32(fieldFloat(fields, "sample_rate")),
		TsMs:       tsToMs(fieldFloat(fields, "ts")),
	}, nil
}

// fieldFloat 宽容取数：缺失=0；字符串数字/JSON 数字均可。
func fieldFloat(fields map[string]string, name string) float64 {
	v, _ := strconv.ParseFloat(strings.TrimSpace(fields[name]), 64)
	return v
}

// anyToString JSON 值宽容字符串化（number/string/bool；嵌套结构不消费，置空）。
func anyToString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case json.Number:
		return t.String()
	case bool:
		if t {
			return "1"
		}
		return "0"
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	default:
		return ""
	}
}

// tsToMs 时间戳归一：docs/09 §6 裁定 epoch 秒为准（×1000）；>1e11 防御性视为
// 已是毫秒（历史生产者容错），0 保持 0（前端 Staleness 不误报）。
func tsToMs(sec float64) int64 {
	switch {
	case sec <= 0:
		return 0
	case sec > 1e11: // 毫秒量级（>3368 年的秒值不可能）
		return int64(sec)
	default:
		return int64(sec * 1000)
	}
}
