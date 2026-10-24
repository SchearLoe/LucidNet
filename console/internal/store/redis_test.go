// redis_test.go —— RedisRealtime 单测（miniredis）：键解析 / 空值降级 / 错误降级。
package store

import (
	"context"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"

	"github.com/SchearLoe/lucidnet/console/internal/query"
)

// newTestReader 起 miniredis 并构造 reader；返回 (reader, miniredis, client, fallback)。
func newTestReader(t *testing.T, prefix string) (*RedisRealtime, *miniredis.Miniredis, *redis.Client, *Memory) {
	t.Helper()
	s := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: s.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	fb := NewMemory(100, 100)
	return NewRedisRealtime(rdb, prefix, fb, nil), s, rdb, fb
}

// mustRows 执行查询并断言不得出错（优雅降级契约：任何场景错误都不上抛业务层）。
func mustRows(t *testing.T, r *RedisRealtime) []query.ZoneTraffic {
	t.Helper()
	rows, err := r.ZoneRealtime(context.Background())
	if err != nil {
		t.Fatalf("ZoneRealtime returned error: %v（降级契约：不得 500/上抛）", err)
	}
	return rows
}

// TestParseHashAndJSONKeys 键解析：HASH 载体 + JSON STRING 载体 + 无关键跳过 +
// epoch 秒→毫秒换算 + 按 zone_id 升序。
func TestParseHashAndJSONKeys(t *testing.T) {
	r, s, _, _ := newTestReader(t, "")

	// HASH 载体（推荐写法）：zone 101，ts=epoch 秒
	s.HSet("rt:zone:101",
		"zone_name", "客户A",
		"bps_in", "12345678",
		"bps_out", "8765432",
		"pps_in", "12000",
		"pps_out", "8000",
		"sample_rate", "100",
		"ts", "1761300000",
	)
	// JSON STRING 载体（兼容写法）：zone 102，防御性毫秒时间戳
	s.Set("rt:zone:102", `{"zone_name":"客户B","bps_in":9000000,"pps_in":9000,"sample_rate":1,"ts":1761300000000}`)
	// 无关键（不得出现）+ 非法 zone_id（跳过不报错）+ 损坏 JSON（跳过不报错）
	s.Set("topn:src:1761300000", "junk")
	s.Set("rt:zone:abc", `{"bps_in":1}`)
	s.Set("rt:zone:103", `{not-json`)

	rows := mustRows(t, r)
	if len(rows) != 2 {
		t.Fatalf("want 2 zones (101,102)，got %d: %+v", len(rows), rows)
	}
	if rows[0].ZoneID != 101 || rows[1].ZoneID != 102 {
		t.Fatalf("want sorted [101,102]，got %d,%d", rows[0].ZoneID, rows[1].ZoneID)
	}

	z := rows[0]
	if z.ZoneName != "客户A" || z.BpsIn != 12345678 || z.BpsOut != 8765432 ||
		z.PpsIn != 12000 || z.PpsOut != 8000 || z.SampleRate != 100 {
		t.Fatalf("hash fields mismatch: %+v", z)
	}
	if z.TsMs != 1761300000000 {
		t.Fatalf("epoch seconds → ms: want 1761300000000，got %d", z.TsMs)
	}
	if rows[1].TsMs != 1761300000000 { // 毫秒值防御性直通
		t.Fatalf("ms passthrough: want 1761300000000，got %d", rows[1].TsMs)
	}
	if rows[1].BpsIn != 9000000 || rows[1].SampleRate != 1 {
		t.Fatalf("json fields mismatch: %+v", rows[1])
	}
}

// TestCustomPrefix 前缀可配（默认 rt:，裁定值；自定义用于多环境隔离）。
func TestCustomPrefix(t *testing.T) {
	r, s, _, _ := newTestReader(t, "lucid-rt") // 无冒号结尾 → 自动补 ":"
	s.HSet("lucid-rt:zone:7", "bps_in", "500", "ts", "1761300000")

	rows := mustRows(t, r)
	if len(rows) != 1 || rows[0].ZoneID != 7 || rows[0].BpsIn != 500 {
		t.Fatalf("custom prefix parse failed: %+v", rows)
	}
	if r.Prefix() != "lucid-rt:" {
		t.Fatalf("prefix normalize: want lucid-rt:，got %q", r.Prefix())
	}
}

// TestEmptyFallbackToSnapshot 空值降级：Redis 在但无键（未写/TTL 过期）→ 空快照
// 而非内存回落（实时口径权威），且不报错。
func TestEmptyFallbackToSnapshot(t *testing.T) {
	r, s, _, fb := newTestReader(t, "")
	// 内存回落里有数据，但 Redis 权威为空 → 必须返回空快照
	fb.UpdateZone(42, "内存客户域", 1, 1, 1, 1, 1, 1761300000000)
	if s.Exists("rt:zone:42") {
		t.Fatal("precondition: no keys expected")
	}

	rows := mustRows(t, r)
	if len(rows) != 0 {
		t.Fatalf("want empty snapshot，got %+v", rows)
	}
}

// TestErrorFallbackToMemory 错误降级：Redis 不可达（进程已关）→ 回落内存实现，不报错。
func TestErrorFallbackToMemory(t *testing.T) {
	r, s, _, fb := newTestReader(t, "")
	fb.UpdateZone(9, "回落客户域", 111, 222, 33, 44, 10, 1761300000000)
	s.Close() // 之后所有命令 → 连接错误

	rows := mustRows(t, r)
	if len(rows) != 1 || rows[0].ZoneID != 9 || rows[0].BpsIn != 111 || rows[0].ZoneName != "回落客户域" {
		t.Fatalf("memory fallback expected，got %+v", rows)
	}
}

// TestErrorFallbackNil 无 fallback（nil）时错误 → 空快照，仍不报错。
func TestErrorFallbackNil(t *testing.T) {
	s := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: s.Addr()})
	s.Close()
	r := NewRedisRealtime(rdb, "", nil, nil)
	t.Cleanup(func() { _ = rdb.Close() })

	rows := mustRows(t, r)
	if rows == nil || len(rows) != 0 {
		t.Fatalf("want empty (non-nil) snapshot，got %+v", rows)
	}
}

// TestZeroTs Staleness 语义：ts 缺失/0 → TsMs=0（前端不误报陈旧）。
func TestZeroTs(t *testing.T) {
	r, s, _, _ := newTestReader(t, "")
	s.HSet("rt:zone:5", "bps_in", "10") // 无 ts 字段

	rows := mustRows(t, r)
	if len(rows) != 1 || rows[0].TsMs != 0 {
		t.Fatalf("want TsMs=0，got %+v", rows)
	}
}

// TestInterfaceAssertions 实现断言：与内存实现共同满足 RealtimeReader。
func TestInterfaceAssertions(t *testing.T) {
	var _ query.RealtimeReader = (*RedisRealtime)(nil)
	var _ query.RealtimeReader = (*Memory)(nil)
}
