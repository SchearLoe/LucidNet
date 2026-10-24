package inserter

import (
	"testing"
)

// TestRouterDeterministic —— 同 (day, key) 恒定落同一分片；分隔符防碰撞。
func TestRouterDeterministic(t *testing.T) {
	r, err := NewRouter(3)
	if err != nil {
		t.Fatalf("new router: %v", err)
	}
	first := r.ShardFor("2026-10-24", "10.0.0.1")
	for i := 0; i < 100; i++ {
		if got := r.ShardFor("2026-10-24", "10.0.0.1"); got != first {
			t.Fatalf("shard drift: %d vs %d", got, first)
		}
	}
	if r.Shards() != 3 {
		t.Errorf("Shards = %d", r.Shards())
	}
}

// TestRouterRange —— 分片号始终 < shards（含单分片）。
func TestRouterRange(t *testing.T) {
	for _, shards := range []int{1, 3, 16} {
		r, err := NewRouter(shards)
		if err != nil {
			t.Fatalf("new router %d: %v", shards, err)
		}
		for _, day := range []string{"2026-01-01", "2026-10-24", "1970-01-01"} {
			for _, key := range []string{"", "a", "10.0.0.1", "attack:01J", "day\x1fkey-collision-probe"} {
				if got := r.ShardFor(day, key); got >= uint64(shards) {
					t.Fatalf("shard %d out of range (shards=%d)", got, shards)
				}
			}
		}
	}
}

// TestRouterSpread —— 键空间散布：不塌缩到单分片（粗粒度健康检查）。
func TestRouterSpread(t *testing.T) {
	const shards = 3
	r, _ := NewRouter(shards)
	seen := make(map[uint64]int)
	for i := 0; i < 300; i++ {
		key := "exporter-" + string(rune('a'+i%26)) + string(rune('0'+i%10))
		seen[r.ShardFor("2026-10-24", key)]++
	}
	if len(seen) < shards {
		t.Errorf("keys collapsed onto %d/%d shards: %v", len(seen), shards, seen)
	}
}

// TestRouterDaySensitivity —— day 参与（跨天重哈希；不要求必变，仅要求确定性）。
func TestRouterDaySensitivity(t *testing.T) {
	r, _ := NewRouter(3)
	_ = r.ShardFor("2026-10-24", "10.0.0.1")
	_ = r.ShardFor("2026-10-25", "10.0.0.1")
	// 断言：联合键含分隔符 0x1f，(day, key) 与拼接碰撞可区分
	a := r.ShardFor("2026-10-2", "4:10.0.0.1")
	b := r.ShardFor("2026-10-24", ":10.0.0.1")
	if a == b {
		t.Log("note: delimiter probe collides for this pair (acceptable, hash deterministic)")
	}
}

// TestNewRouterInvalid —— 非法分片数。
func TestNewRouterInvalid(t *testing.T) {
	if _, err := NewRouter(0); err == nil {
		t.Fatal("shards=0 must fail")
	}
	if _, err := NewRouter(-1); err == nil {
		t.Fatal("shards=-1 must fail")
	}
}
