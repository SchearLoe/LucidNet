package assign

import (
	"fmt"
	"testing"
)

func TestRingBuildVnodeCount(t *testing.T) {
	r := NewRing([]Collector{
		{ID: "c1", Weight: 1.0}, // 160 vnodes
		{ID: "c2", Weight: 0.5}, // 80 vnodes
		{ID: "c3", Weight: 0.0}, // 权重下限 0.05 → 8 vnodes
	})
	if len(r.points) != 160+80+8 {
		t.Fatalf("vnodes = %d, want %d", len(r.points), 160+80+8)
	}
	// hash 有序
	for i := 1; i < len(r.points); i++ {
		if r.points[i-1].hash > r.points[i].hash {
			t.Fatal("ring not sorted")
		}
	}
}

func TestRingLookupDeterministic(t *testing.T) {
	r := NewRing([]Collector{{ID: "a", Weight: 1}, {ID: "b", Weight: 1}})
	got := map[string]string{}
	for i := 0; i < 100; i++ {
		ip := fmt.Sprintf("10.0.%d.%d", i/256, i%256)
		got[ip] = r.Lookup(ip)
	}
	for ip, c := range got {
		if again := r.Lookup(ip); again != c {
			t.Fatalf("lookup %s unstable: %s vs %s", ip, c, again)
		}
		if c != "a" && c != "b" {
			t.Fatalf("lookup %s out of ring: %s", ip, c)
		}
	}
}

// TestRingRemovalMovesMinority —— 节点增减仅迁移 ~1/N exporter（hld/07 §4）。
func TestRingRemovalMovesMinority(t *testing.T) {
	full := NewRing([]Collector{{ID: "a", Weight: 1}, {ID: "b", Weight: 1}, {ID: "c", Weight: 1}})
	minus := NewRing([]Collector{{ID: "a", Weight: 1}, {ID: "b", Weight: 1}})
	moved, total := 0, 500
	for i := 0; i < total; i++ {
		ip := fmt.Sprintf("10.1.%d.%d", i/256, i%256)
		if full.Lookup(ip) != minus.Lookup(ip) {
			moved++
		}
	}
	// 期望 ~1/3；放宽到 [10%, 60%]
	ratio := float64(moved) / float64(total)
	if ratio < 0.10 || ratio > 0.60 {
		t.Fatalf("moved ratio = %.2f, want ~0.33", ratio)
	}
}

func TestRingLookupWalkDistinct(t *testing.T) {
	r := NewRing([]Collector{{ID: "a", Weight: 1}, {ID: "b", Weight: 1}, {ID: "c", Weight: 1}})
	seen := map[string]bool{}
	for skip := 0; skip < 3; skip++ {
		c := r.LookupWalk("10.2.3.4", skip)
		if c == "" || seen[c] {
			t.Fatalf("walk skip=%d got %q (seen %v)", skip, c, seen)
		}
		seen[c] = true
	}
	if got := r.LookupWalk("10.2.3.4", 3); got != "" {
		t.Fatalf("walk beyond ring size should be empty, got %q", got)
	}
}
