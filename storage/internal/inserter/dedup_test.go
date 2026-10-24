package inserter

import (
	"context"
	"errors"
	"testing"
)

// TestMemoryDeduper —— Seen/MarkDone 幂等语义。
func TestMemoryDeduper(t *testing.T) {
	ctx := context.Background()
	d := NewMemoryDeduper(0) // capacity<=0 → 1024
	if seen, err := d.Seen(ctx, 1); err != nil || seen {
		t.Fatalf("initial seen = %v, %v", seen, err)
	}
	if err := d.MarkDone(ctx, 1); err != nil {
		t.Fatalf("mark: %v", err)
	}
	if err := d.MarkDone(ctx, 1); err != nil { // 重复标记幂等
		t.Fatalf("re-mark: %v", err)
	}
	if seen, _ := d.Seen(ctx, 1); !seen {
		t.Fatal("seen after mark")
	}
	if seen, _ := d.Seen(ctx, 2); seen {
		t.Fatal("unrelated id must not be seen")
	}
}

// TestMemoryDeduperEviction —— FIFO 容量淘汰。
func TestMemoryDeduperEviction(t *testing.T) {
	ctx := context.Background()
	d := NewMemoryDeduper(2)
	_ = d.MarkDone(ctx, 1)
	_ = d.MarkDone(ctx, 2)
	_ = d.MarkDone(ctx, 3) // 淘汰 1
	if seen, _ := d.Seen(ctx, 1); seen {
		t.Error("id 1 must be evicted")
	}
	for _, id := range []uint64{2, 3} {
		if seen, _ := d.Seen(ctx, id); !seen {
			t.Errorf("id %d must be retained", id)
		}
	}
}

// TestPGDeduperStub —— PG 桩返回 ErrNotImplemented 包裹。
func TestPGDeduperStub(t *testing.T) {
	d := NewPGDeduper("postgres://localhost/lucid")
	if _, err := d.Seen(context.Background(), 1); !errors.Is(err, ErrNotImplemented) {
		t.Errorf("seen err = %v", err)
	}
	if err := d.MarkDone(context.Background(), 1); !errors.Is(err, ErrNotImplemented) {
		t.Errorf("mark err = %v", err)
	}
}
