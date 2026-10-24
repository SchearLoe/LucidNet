package fsm

import (
	"regexp"
	"testing"
	"time"
)

var ulidPattern = regexp.MustCompile(`^[0-9A-HJKMNP-TV-Z]{26}$`)

func TestULIDFormat(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_777_000_000, 0).UTC()
	for i := 0; i < 100; i++ {
		id := NewULID(now)
		if !ulidPattern.MatchString(id) {
			t.Fatalf("ULID %q does not match Crockford Base32 26-char format", id)
		}
	}
}

func TestULIDUniqueness(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_777_000_000, 0).UTC()
	seen := make(map[string]struct{}, 10_000)
	for i := 0; i < 10_000; i++ {
		seen[NewULID(now)] = struct{}{}
	}
	if len(seen) != 10_000 {
		t.Fatalf("ULID collision: %d unique of 10,000", len(seen))
	}
}

func TestULIDTimeOrdered(t *testing.T) {
	t.Parallel()
	t0 := time.Unix(1_777_000_000, 0).UTC()
	t1 := t0.Add(time.Hour)
	a, b := NewULID(t0), NewULID(t1)
	if a[:10] >= b[:10] {
		t.Fatalf("ULID time prefix must be ordered: %s vs %s", a[:10], b[:10])
	}
}
