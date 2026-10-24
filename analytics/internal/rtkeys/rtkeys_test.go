package rtkeys

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestTopNKeyFormat(t *testing.T) {
	t.Parallel()
	cases := []struct {
		dim   string
		tsSec int64
		want  string
	}{
		{"src_ip_1m", 1_792_863_420, "rt:topn:src_ip_1m:1792863420"},
		{"dst_ip_5m", 0, "rt:topn:dst_ip_5m:0"},
		{"port", 60, "rt:topn:port:60"},
	}
	for _, tc := range cases {
		if got := TopN(tc.dim, tc.tsSec); got != tc.want {
			t.Errorf("TopN(%q,%d) = %q, want %q", tc.dim, tc.tsSec, got, tc.want)
		}
	}
}

func TestEvidenceKeyFormat(t *testing.T) {
	t.Parallel()
	id := "01M5QFT1DERVPQN97F92A3QJ2B"
	if got := Evidence(id); got != "rt:evidence:"+id {
		t.Fatalf("Evidence = %q", got)
	}
}

// TestRtPrefixRuling —— 09 §6 2026-10-25 裁定：统一 rt:* 前缀，
// dd/03 §7 旧文 topn:{dim}:{ts} 写法作废（防回归）。
func TestRtPrefixRuling(t *testing.T) {
	t.Parallel()
	if Prefix != "rt" {
		t.Fatalf("Prefix = %q, want rt", Prefix)
	}
	keys := []string{
		TopN("src_ip_1m", 100),
		Evidence("01M5QFT1DERVPQN97F92A3QJ2B"),
		TopNPrefix,
		EvidencePrefix,
	}
	for _, k := range keys {
		if !startsWithRt(k) {
			t.Errorf("key %q must start with rt: prefix (09 §6)", k)
		}
	}
	if TopN("src_ip_1m", 100) == "topn:src_ip_1m:100" {
		t.Fatal("legacy dd/03 §7 key format must not be produced")
	}
}

func startsWithRt(k string) bool {
	return len(k) >= 3 && k[:3] == "rt:"
}

func TestTTLConstants(t *testing.T) {
	t.Parallel()
	if TopNTTL != 10*time.Minute {
		t.Fatalf("TopNTTL = %v, want 10m", TopNTTL)
	}
	if EvidenceTTL != 24*time.Hour {
		t.Fatalf("EvidenceTTL = %v, want 24h", EvidenceTTL)
	}
}

func TestValidDim(t *testing.T) {
	t.Parallel()
	valid := []string{"src_ip_1m", "port", "dst_as_5m", "a", "x0_9"}
	invalid := []string{"", "Src", "src-ip", "src:ip", "dim with space", toolongDim()}
	for _, d := range valid {
		if !ValidDim(d) {
			t.Errorf("dim %q should be valid", d)
		}
	}
	for _, d := range invalid {
		if ValidDim(d) {
			t.Errorf("dim %q should be invalid", d)
		}
	}
}

func toolongDim() string {
	b := make([]byte, 33)
	for i := range b {
		b[i] = 'a'
	}
	return string(b)
}

func TestValidAttackID(t *testing.T) {
	t.Parallel()
	if !ValidAttackID("01M5QFT1DERVPQN97F92A3QJ2B") {
		t.Error("26-char ULID should be valid")
	}
	if ValidAttackID("") {
		t.Error("empty attack id should be invalid")
	}
	if ValidAttackID(strings.Repeat("a", 65)) {
		t.Error("overlong attack id should be invalid")
	}
}

// TestDevStoreRoundTrip —— 写入落键格式与 TTL 归属。
func TestDevStoreRoundTrip(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := NewDevStore()

	if err := s.SetTopN(ctx, "src_ip_1m", 1_792_863_420, []byte(`{"top":[["10.0.0.1",100]]}`)); err != nil {
		t.Fatal(err)
	}
	got, ok := s.Get(ctx, TopN("src_ip_1m", 1_792_863_420))
	if !ok || string(got) != `{"top":[["10.0.0.1",100]]}` {
		t.Fatalf("topn roundtrip = %q ok=%v", got, ok)
	}
	if _, ok := s.Get(ctx, "rt:topn:src_ip_1m:999"); ok {
		t.Fatal("wrong window key should miss")
	}

	id := "01M5QFT1DERVPQN97F92A3QJ2B"
	if err := s.SetEvidence(ctx, id, []byte(`{"syn_ratio":1}`)); err != nil {
		t.Fatal(err)
	}
	if got, ok := s.Get(ctx, Evidence(id)); !ok || string(got) != `{"syn_ratio":1}` {
		t.Fatalf("evidence roundtrip = %q ok=%v", got, ok)
	}
	if s.Len() != 2 {
		t.Fatalf("len = %d, want 2", s.Len())
	}
}

// TestDevStoreExpiry —— TTL 以注入时钟判定（TopN 10m / Evidence 24h）。
func TestDevStoreExpiry(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	now := time.Unix(1_792_863_400, 0).UTC()
	s := NewDevStore(WithClock(func() time.Time { return now }))

	_ = s.SetTopN(ctx, "src_ip_1m", 0, []byte("x"))
	_ = s.SetEvidence(ctx, "01M5QFT1DERVPQN97F92A3QJ2B", []byte("y"))

	now = now.Add(9 * time.Minute)
	if _, ok := s.Get(ctx, TopN("src_ip_1m", 0)); !ok {
		t.Fatal("topn key should live at 9m (TTL 10m)")
	}
	now = now.Add(2 * time.Minute)
	if _, ok := s.Get(ctx, TopN("src_ip_1m", 0)); ok {
		t.Fatal("topn key should expire after 10m")
	}
	if _, ok := s.Get(ctx, Evidence("01M5QFT1DERVPQN97F92A3QJ2B")); !ok {
		t.Fatal("evidence key should live at 11m (TTL 24h)")
	}
	now = now.Add(24 * time.Hour)
	if _, ok := s.Get(ctx, Evidence("01M5QFT1DERVPQN97F92A3QJ2B")); ok {
		t.Fatal("evidence key should expire after 24h")
	}
	if s.Len() != 0 {
		t.Fatalf("len = %d, want 0 after expiry", s.Len())
	}
}

func TestDevStoreValidation(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := NewDevStore()
	if err := s.SetTopN(ctx, "Bad-Dim", 0, nil); !errors.Is(err, ErrInvalidDim) {
		t.Fatalf("invalid dim should wrap ErrInvalidDim, got %v", err)
	}
	if err := s.SetEvidence(ctx, "", nil); !errors.Is(err, ErrInvalidAttackID) {
		t.Fatalf("empty attack id should wrap ErrInvalidAttackID, got %v", err)
	}
}

// TestDevStoreConcurrentAccess —— 并发读写结构安全（-race 不可用环境以一致性替代）。
func TestDevStoreConcurrentAccess(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := NewDevStore()
	var wg sync.WaitGroup
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				_ = s.SetTopN(ctx, "src_ip_1m", int64(i), []byte(fmt.Sprint(w)))
				_, _ = s.Get(ctx, TopN("src_ip_1m", int64(i)))
				_ = s.Len()
			}
		}(w)
	}
	wg.Wait()
	if s.Len() != 200 {
		t.Fatalf("len = %d, want 200 distinct window keys", s.Len())
	}
}

// 接口满足性编译期断言。
var _ Store = (*DevStore)(nil)
