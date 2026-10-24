package hll

import (
	"fmt"
	"math"
	"testing"

	"github.com/cespare/xxhash/v2"
)

// hashIP —— 用与 detector 相同的散列方式生成测试哈希。
func hashIP(ip [16]byte, salt uint64) uint64 {
	var buf [24]byte
	copy(buf[:16], ip[:])
	buf[16] = byte(salt)
	buf[17] = byte(salt >> 8)
	buf[18] = byte(salt >> 16)
	buf[19] = byte(salt >> 24)
	buf[20] = byte(salt >> 32)
	buf[21] = byte(salt >> 40)
	buf[22] = byte(salt >> 48)
	buf[23] = byte(salt >> 56)
	return xxhash.Sum64(buf[:])
}

func v4(a, b, c, d byte) [16]byte {
	var ip [16]byte
	ip[10], ip[11] = 0xff, 0xff
	ip[12], ip[13], ip[14], ip[15] = a, b, c, d
	return ip
}

func TestEstimateEmpty(t *testing.T) {
	t.Parallel()
	s := New(PrecisionDefault)
	if got := s.Estimate(); got != 0 {
		t.Fatalf("empty estimate = %v, want 0", got)
	}
}

func TestEstimateSingle(t *testing.T) {
	t.Parallel()
	s := New(PrecisionDefault)
	s.Insert(hashIP(v4(1, 2, 3, 4), 0))
	if got := s.Estimate(); got < 0.5 || got > 1.5 {
		t.Fatalf("single insert estimate = %v, want ~1", got)
	}
}

// TestEstimateAccuracy —— 不同基数下误差 <5%（m=2^14 理论 1σ≈0.8%）。
func TestEstimateAccuracy(t *testing.T) {
	t.Parallel()
	cases := []struct {
		n         int
		tolerance float64
	}{
		{n: 10, tolerance: 0.35}, // 小基数走线性计数，放宽
		{n: 32, tolerance: 0.20},
		{n: 1_000, tolerance: 0.05},
		{n: 10_000, tolerance: 0.05},
		{n: 100_000, tolerance: 0.03},
	}
	for _, tc := range cases {
		t.Run(fmt.Sprintf("n=%d", tc.n), func(t *testing.T) {
			s := New(PrecisionDefault)
			for i := 0; i < tc.n; i++ {
				s.Insert(hashIP(v4(byte(i>>24), byte(i>>16), byte(i>>8), byte(i)), uint64(i)))
			}
			got := s.Estimate()
			want := float64(tc.n)
			if math.Abs(got-want)/want > tc.tolerance {
				t.Fatalf("n=%d estimate=%.1f, error %.2f%% > %.0f%%",
					tc.n, got, math.Abs(got-want)/want*100, tc.tolerance*100)
			}
		})
	}
}

func TestInsertIdempotent(t *testing.T) {
	t.Parallel()
	s := New(PrecisionDefault)
	h := hashIP(v4(9, 9, 9, 9), 42)
	for i := 0; i < 1000; i++ {
		s.Insert(h)
	}
	if got := s.Estimate(); got < 0.5 || got > 1.5 {
		t.Fatalf("repeated insert estimate = %v, want ~1", got)
	}
}

func TestReset(t *testing.T) {
	t.Parallel()
	s := New(PrecisionDefault)
	for i := 0; i < 1000; i++ {
		s.Insert(hashIP(v4(1, 1, 1, byte(i)), 0))
	}
	if s.Estimate() < 10 {
		t.Fatalf("pre-reset estimate too small: %v", s.Estimate())
	}
	s.Reset()
	if got := s.Estimate(); got != 0 {
		t.Fatalf("post-reset estimate = %v, want 0", got)
	}
}

func TestPrecisionClampAndSize(t *testing.T) {
	t.Parallel()
	if got := New(2).Registers(); got != 16 {
		t.Fatalf("precision clamp low: %d registers, want 16", got)
	}
	if got := New(20).Registers(); got != 1<<16 {
		t.Fatalf("precision clamp high: %d registers, want %d", got, 1<<16)
	}
	s := New(PrecisionDefault)
	if sz := len(s.regs); sz != 8192 {
		t.Fatalf("2^14 registers packed size = %d bytes, want 8192", sz)
	}
}

// TestTinyPrecision —— srcAgg 每源基数（p=6）在少量目的下仍可用。
func TestTinyPrecision(t *testing.T) {
	t.Parallel()
	s := New(PrecisionTiny)
	for i := 0; i < 20; i++ {
		s.Insert(hashIP(v4(10, 0, 0, byte(i)), 7))
	}
	got := s.Estimate()
	if got < 12 || got > 30 { // 小精度误差大，仅量级断言
		t.Fatalf("tiny precision estimate = %.1f, want 12..30", got)
	}
}
