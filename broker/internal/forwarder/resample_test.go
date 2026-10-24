package forwarder

import (
	"testing"
	"time"

	"github.com/SchearLoe/lucidnet/shared"
)

func rec(src [16]byte, dst [16]byte, sport, dport, proto uint32) shared.FlowRecord {
	return shared.FlowRecord{SrcIP: src, DstIP: dst, SrcPort: sport, DstPort: dport, Proto: proto, SampleRate: 1}
}

func TestDeterministicSamplerReproducible(t *testing.T) {
	r := &Resample{Mode: ResampleDeterministic, Rate: 10}
	s := NewSampler(r)
	a := rec([16]byte{1}, [16]byte{2}, 1, 2, 6)
	b := a // 同流同判（dd/01 §4.1）
	if s.Keep(&a) != s.Keep(&b) {
		t.Fatal("deterministic sampler must be reproducible for identical flowkey")
	}
	// 时间无关：改时间不改变判定
	a.TimeStartMs = 1
	b.TimeStartMs = 999
	if s.Keep(&a) != s.Keep(&b) {
		t.Fatal("time must not affect decision")
	}
}

func TestSamplerRatio(t *testing.T) {
	// 1000 条互异流，1:10 采样 → 比例接近 0.1（统计性断言，宽松界 0.05–0.2）
	mk := func(i uint32) [16]byte {
		var a [16]byte
		a[12], a[13], a[14], a[15] = byte(i>>24), byte(i>>16), byte(i>>8), byte(i)
		return a
	}
	for mode, sampler := range map[string]Sampler{
		"deterministic": NewSampler(&Resample{Mode: ResampleDeterministic, Rate: 10}),
		"random":        NewSampler(&Resample{Mode: ResampleRandom, Rate: 10}),
	} {
		kept := 0
		const n = 1000
		for i := 0; i < n; i++ {
			r := rec(mk(uint32(i+1)), mk(uint32(i+1000)), 5, 80, 6)
			if sampler.Keep(&r) {
				kept++
			}
		}
		ratio := float64(kept) / n
		if ratio < 0.05 || ratio > 0.2 {
			t.Errorf("%s: kept ratio %.3f out of bounds", mode, ratio)
		}
	}
}

func TestSamplerKeepAll(t *testing.T) {
	s := NewSampler(&Resample{Mode: ResampleRandom, Rate: 1})
	r := rec([16]byte{1}, [16]byte{2}, 1, 2, 6)
	for i := 0; i < 100; i++ {
		if !s.Keep(&r) {
			t.Fatal("rate=1 must keep all")
		}
	}
	if NewSampler(nil).Keep(&r) != true {
		t.Fatal("nil resample keeps all")
	}
}

func TestEffectiveSampleRate(t *testing.T) {
	cases := []struct {
		exp, res, want uint32
	}{
		{1, 10, 10},
		{5, 10, 50},
		{0, 5, 5},
		{3, 1, 3},
		{0xffffffff, 2, 0xffffffff}, // 溢出钳位
	}
	for _, c := range cases {
		if got := EffectiveSampleRate(c.exp, c.res); got != c.want {
			t.Errorf("EffectiveSampleRate(%d,%d) = %d want %d", c.exp, c.res, got, c.want)
		}
	}
}

func TestRandomSamplerDifferentSeeds(t *testing.T) {
	// random 模式不同时刻判定可以不同（非流键函数）——仅烟测不 panic 且产生两种结果可能
	s := NewSampler(&Resample{Mode: ResampleRandom, Rate: 2})
	r := rec([16]byte{9}, [16]byte{9}, 1, 1, 1)
	_ = s.Keep(&r)
	_ = time.Now()
}
