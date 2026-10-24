package forwarder

import (
	"hash/fnv"
	"math/rand/v2"

	"github.com/SchearLoe/lucidnet/shared"
)

// Sampler —— 再采样器（dd/01 §4.1）。
type Sampler interface {
	// Keep 判定单条记录是否保留。
	Keep(rec *shared.FlowRecord) bool
}

// NewSampler —— 按配置构造；rate=1（不采样）返回 keepAll。
func NewSampler(r *Resample) Sampler {
	if r == nil || r.Rate <= 1 {
		return keepAll{}
	}
	switch r.Mode {
	case ResampleDeterministic:
		return &deterministicSampler{rate: uint64(r.Rate)}
	default:
		return &randomSampler{rate: r.Rate}
	}
}

type keepAll struct{}

func (keepAll) Keep(*shared.FlowRecord) bool { return true }

// deterministicSampler —— hash(流键 5 元组+proto) % rate == 0 保留（FNV-1a 64bit，
// dd/01 §4.1：流键不含时间，保证同一流在多次转发中判定一致、下游聚合无偏）。
type deterministicSampler struct {
	rate uint64
}

// Keep 实现 Sampler。
func (s *deterministicSampler) Keep(rec *shared.FlowRecord) bool {
	h := fnv.New64a()
	h.Write(rec.SrcIP[:])
	h.Write(rec.DstIP[:])
	var b [8]byte
	le := func(v uint32) { b[0], b[1], b[2], b[3] = byte(v), byte(v>>8), byte(v>>16), byte(v>>24) }
	le(rec.SrcPort)
	h.Write(b[:4])
	le(rec.DstPort)
	h.Write(b[:4])
	le(rec.Proto)
	h.Write(b[:4])
	sum := h.Sum64()
	// FNV-1a 低位分布弱（低位 XOR 线性），取模前做 64bit 折叠改善均匀性；
	// 折叠为纯函数，仍满足"同流同判"（dd/01 §4.1）。
	sum ^= sum >> 32
	return sum%s.rate == 0
}

// randomSampler —— 每条记录 rand() < 1/rate 保留（dd/01 §4.1：实现最简，短流方差大）。
type randomSampler struct {
	rate uint32
}

// Keep 实现 Sampler。
func (s *randomSampler) Keep(*shared.FlowRecord) bool {
	return rand.Uint64()%uint64(s.rate) == 0
}

// EffectiveSampleRate —— effective_sample_rate = exporter_sample_rate × resample_rate（dd/01 §4.1），
// 溢出钳位 uint32。
func EffectiveSampleRate(exporterRate, resampleRate uint32) uint32 {
	if resampleRate <= 1 {
		return exporterRate
	}
	if exporterRate == 0 {
		exporterRate = 1
	}
	prod := uint64(exporterRate) * uint64(resampleRate)
	if prod > 0xffffffff {
		return 0xffffffff
	}
	return uint32(prod)
}
