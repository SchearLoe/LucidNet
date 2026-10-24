// Package hll —— 紧凑 HyperLogLog（dd/03 §3.1/§4.2）：
// 4bit 寄存器两两打包（m=2^14 寄存器仅 8KB），供扫段 per-/24(v4)、/64(v6)
// distinct-dst 判定与 srcAgg 每源目的基数使用。
//
// 设计取舍（骨架范围）：
//   - rho 上限截断到 15（4bit）：true rho>15 对调和均值贡献 <2^-15，
//     引入的误差远小于 HLL 固有误差（m=2^14 时 ≈0.8%），不设溢出表；
//   - 不做中等区间偏差校正（仅小基数线性计数），误差界 1.04/sqrt(m)。
//
// 非并发安全：检测路径单分区单 goroutine（dd/03 §1）。
package hll

import "math"

const (
	// PrecisionDefault —— 扫段 cell 用 2^14 寄存器（dd/03 §4.2 固定 8KB/段）。
	PrecisionDefault uint8 = 14
	// PrecisionTiny —— srcAgg 每源目的基数用（2^6=64 寄存器×4bit=32B/源）。
	PrecisionTiny uint8 = 6

	minPrecision uint8 = 4
	maxPrecision uint8 = 16
)

// Sketch —— 一份 HyperLogLog 概要。
type Sketch struct {
	p    uint8
	m    uint64
	regs []byte // 每 byte 存 2 个 4bit 寄存器（低 nibble=偶数下标）
}

// New 构造指定精度（寄存器数 2^p）的空概要。
func New(p uint8) *Sketch {
	if p < minPrecision {
		p = minPrecision
	}
	if p > maxPrecision {
		p = maxPrecision
	}
	return &Sketch{
		p:    p,
		m:    1 << p,
		regs: make([]byte, (1<<p)/2), // m=2^p 恒为偶数，两寄存器一字节
	}
}

// Precision 返回精度（log2 寄存器数）。
func (s *Sketch) Precision() uint8 { return s.p }

// Registers 返回寄存器数 m。
func (s *Sketch) Registers() int { return int(s.m) }

// Insert 插入一个 64bit 哈希（调用方负责对原始值做 xxhash64 等散列）。
func (s *Sketch) Insert(hash uint64) {
	idx := hash >> (64 - s.p)
	w := hash << s.p // 低 64-p 位，rho 从最高有效位起数
	var rho uint8 = 1
	for rho <= 64-s.p && w&0x8000000000000000 == 0 {
		w <<= 1
		rho++
	}
	if rho > 15 {
		rho = 15 // 4bit 截断，误差见包注释
	}
	s.set(uint16(idx), rho)
}

func (s *Sketch) get(i uint16) uint8 {
	b := s.regs[i/2]
	if i%2 == 0 {
		return b & 0x0f
	}
	return b >> 4
}

func (s *Sketch) set(i uint16, v uint8) {
	if old := s.get(i); old >= v {
		return
	}
	if i%2 == 0 {
		s.regs[i/2] = (s.regs[i/2] & 0xf0) | v
	} else {
		s.regs[i/2] = (s.regs[i/2] & 0x0f) | v<<4
	}
}

// Estimate 返回去重基数估计。
func (s *Sketch) Estimate() float64 {
	zeros := 0
	sum := 0.0
	for i := 0; i < int(s.m); i++ {
		r := s.get(uint16(i))
		if r == 0 {
			zeros++
		}
		sum += 1.0 / float64(uint64(1)<<r)
	}
	if zeros == int(s.m) {
		return 0
	}
	alpha := alphaM(s.m)
	e := alpha * float64(s.m) * float64(s.m) / sum
	if e <= 2.5*float64(s.m) && zeros > 0 {
		// 小基数：线性计数更准
		return float64(s.m) * math.Log(float64(s.m)/float64(zeros))
	}
	return e
}

// Reset 清空全部寄存器（复用内存，扫段 10s 窗翻转用）。
func (s *Sketch) Reset() {
	for i := range s.regs {
		s.regs[i] = 0
	}
}

// alphaM —— HLL 偏差修正常数。
func alphaM(m uint64) float64 {
	switch m {
	case 16:
		return 0.673
	case 32:
		return 0.697
	case 64:
		return 0.709
	default:
		return 0.7213 / (1 + 1.079/float64(m))
	}
}
