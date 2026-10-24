package detector

import (
	"sort"

	"github.com/SchearLoe/lucidnet/analytics/internal/hll"
	"github.com/SchearLoe/lucidnet/shared"
)

// SrcStats —— srcAgg 每源统计（dd/03 §3.1：pkts, bytes, dstIPs(HLL4), ports(set16)）。
type SrcStats struct {
	SrcIP  [16]byte // 保留原始地址：Top 源证据输出（hash 不可逆）
	Pkts   uint64
	Bytes  uint64
	DstIPs *hll.Sketch // p=6 每源目的基数（32B/源）
	Ports  PortSet16   // 最多 16 个不同目的端口
}

// PortSet16 —— 定容 16 的目的端口集合（dd/03 §3.1 ports(set16)）。
type PortSet16 struct {
	ports [16]uint32
	n     int
}

// Add 记录端口；集合满后仅去重不计新（端口离散度近似）。
func (p *PortSet16) Add(port uint32) {
	for i := 0; i < p.n; i++ {
		if p.ports[i] == port {
			return
		}
	}
	if p.n < len(p.ports) {
		p.ports[p.n] = port
		p.n++
	}
}

// Ports 返回已见端口副本。
func (p *PortSet16) Ports() []uint32 { return p.ports[:p.n] }

// CountMinSketch —— srcAgg 超 50,000 源降级结构接口
// （dd/03 §3.1：CM16×65536，精度 1%）。
type CountMinSketch interface {
	Add(srcHash uint64, pkts, bytes uint64)
	EstimatePkts(srcHash uint64) uint64
	EstimateBytes(srcHash uint64) uint64
}

// cmsStub —— 降级桩：TODO(dd/03 §3.1) M2 实现紧凑 CM（16 行 × 65536 列，≈1MB/zone）。
// 当前仅保证接口与降级路径正确，估计值恒 0。
type cmsStub struct{}

// NewCountMinSketchStub —— 降级桩构造（M2 替换为真实现）。
func NewCountMinSketchStub() CountMinSketch { return cmsStub{} }

func (cmsStub) Add(uint64, uint64, uint64)  {}
func (cmsStub) EstimatePkts(uint64) uint64  { return 0 }
func (cmsStub) EstimateBytes(uint64) uint64 { return 0 }

// srcAdd —— 每源统计追加；超上限的新源降级进 CMS 桩（原有源继续精算）。
// 返回 true 表示本次发生降级。
func (z *zoneState) srcAdd(rec *shared.FlowRecord) bool {
	h := srcHash(rec)
	if s, ok := z.srcAgg[h]; ok {
		s.Pkts += rec.Packets
		s.Bytes += rec.Bytes
		s.DstIPs.Insert(dstHash(rec))
		if rec.Proto == protoTCP || rec.Proto == protoUDP {
			s.Ports.Add(rec.DstPort)
		}
		return false
	}
	if len(z.srcAgg) >= z.srcAggCap {
		z.srcOverflow = true
		z.cms.Add(h, rec.Packets, rec.Bytes) // TODO(dd/03 §3.1)：M2 CM 实现后接证据输出
		return true
	}
	s := &SrcStats{
		SrcIP:  rec.SrcIP,
		Pkts:   rec.Packets,
		Bytes:  rec.Bytes,
		DstIPs: hll.New(hll.PrecisionTiny),
	}
	s.DstIPs.Insert(dstHash(rec))
	if rec.Proto == protoTCP || rec.Proto == protoUDP {
		s.Ports.Add(rec.DstPort)
	}
	z.srcAgg[h] = s
	return false
}

// SrcTop —— Top 源证据条目。
type SrcTop struct {
	IP    [16]byte
	Pkts  uint64
	Bytes uint64
}

// topSources —— 按 Pkts 取前 n 源（攻击证据，≤100，dd/03 §6.1）。
func (z *zoneState) topSources(n int) []SrcTop {
	all := make([]SrcTop, 0, len(z.srcAgg))
	for _, s := range z.srcAgg {
		all = append(all, SrcTop{IP: s.SrcIP, Pkts: s.Pkts, Bytes: s.Bytes})
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].Pkts != all[j].Pkts {
			return all[i].Pkts > all[j].Pkts
		}
		return srcIPLess(all[i].IP, all[j].IP)
	})
	if len(all) > n {
		all = all[:n]
	}
	return all
}

func srcIPLess(a, b [16]byte) bool {
	for i := 0; i < 16; i++ {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return false
}
