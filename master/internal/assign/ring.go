package assign

import (
	"sort"
)

// 一致性哈希环（docs/dd/07 §3）：
//
//	每物理节点 vnode = 160 × weight；hash(exporter_ip) 顺时针落环。
//	节点增减仅迁移 ~1/N exporter。

// vnodeFactor —— 每单位权重虚拟节点数。
const vnodeFactor = 160

// Collector —— 哈希环输入。
type Collector struct {
	ID     string
	Weight float64
}

// ringPoint —— 环上一点。
type ringPoint struct {
	hash      uint64
	collector string
}

// Ring —— 哈希环。
type Ring struct {
	points []ringPoint
}

// NewRing 构建哈希环（weight ≤0 的节点忽略；vnode 数下限 1）。
func NewRing(collectors []Collector) *Ring {
	r := &Ring{}
	for _, c := range collectors {
		w := c.Weight
		if w <= 0 {
			w = 0.05
		}
		vnodes := int(vnodeFactor * w)
		if vnodes < 1 {
			vnodes = 1
		}
		for i := 0; i < vnodes; i++ {
			r.points = append(r.points, ringPoint{
				hash:      fnv1a64(c.ID + "#" + itoa(i)),
				collector: c.ID,
			})
		}
	}
	sort.Slice(r.points, func(i, j int) bool { return r.points[i].hash < r.points[j].hash })
	return r
}

// Lookup 顺时针查找（环空返回 ""）。
func (r *Ring) Lookup(key string) string {
	if len(r.points) == 0 {
		return ""
	}
	h := fnv1a64(key)
	idx := sort.Search(len(r.points), func(i int) bool { return r.points[i].hash >= h })
	if idx == len(r.points) {
		idx = 0
	}
	return r.points[idx].collector
}

// LookupWalk 从 key 落点出发顺时针返回第 skip 个不同的 collector
// （容量溢出/超载独占绑定时找下一个候选用；skip=0 即普通 Lookup；
// skip ≥ 环上 collector 数时返回 ""）。
func (r *Ring) LookupWalk(key string, skip int) string {
	if len(r.points) == 0 {
		return ""
	}
	set := map[string]bool{}
	for i := range r.points {
		set[r.points[i].collector] = true
	}
	distinct := len(set)
	if skip < 0 || skip >= distinct {
		return ""
	}
	h := fnv1a64(key)
	idx := sort.Search(len(r.points), func(i int) bool { return r.points[i].hash >= h })
	seen := ""
	visited := 0
	for n := 0; n < len(r.points) && visited < distinct; n++ {
		p := r.points[(idx+n)%len(r.points)]
		if p.collector == seen {
			continue
		}
		seen = p.collector
		if visited == skip {
			return p.collector
		}
		visited++
	}
	return ""
}

// Empty 环是否为空。
func (r *Ring) Empty() bool { return r == nil || len(r.points) == 0 }

// fnv1a64 —— FNV-1a 64bit（与 dd/01 §4.1 Broker 采样哈希同族：快、够散）。
func fnv1a64(s string) uint64 {
	const (
		offset64 = 14695981039346656037
		prime64  = 1099511628211
	)
	h := uint64(offset64)
	for i := 0; i < len(s); i++ {
		h ^= uint64(s[i])
		h *= prime64
	}
	return h
}

func itoa(i int) string {
	// 小整数快速转十进制（vnode 序号）
	if i == 0 {
		return "0"
	}
	var buf [20]byte
	pos := len(buf)
	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}
	return string(buf[pos:])
}
