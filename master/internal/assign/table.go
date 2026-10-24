package assign

import (
	"fmt"
	"sort"
	"time"
)

// 分配表与计算（docs/dd/07 §3）：
//
//	输入: exporters[]（活跃，含速率观测）、collectors[]（在线，weight）
//	约束: 单 collector 承载 ≤ 其 weight 份额 × 1.2；超载 exporter（>5w fps）独占绑定
//	输出: AssignTable{version, map[exporter]collector} → etcd /lucid/assign/flow
//	触发: 节点上下线/权重变化/新 exporter 发现/手工 pin；防抖 30s 合并变更

// Options —— 计算与编排参数。
type Options struct {
	Debounce       time.Duration // 变更防抖合并窗口（dd/07 §3：30s）
	OverloadFPS    float64       // 超载 exporter 阈值（dd/07 §3：5w fps）
	CapacityFactor float64       // 容量约束系数（dd/07 §3：×1.2）
	Now            func() time.Time
}

func (o *Options) fill() {
	if o.Debounce <= 0 {
		o.Debounce = 30 * time.Second
	}
	if o.OverloadFPS <= 0 {
		o.OverloadFPS = 50000
	}
	if o.CapacityFactor <= 0 {
		o.CapacityFactor = 1.2
	}
	if o.Now == nil {
		o.Now = time.Now
	}
}

// Entry —— 分配表条目。
type Entry struct {
	Exporter  string `json:"exporter"`
	Collector string `json:"collector"`
	Pinned    bool   `json:"pinned,omitempty"`   // 手工 pin（绕过哈希环）
	Overload  bool   `json:"overload,omitempty"` // 超载独占绑定
}

// Table —— 版本化分配表快照（etcd /lucid/assign/flow 值 = 本结构 JSON）。
type Table struct {
	Version   uint64    `json:"version"`
	UpdatedAt time.Time `json:"updated_at"`
	Entries   []Entry   `json:"entries"`
}

// CollectorOf 查询 exporter 的 collector。
func (t *Table) CollectorOf(exporter string) (string, bool) {
	for _, e := range t.Entries {
		if e.Exporter == exporter {
			return e.Collector, true
		}
	}
	return "", false
}

// Exporter —— 分配输入。
type Exporter struct {
	IP       string
	RateFPS  float64
	PinnedTo string // 手工 pin 的 collector 节点 ID（空=自动）
}

// computePlan —— 单次分配计算（纯函数，便于单测）。
func computePlan(collectors []Collector, exporters []Exporter, opts Options) (map[string]Entry, error) {
	if len(collectors) == 0 {
		if len(exporters) == 0 {
			return map[string]Entry{}, nil // 空集群：空表（版本仍推进）
		}
		return nil, fmt.Errorf("no online collector available")
	}
	out := make(map[string]Entry, len(exporters))
	online := func(id string) bool {
		for _, c := range collectors {
			if c.ID == id {
				return true
			}
		}
		return false
	}

	// ① 手工 pin：目标在线才生效（否则回落哈希环）
	ringExporters := make([]Exporter, 0, len(exporters))
	for _, e := range exporters {
		if e.PinnedTo != "" && online(e.PinnedTo) {
			out[e.IP] = Entry{Exporter: e.IP, Collector: e.PinnedTo, Pinned: true}
			continue
		}
		ringExporters = append(ringExporters, e)
	}

	// ② 超载 exporter（>5w fps）独占绑定：按权重降序，每台 collector 至多 1 个，
	//    被独占的 collector 不再进入哈希环（语义裁定见模块 README）
	overload := make([]Exporter, 0, len(ringExporters))
	normal := make([]Exporter, 0, len(ringExporters))
	for _, e := range ringExporters {
		if e.RateFPS > opts.OverloadFPS {
			overload = append(overload, e)
		} else {
			normal = append(normal, e)
		}
	}
	exclusive := map[string]bool{} // 被超载 exporter 独占的 collector
	if len(overload) > 0 {
		byWeight := append([]Collector(nil), collectors...)
		sort.Slice(byWeight, func(i, j int) bool { return byWeight[i].Weight > byWeight[j].Weight })
		for _, e := range overload {
			for _, c := range byWeight {
				if !exclusive[c.ID] {
					exclusive[c.ID] = true
					out[e.IP] = Entry{Exporter: e.IP, Collector: c.ID, Overload: true}
					break
				}
			}
			// 全部被占用时降级：交由哈希环承载（下一轮 append 到 normal）
			if _, placed := out[e.IP]; !placed {
				normal = append(normal, e)
			}
		}
	}

	// ③ 哈希环（排除独占节点）；无可用环但有 normal 时报错
	ringInput := make([]Collector, 0, len(collectors))
	var totalWeight float64
	for _, c := range collectors {
		if !exclusive[c.ID] {
			ringInput = append(ringInput, c)
			totalWeight += c.Weight
		}
	}
	if len(ringInput) == 0 && len(normal) > 0 {
		return nil, fmt.Errorf("no ring capacity for %d exporters", len(normal))
	}
	ring := NewRing(ringInput)

	// ④ 容量约束：cap_i = ⌈1.2 × N × w_i/Σw⌉；落点超容则顺时针找下一台，全满回落最小负载
	load := make(map[string]int, len(ringInput))
	for _, c := range ringInput {
		share := 0.0
		if totalWeight > 0 {
			share = float64(len(normal)) * c.Weight / totalWeight
		}
		load["cap:"+c.ID] = int(opts.CapacityFactor*share + 0.999)
	}
	for _, e := range normal {
		target := ring.LookupWalk(e.IP, 0)
		for skip := 1; target != "" && load[target] >= load["cap:"+target]; skip++ {
			if skip > len(ringInput) {
				target = ""
				break
			}
			target = ring.LookupWalk(e.IP, skip)
		}
		if target == "" { // 全满：最小负载兜底（容量约束尽力而为）
			target = leastLoaded(ringInput, load)
		}
		load[target]++
		out[e.IP] = Entry{Exporter: e.IP, Collector: target}
	}
	return out, nil
}

func leastLoaded(collectors []Collector, load map[string]int) string {
	best := ""
	bestLoad := int(^uint(0) >> 1)
	for _, c := range collectors {
		if l := load[c.ID]; l < bestLoad {
			best, bestLoad = c.ID, l
		}
	}
	return best
}

// SortEntries 稳定排序（etcd 快照与 WatchAssign 输出确定性）。
func SortEntries(t *Table) {
	sort.Slice(t.Entries, func(i, j int) bool {
		if t.Entries[i].Exporter != t.Entries[j].Exporter {
			return t.Entries[i].Exporter < t.Entries[j].Exporter
		}
		return t.Entries[i].Collector < t.Entries[j].Collector
	})
}
