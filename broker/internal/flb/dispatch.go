package flb

import (
	"context"
	"errors"
	"hash/fnv"
	"net"
	"sync"
	"time"
)

// Counters —— FLB 打点接口（internal/metrics 实现）。
type Counters interface {
	FlbForwarded(n int)
	FlbDrop(n int)
	FlbUnknownExporter()
	SetCollectorHealth(addr string, up bool)
}

// NoopCounters —— 空实现。
type NoopCounters struct{}

func (NoopCounters) FlbForwarded(int)                {}
func (NoopCounters) FlbDrop(int)                     {}
func (NoopCounters) FlbUnknownExporter()             {}
func (NoopCounters) SetCollectorHealth(string, bool) {}

// Dispatcher —— 收包路径 FLB 转发器（dd/01 §2）：查表 → 哈希兜底 → connected UDP 写出。
// 纯 UDP 转发 + 一次 map 查表（~700ns/包预算），同步写、无队列跳数。
type Dispatcher struct {
	table    TablePtr
	health   *Health
	defaults []string // 分配表为空时的兜底 collector（本模块引导配置）
	counters Counters

	mu      sync.Mutex
	sockets map[string]*net.UDPConn
}

// NewDispatcher 构造。
func NewDispatcher(defaults []string, health *Health, counters Counters) *Dispatcher {
	if counters == nil {
		counters = NoopCounters{}
	}
	if health == nil {
		health = NewHealth(0, 0, nil)
	}
	return &Dispatcher{
		health:   health,
		defaults: defaults,
		counters: counters,
		sockets:  map[string]*net.UDPConn{},
	}
}

// Table 访问原子表指针（admin watch 写入）。
func (d *Dispatcher) Table() *TablePtr { return &d.table }

// Health 访问健康态（探活写入）。
func (d *Dispatcher) Health() *Health { return d.health }

// Forward —— 单个流报文转发（热路径；datagram 归调用方，写为同步语义）。
func (d *Dispatcher) Forward(datagram []byte, exporter string) {
	addr := d.choose(exporter)
	if addr == "" {
		d.counters.FlbDrop(1)
		return
	}
	conn := d.socketFor(addr)
	if conn == nil {
		d.counters.FlbDrop(1)
		return
	}
	if _, err := conn.Write(datagram); err != nil {
		// ICMP 不可达等即时错误：计失败并重建 socket（清除 sticky 错误态）
		d.health.RecordFail(addr, time.Now())
		d.dropSocket(addr)
		d.counters.FlbDrop(1)
		return
	}
	d.health.RecordOK(addr)
	d.counters.FlbForwarded(1)
}

// choose —— 选路：分配表精确命中（健康）→ 本地摘除兜底哈希 → 未知 exporter 哈希（dd/01 §2.3/2.4）。
func (d *Dispatcher) choose(exporter string) string {
	t := d.table.Load()
	candidates := t.Collectors()
	if len(candidates) == 0 {
		candidates = d.defaults
	}
	if len(candidates) == 0 {
		return ""
	}
	if assigned, ok := t.Assigned(exporter); ok {
		if d.health.IsHealthy(assigned, time.Now()) {
			return assigned
		}
		// 本地摘除兜底：从健康候选中哈希重选（Master 稍后纠偏）
		if c := pickHealthy(candidates, exporter, d.health, time.Now()); c != "" {
			return c
		}
		return "" // 全部不健康：丢弃（保底语义，等待探活恢复）
	}
	// 未知 exporter（表未覆盖新设备）：哈希落任意 collector + 告警打点（dd/01 §2.4）
	d.counters.FlbUnknownExporter()
	return pickHealthy(candidates, exporter, d.health, time.Now())
}

// pickHealthy —— FNV-1a 32(exporter) 在健康候选中取模（一致性哈希由 Master 侧实现，
// Broker 只查表+兜底哈希，dd/01 §2.2）。
func pickHealthy(candidates []string, exporter string, h *Health, now time.Time) string {
	if len(candidates) == 0 {
		return ""
	}
	start := int(fnv32(exporter) % uint32(len(candidates)))
	for i := 0; i < len(candidates); i++ {
		c := candidates[(start+i)%len(candidates)]
		if h.IsHealthy(c, now) {
			return c
		}
	}
	return ""
}

func fnv32(s string) uint32 {
	h := fnv.New32a()
	_, _ = h.Write([]byte(s))
	return h.Sum32()
}

// socketFor —— 每 collector 一个 connected UDP socket（并发写安全；错误后重建）。
func (d *Dispatcher) socketFor(addr string) *net.UDPConn {
	d.mu.Lock()
	defer d.mu.Unlock()
	if conn, ok := d.sockets[addr]; ok {
		return conn
	}
	conn, err := net.Dial("udp", addr)
	if err != nil {
		return nil
	}
	udp, ok := conn.(*net.UDPConn)
	if !ok {
		_ = conn.Close()
		return nil
	}
	d.sockets[addr] = udp
	return udp
}

func (d *Dispatcher) dropSocket(addr string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if conn, ok := d.sockets[addr]; ok {
		_ = conn.Close()
		delete(d.sockets, addr)
	}
}

// Close 关停全部 socket。
func (d *Dispatcher) Close() {
	d.mu.Lock()
	defer d.mu.Unlock()
	for addr, conn := range d.sockets {
		_ = conn.Close()
		delete(d.sockets, addr)
	}
}

// —— 探活（dd/01 §2.3：1s 间隔，3 次失败摘除） ——

// Prober —— collector 探活循环。
type Prober struct {
	d        *Dispatcher
	interval time.Duration
	timeout  time.Duration
}

// NewProber 构造（interval≤0 取 1s）。
func NewProber(d *Dispatcher, interval time.Duration) *Prober {
	if interval <= 0 {
		interval = time.Second
	}
	return &Prober{d: d, interval: interval, timeout: 500 * time.Millisecond}
}

// Run —— 探活主循环（ctx 取消退出）。探测载荷 = count=0 的 v5 头（24B），
// collector 解码语义为空流集，无副作用。
func (p *Prober) Run(ctx context.Context) {
	probe := make([]byte, 24)
	probe[0], probe[1] = 0x00, 0x05 // version=5, count=0
	t := time.NewTicker(p.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			p.round(probe)
		}
	}
}

// round —— 一轮探测：候选 = 分配表 ∪ 兜底列表。
func (p *Prober) round(probe []byte) {
	t := p.d.table.Load()
	seen := make(map[string]struct{})
	var addrs []string
	add := func(list []string) {
		for _, a := range list {
			if a == "" {
				continue
			}
			if _, dup := seen[a]; dup {
				continue
			}
			seen[a] = struct{}{}
			addrs = append(addrs, a)
		}
	}
	add(t.Collectors())
	add(p.d.defaults)
	for _, addr := range addrs {
		if p.probeOne(addr, probe) {
			p.d.health.RecordOK(addr)
		} else {
			p.d.health.RecordFail(addr, time.Now())
		}
	}
}

// probeOne —— 单点探测：connected UDP 写 + 短读排空 ICMP 错误。
func (p *Prober) probeOne(addr string, probe []byte) bool {
	conn, err := net.Dial("udp", addr)
	if err != nil {
		return false
	}
	defer conn.Close() //nolint:errcheck // 探测短连接
	_ = conn.SetWriteDeadline(time.Now().Add(p.timeout))
	if _, err := conn.Write(probe); err != nil {
		return false
	}
	_ = conn.SetReadDeadline(time.Now().Add(p.timeout))
	buf := make([]byte, 1)
	if _, err := conn.Read(buf); err != nil {
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			return true // 超时=无 ICMP 拒绝，视为可达（UDP 无应用层应答）
		}
		return false // connection refused 等即时错误
	}
	return true
}
