package flowcodec

import (
	"sync"
	"time"
)

// TemplateCache —— NetFlow v9 / IPFIX 解码侧模板缓存（任务一，dd/01 §4）：
// 模板按 (exporter, source_id/observation_domain, template_id) 三元组作用域
// （RFC 3954 §5.5 / RFC 7011 §3.4.1）；数据集先于模板到达时跳过计数，
// 同包或后续包内的模板集学习后即可解码；模板按超时老化（exporter 刷新周期
// ≤600s，RFC 7011 §10.3.7，老化取 3× 余量），防炸地上限内挤掉最旧。
//
// 并发模型：引擎收包路径可能多 worker 并发解码同一缓存，互斥锁保护；
// 学习/查找为 O(1)，老化惰性触发（按 maxAge/4 节流），不得阻塞热路径。
type TemplateCache struct {
	mu    sync.Mutex
	byKey map[TemplateKey]*TemplateDef

	anchors map[anchorKey]*anchorEntry // systemInitTimeMilliseconds(160) 锚点（IPFIX 相对时间换算）

	rates map[anchorKey]*anchorEntry // options 集学习的全局采样间隔（IE 34/305，数据记录缺省回退）

	maxAge    time.Duration // 模板老化周期
	maxCount  int           // 模板条数上限（防伪造模板炸内存）
	lastSweep time.Time
	now       func() time.Time
}

// TemplateKey —— 模板作用域键（docs/11 §3：英文命名）。
type TemplateKey struct {
	Exporter   string
	ObsDomain  uint32
	TemplateID uint16
}

// anchorKey —— 系统启动锚点作用域（exporter+obsDomain）。
type anchorKey struct {
	Exporter  string
	ObsDomain uint32
}

type anchorEntry struct {
	bootMs int64
	seen   time.Time
}

// TemplateField —— 模板内单字段说明符（RFC 7011 §3.2）。
type TemplateField struct {
	IE     uint16
	Length uint16 // 65535=变长（RFC 7011 §7.1.2）
	// Enterprise 非 0 表示 vendor PEN 字段（说明符带 enterprise 位 + 4B PEN），
	// 解码时仅消费数据不映射语义（docs/00 统一记录无私有 IE 表达域）。
	Enterprise uint32
}

// TemplateDef —— 已学习模板。
type TemplateDef struct {
	Fields          []TemplateField
	ScopeFieldCount int  // options 模板：scope 字段数（数据模板恒 0）
	IsOptions       bool // options 模板（set id 1/3）

	seen time.Time // 学习/使用时刻（老化与挤淘汰基准）
}

// 模板缓存缺省参数（RFC 7011 §10.3.7：刷新 ≤600s → 老化 30min 取 3× 余量）。
const (
	DefaultTemplateMaxAge   = 30 * time.Minute
	DefaultTemplateMaxCount = 16384
)

// NewTemplateCache 构造解码侧模板缓存（maxAge≤0 取默认；now 可注入测试时钟）。
func NewTemplateCache(maxAge time.Duration, maxCount int, now func() time.Time) *TemplateCache {
	if maxAge <= 0 {
		maxAge = DefaultTemplateMaxAge
	}
	if maxCount <= 0 {
		maxCount = DefaultTemplateMaxCount
	}
	if now == nil {
		now = time.Now
	}
	return &TemplateCache{
		byKey:    map[TemplateKey]*TemplateDef{},
		anchors:  map[anchorKey]*anchorEntry{},
		rates:    map[anchorKey]*anchorEntry{},
		maxAge:   maxAge,
		maxCount: maxCount,
		now:      now,
	}
}

// Lookup 查模板并刷新使用时刻（nil 缓存安全：恒 miss）。
func (c *TemplateCache) Lookup(exporter string, obsDomain uint32, id uint16) *TemplateDef {
	if c == nil {
		return nil
	}
	now := c.now()
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sweepLocked(now)
	key := TemplateKey{Exporter: exporter, ObsDomain: obsDomain, TemplateID: id}
	def, ok := c.byKey[key]
	if !ok || now.Sub(def.seen) > c.maxAge {
		delete(c.byKey, key) // 过期即删：数据集按模板缺失跳过，等重学
		return nil
	}
	def.seen = now // 使用即续期（活跃 exporter 不被误老化）
	return def
}

// Learn 学习/刷新模板（数据模板 ID <256 非法拒学，RFC 7011 §3.4.1）。
// 返回新学/刷新的模板数（打点用）。nil 缓存安全：no-op。
func (c *TemplateCache) Learn(exporter string, obsDomain uint32, id uint16, def *TemplateDef) int {
	if c == nil || def == nil || id < 256 {
		return 0
	}
	now := c.now()
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sweepLocked(now)
	key := TemplateKey{Exporter: exporter, ObsDomain: obsDomain, TemplateID: id}
	if _, exists := c.byKey[key]; !exists && len(c.byKey) >= c.maxCount {
		c.evictOldestLocked() // 容量兜底：满则挤最旧，绝不让 map 无界增长
	}
	def.seen = now
	c.byKey[key] = def
	return 1
}

// Withdraw 撤回模板（IPFIX 模板集 field_count=0，RFC 7011 §3.4.1）。
func (c *TemplateCache) Withdraw(exporter string, obsDomain uint32, id uint16) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.byKey, TemplateKey{Exporter: exporter, ObsDomain: obsDomain, TemplateID: id})
}

// SetAnchor 记录 systemInitTimeMilliseconds(160)（IPFIX 相对时间基准，RFC 7011 §8.4）。
func (c *TemplateCache) SetAnchor(exporter string, obsDomain uint32, bootMs int64) {
	if c == nil || bootMs <= 0 {
		return
	}
	c.mu.Lock()
	c.anchors[anchorKey{Exporter: exporter, ObsDomain: obsDomain}] = &anchorEntry{bootMs: bootMs, seen: c.now()}
	c.mu.Unlock()
}

// Anchor 取系统启动锚点（未学习返回 false）。
func (c *TemplateCache) Anchor(exporter string, obsDomain uint32) (int64, bool) {
	if c == nil {
		return 0, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.anchors[anchorKey{Exporter: exporter, ObsDomain: obsDomain}]
	if !ok {
		return 0, false
	}
	e.seen = c.now()
	return e.bootMs, true
}

// SetSampleRate 记录 options 集（IE samplingInterval/samplingPacketInterval）学习的
// 该 observation domain 全局采样间隔，数据记录未带采样 IE 时回退使用。
func (c *TemplateCache) SetSampleRate(exporter string, obsDomain uint32, rate uint32) {
	if c == nil || rate == 0 {
		return
	}
	c.mu.Lock()
	c.rates[anchorKey{Exporter: exporter, ObsDomain: obsDomain}] = &anchorEntry{bootMs: int64(rate), seen: c.now()}
	c.mu.Unlock()
}

// SampleRate 取 options 学习的采样间隔（未学习返回 false）。
func (c *TemplateCache) SampleRate(exporter string, obsDomain uint32) (uint32, bool) {
	if c == nil {
		return 0, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.rates[anchorKey{Exporter: exporter, ObsDomain: obsDomain}]
	if !ok {
		return 0, false
	}
	e.seen = c.now()
	return uint32(e.bootMs), true
}

// Len 当前模板数（自监控/测试）。
func (c *TemplateCache) Len() int {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.byKey)
}

// sweepLocked —— 惰性老化（按 maxAge/4 节流，均摊 O(n) 且不阻塞热路径）。
func (c *TemplateCache) sweepLocked(now time.Time) {
	if !c.lastSweep.IsZero() && now.Sub(c.lastSweep) < c.maxAge/4 {
		return
	}
	c.lastSweep = now
	for k, def := range c.byKey {
		if now.Sub(def.seen) > c.maxAge {
			delete(c.byKey, k)
		}
	}
	for k, e := range c.anchors { // 锚点/采样率随自身空闲加倍老化
		if now.Sub(e.seen) > c.maxAge*2 {
			delete(c.anchors, k)
		}
	}
	for k, e := range c.rates {
		if now.Sub(e.seen) > c.maxAge*2 {
			delete(c.rates, k)
		}
	}
}

// evictOldestLocked —— 容量满时挤掉最旧一条（线性扫描；仅伪造模板轰炸场景可达，
// 正常流 maxCount 内不可达）。
func (c *TemplateCache) evictOldestLocked() {
	var oldestKey TemplateKey
	var oldest time.Time
	first := true
	for k, def := range c.byKey {
		if first || def.seen.Before(oldest) {
			oldestKey, oldest, first = k, def.seen, false
		}
	}
	if !first {
		delete(c.byKey, oldestKey)
	}
}
