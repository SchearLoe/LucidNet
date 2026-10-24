package decoder

import (
	"net/netip"
	"sync"
	"time"
)

// 模板管理（dd/02 §1 定制点 #1 与 #5）：
//   - 缓存 key = (exporter, observationDomainId, templateId)，模板/采样状态按观测域隔离（#5）；
//   - 模板增删追加写 Kafka flow.templates（compact）+ 本地 WAL，启动重放（#1）。
//     v9 模板默认无超时；IPFIX 模板活跃期可配，默认 24h 重验证。

// TemplateKey —— 观测域隔离键（dd/02 §1 定制点 #5）。
type TemplateKey struct {
	Exporter    netip.Addr
	ObsDomainID uint32
	TemplateID  uint16
}

// Template —— 缓存中的模板。
type Template struct {
	Key       TemplateKey
	Version   uint8 // VersionNetFlowV9 / VersionIPFIX（低 8 位）
	Body      []byte
	UpdatedAt time.Time
	ExpiresAt time.Time // 零值 = 无超时（v9）；IPFIX 活跃期重验证默认 24h（dd/02 §1 #1）
}

// TemplateCache —— 模板缓存接口（v9/IPFIX 解码器持有；进程内 + WAL 恢复）。
type TemplateCache interface {
	Get(key TemplateKey) (Template, bool)
	Put(t Template)
	Delete(key TemplateKey)
	Len() int
}

// MemTemplateCache —— 内存实现（互斥表 + Get 时惰性过期）。
type MemTemplateCache struct {
	mu      sync.RWMutex
	entries map[TemplateKey]Template
	now     func() time.Time // 可注入时钟（测试）
}

// NewMemTemplateCache —— 构造内存模板缓存。
func NewMemTemplateCache() *MemTemplateCache {
	return &MemTemplateCache{entries: make(map[TemplateKey]Template), now: time.Now}
}

// WithClock —— 注入时钟（测试用）。
func (c *MemTemplateCache) WithClock(now func() time.Time) *MemTemplateCache {
	c.now = now
	return c
}

func (c *MemTemplateCache) Get(key TemplateKey) (Template, bool) {
	c.mu.RLock()
	t, ok := c.entries[key]
	c.mu.RUnlock()
	if !ok {
		return Template{}, false
	}
	if !t.ExpiresAt.IsZero() && c.now().After(t.ExpiresAt) {
		c.Delete(key) // 惰性过期（IPFIX 活跃期重验证，dd/02 §1 #1）
		return Template{}, false
	}
	return t, true
}

func (c *MemTemplateCache) Put(t Template) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[t.Key] = t
}

func (c *MemTemplateCache) Delete(key TemplateKey) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.entries, key)
}

func (c *MemTemplateCache) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}

// TemplateEventKind —— 模板生命周期事件类型。
type TemplateEventKind uint8

const (
	TemplateAdded TemplateEventKind = iota + 1
	TemplateRemoved
)

// TemplateEvent —— 模板变更事件 → Kafka flow.templates（proto TemplateRecord：exporter, obs_domain,
// template_id, body, version, ts；docs/09 §2）+ 本地 WAL（dd/02 §1 #1）。
type TemplateEvent struct {
	Kind        TemplateEventKind
	Exporter    string
	ObsDomainID uint32
	TemplateID  uint16
	Version     uint16 // VersionNetFlowV9 / VersionIPFIX
	Body        []byte // 模板集原始字节（TemplateRecord.body）
	TS          time.Time
}

// TemplateWAL —— 模板持久化接口（dd/02 §1 定制点 #1：Kafka compact log + 本地 WAL + 启动重放）。
type TemplateWAL interface {
	Append(ev TemplateEvent) error
	// Replay —— 启动时重放全部事件（旧→新），调用方据此重建内存缓存。
	Replay() ([]TemplateEvent, error)
	Close() error
}

// MemTemplateWAL —— 内存 WAL（开发/单测用；生产为 Kafka + 本地文件，见 wal_kafka.go）。
type MemTemplateWAL struct {
	mu     sync.Mutex
	events []TemplateEvent
}

// NewMemTemplateWAL —— 构造内存 WAL。
func NewMemTemplateWAL() *MemTemplateWAL { return &MemTemplateWAL{} }

func (w *MemTemplateWAL) Append(ev TemplateEvent) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.events = append(w.events, ev)
	return nil
}

func (w *MemTemplateWAL) Replay() ([]TemplateEvent, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := make([]TemplateEvent, len(w.events))
	copy(out, w.events)
	return out, nil
}

func (w *MemTemplateWAL) Close() error { return nil }
