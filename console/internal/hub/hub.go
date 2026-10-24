package hub

import "sync"

// Message —— WS 下行信封（字段 proto JSON snake_case，docs/11 §8）。
// topic ∈ alarms | bgp.mitigations（与消费主题同名）；type ∈ alarm|attack|mitigation。
// zone_id 提升到信封层供服务端过滤与前端轻量路由；mitigation 事件按 attack_id
// 关联攻击的 zone（泵侧回填，查不到为 0=广播）。
// 该信封为网关自有 WS 契约（docs/00 §6 定路径未定报文），已列入报告契约登记建议。
type Message struct {
	Topic  string `json:"topic"`
	Type   string `json:"type"`
	ZoneID int32  `json:"zone_id,omitempty"`
	TsMs   int64  `json:"ts_ms"`
	Data   any    `json:"data"`
}

// Client —— 一个 WS 订阅端（单页一条连接，可多路 topic 以 URL 区分）。
type Client struct {
	ZoneID int32 // 0=全部客户域；非 0 服务端过滤（R2 租户/客户域视图）
	Send   chan Message
	done   chan struct{}
	once   sync.Once
}

// NewClient 构造；buf 为发送缓冲（慢客户端超限被丢弃断开，防背压拖垮 hub）。
func NewClient(zoneID int32, buf int) *Client {
	if buf <= 0 {
		buf = 64
	}
	return &Client{ZoneID: zoneID, Send: make(chan Message, buf), done: make(chan struct{})}
}

// Closed 返回关闭信号通道。
func (c *Client) Closed() <-chan struct{} { return c.done }

// Close 关闭客户端（幂等；不 close Send，由读端协程退出）。
func (c *Client) Close() { c.once.Do(func() { close(c.done) }) }

// Hub —— topic 广播中心。publish 单写协程（ingest 泵）调用；
// 注册/注销并发安全。
type Hub struct {
	mu      sync.RWMutex
	clients map[*Client]struct{}
	dropped uint64
}

// NewHub 构造。
func NewHub() *Hub {
	return &Hub{clients: make(map[*Client]struct{})}
}

// Subscribe 注册客户端（立即返回，不阻塞发布方）。
func (h *Hub) Subscribe(c *Client) {
	h.mu.Lock()
	h.clients[c] = struct{}{}
	h.mu.Unlock()
}

// Unsubscribe 注销客户端。
func (h *Hub) Unsubscribe(c *Client) {
	h.mu.Lock()
	delete(h.clients, c)
	h.mu.Unlock()
}

// Publish 按 topic + 客户域过滤广播；缓冲满的客户端丢弃该条（计数），
// 不阻塞发布协程（实时推送优先新数据，doc10 §3.7 断连黄条由前端重连兜底）。
func (h *Hub) Publish(msg Message) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	for c := range h.clients {
		if msg.ZoneID != 0 && c.ZoneID != 0 && c.ZoneID != msg.ZoneID {
			continue
		}
		select {
		case c.Send <- msg:
		default:
			h.dropped++
		}
	}
}

// Count 当前订阅数（健康检查/测试）。
func (h *Hub) Count() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.clients)
}

// Dropped 累计丢弃条数（自监控，Prometheus 接入前先留计数）。
func (h *Hub) Dropped() uint64 {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.dropped
}
