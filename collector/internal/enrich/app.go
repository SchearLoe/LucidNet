package enrich

import "sync"

// AppMapper —— 应用映射（dd/02 §3.2：{proto,port}→app_id 静态表，PG 下发 ≤1 万条）。
// port 取五元组目的端口（服务端语义：按被访问服务归类）。
type AppMapper interface {
	AppID(proto, port uint32) uint32
}

// appKey —— 映射键。
type appKey struct {
	proto uint32
	port  uint32
}

// AppTable —— 静态表开发实现。
//
// TODO(apptable)：PG 下发 + 变更推送；查表换 LRU 数组直查（dd/02 §3.2，
// 1 万条规模 map 读亦在预算内，生产换无锁结构时按 dd/02 口径）。
type AppTable struct {
	mu sync.RWMutex
	m  map[appKey]uint32
}

// NewAppTable —— 构造空表。
func NewAppTable() *AppTable { return &AppTable{m: make(map[appKey]uint32)} }

// Set —— 注入一条映射（配置下发/测试用）。
func (a *AppTable) Set(proto, port, appID uint32) {
	a.mu.Lock()
	a.m[appKey{proto: proto, port: port}] = appID
	a.mu.Unlock()
}

// Replace —— 全量替换（PG 静态表重下发）。
func (a *AppTable) Replace(m map[appKey]uint32) {
	a.mu.Lock()
	a.m = m
	a.mu.Unlock()
}

// AppID —— 查表；未命中 0（应用未知）。
func (a *AppTable) AppID(proto, port uint32) uint32 {
	a.mu.RLock()
	id := a.m[appKey{proto: proto, port: port}]
	a.mu.RUnlock()
	return id
}
