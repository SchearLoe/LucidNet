// Package zone —— 双栈 Zone 匹配器（R2 关键路径，dd/02 §3.3）。
//
// 数据结构两级（dd/02 §3.3）：单 IP（掩码全长）哈希表 + v4/v6 两棵 radix 树（前缀 LPM）。
// 热更新 = 全量重建快照 + copy-on-write 原子换指针（etcd watch 投递 → ≤2s 生效，docs/09 §5）。
//
// 语义唯一权威 docs/09 §3：
//   - zone_match=dst|src（默认 dst，禁止 both）；
//   - 一条记录只标一个客户域，zone_id=0 表示未命中；
//   - zone_side（1=dst 命中 / 2=src 命中）是下游方向换算的唯一依据。
package zone

import "errors"

// ErrInvalidSpec —— Zone 配置非法（id 非法、掩码越界等）。
var ErrInvalidSpec = errors.New("invalid zone spec")

// ZoneSpec —— proto/lucidnet/v1/zone.proto `ZoneSpec` 的 Go 镜像（etcd /lucid/zones，docs/09 §5）。
// shared/ 暂无 Zone 镜像结构，按模块边界在本包定义；proto 为线格式权威（字段只增不改不删）。
type ZoneSpec struct {
	ID          int32 // zone_id；>0（0 = 未命中保留值，docs/09 §3）
	Name        string
	Tenant      string
	IPs         []IPEntry // ≤1000 条/客户；重叠由 Master 保存时校验禁止，采集侧按“取小 id”兜底（dd/02 §3.3）
	BoundaryIFs []DeviceIf
	PolicyID    int32 // 检测策略模板
}

// IPEntry —— proto/lucidnet/v1/zone.proto `IpEntry` 镜像。
type IPEntry struct {
	Prefix  [16]byte // 16B 地址（IPv4 用 ::ffff:a.b.c.d 映射表示）
	MaskLen int32    // v4: 0-32, v6: 0-128；单 IP = 全长度掩码
}

// DeviceIf —— proto/lucidnet/v1/zone.proto `DeviceIf` 镜像。
type DeviceIf struct {
	DeviceID uint32
	IfIndex  uint32
}
