// Package shared —— LucidNet 跨模块共享契约（结构体镜像 + 常量）。
// proto/ 为线格式权威（codegen 待 CI 接入 protoc/buf）；本包结构体字段与
// proto/lucidnet/v1 一一对应，语义以 docs/09-模块间接口契约.md 为准。
package shared

// FlowRecord —— proto/lucidnet/v1/flowrecord.proto 的 Go 镜像（flows.raw 消息体）
type FlowRecord struct {
	TimeStartMs int64
	TimeEndMs   int64
	Exporter    string
	DeviceID    uint32
	InIf        uint32
	OutIf       uint32
	SrcIP       [16]byte // IPv4 用 ::ffff: 映射
	DstIP       [16]byte
	SrcPort     uint32
	DstPort     uint32
	Proto       uint32
	IPVersion   uint32 // 4/6
	Packets     uint64
	Bytes       uint64
	TCPFlags    uint32
	TOS         uint32
	SampleRate  uint32 // 全链路采样率倒数，1=全采
	SrcAS       uint32
	DstAS       uint32
	BGPNextHop  [16]byte
	SrcGeo      uint32
	DstGeo      uint32
	AppID       uint32
	ZoneID      int32  // 0=未命中；一条记录只标一个客户域（09 §3）
	IfRole      uint8  // IfRole 位图
	ZoneSide    uint8  // ZoneSide 枚举；方向推导唯一依据（09 §3）
}

// ZoneSide —— zone_side 字段枚举（09 §3 裁定）
type ZoneSide uint8

const (
	ZoneSideNone ZoneSide = 0 // 未命中
	ZoneSideDst  ZoneSide = 1 // dst 命中 → 客户视角 in（流入客户）
	ZoneSideSrc  ZoneSide = 2 // src 命中 → 客户视角 out（客户发出）
)

// IfRole —— if_role 位图（09 §3：unknown 按 boundary；互联过滤 = in 与 out 均 internal 才丢弃）
const (
	IfRoleInBoundary  uint8 = 1 << 0 // bit0 入接口 boundary
	IfRoleOutBoundary uint8 = 1 << 1 // bit1 出接口 boundary
)

// InternalFilterDrop —— 互联过滤裁定（09 §9-④）：仅 in 与 out 均为 internal（两位均 0）才丢弃
func InternalFilterDrop(ifRole uint8) bool {
	return ifRole&(IfRoleInBoundary|IfRoleOutBoundary) == 0
}

// Direction —— 客户视角方向（AggrRow.direction；由 ZoneSide 推导，禁用 ifIndex 二次推断）
type Direction uint8

const (
	DirUnknown Direction = 0
	DirIn      Direction = 1
	DirOut     Direction = 2
	DirIntra   Direction = 3
)

// DirectionFromZoneSide —— 09 §3：1→in，2→out，0→unknown
func DirectionFromZoneSide(z ZoneSide) Direction {
	switch z {
	case ZoneSideDst:
		return DirIn
	case ZoneSideSrc:
		return DirOut
	default:
		return DirUnknown
	}
}
