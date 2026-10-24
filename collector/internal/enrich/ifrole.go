package enrich

import "sync/atomic"

// IfRole —— 接口角色枚举（dd/02 §5.2 接口角色识别引擎输出；语义对照 docs/09 §3）。
// 识别优先级 manual > LLDP > IGP 邻接 > 命名规则 > 默认，见 dd/02 §5.2 优先级表。
type IfRole uint8

const (
	// IfRoleUnknown —— 未识别：按 boundary 处理（宁可多算，UI 标“待确认”，dd/02 §3.4）。
	IfRoleUnknown IfRole = iota
	// IfRoleBoundary —— 客户/边界接口。
	IfRoleBoundary
	// IfRoleInternal —— 互联接口。
	IfRoleInternal
)

// String —— 配置/日志文本。
func (r IfRole) String() string {
	switch r {
	case IfRoleBoundary:
		return "boundary"
	case IfRoleInternal:
		return "internal"
	default:
		return "unknown"
	}
}

// IfRef —— 接口引用（device_id + ifIndex，SNMP ifIndex 命名空间，dd/02 §3.4）。
type IfRef struct {
	DeviceID uint32
	IfIndex  uint32
}

// IfRoleSource —— 接口角色快照源（dd/02 §3.4：PG interfaces 快照，
// 键 = device_id + ifIndex，与流记录 in_if/out_if 同命名空间对齐）。
type IfRoleSource interface {
	Role(deviceID, ifIndex uint32) IfRole
}

// IfRoleSnapshot —— 接口角色快照（PG interfaces 镜像；etcd 推送，dd/02 §5.2）。
// 不可变整表 + 原子换指针（copy-on-write，热更新语义同 zone.Matcher）。
type IfRoleSnapshot struct {
	table atomic.Pointer[map[IfRef]IfRole]
}

// NewIfRoleSnapshot —— 构造空快照（全部 unknown → 按 boundary，docs/09 §3）。
func NewIfRoleSnapshot() *IfRoleSnapshot {
	s := &IfRoleSnapshot{}
	empty := make(map[IfRef]IfRole)
	s.table.Store(&empty)
	return s
}

// Update —— 全量换表（旧引用上的查询不受影响）。
func (s *IfRoleSnapshot) Update(roles map[IfRef]IfRole) {
	m := make(map[IfRef]IfRole, len(roles))
	for k, v := range roles {
		m[k] = v
	}
	s.table.Store(&m)
}

// Role —— 查询；缺失 = unknown（调用方按 boundary 落位图，docs/09 §3）。
func (s *IfRoleSnapshot) Role(deviceID, ifIndex uint32) IfRole {
	m := s.table.Load()
	if r, ok := (*m)[IfRef{DeviceID: deviceID, IfIndex: ifIndex}]; ok {
		return r
	}
	return IfRoleUnknown
}

// roleBit —— 单接口角色 → 对应 boundary 位（unknown 按 boundary，docs/09 §3）。
// bit 位置语义 = shared.IfRoleInBoundary / shared.IfRoleOutBoundary（FlowRecord.IfRole 位图）。
func roleBit(role IfRole, boundaryBit uint8) uint8 {
	if role == IfRoleInternal {
		return 0
	}
	return boundaryBit // boundary 与 unknown 均置位
}
