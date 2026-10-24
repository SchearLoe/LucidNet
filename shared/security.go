package shared

// 攻击与告警枚举（docs/00 §2.3/§2.4 契约镜像）

type AttackType uint32

const (
	AttackSYNFlood   AttackType = 1
	AttackUDPFlood   AttackType = 2
	AttackACKFlood   AttackType = 3
	AttackICMPFlood  AttackType = 4
	AttackReflection AttackType = 5
	AttackSweep      AttackType = 6 // 扫段（R7）
	AttackAnomaly    AttackType = 7 // 客户总流量波动（R7）
	AttackUnknown    AttackType = 8
)

type AttackStatus uint32

const (
	AttackCandidate  AttackStatus = 1 // 候选
	AttackConfirmed  AttackStatus = 2 // 确认
	AttackMitigating AttackStatus = 3 // 处置中（R9 回执联动）
	AttackMitigated  AttackStatus = 4 // 已缓解
	AttackClosed     AttackStatus = 5 // 误报关闭/恢复关闭
)

type AlarmSeverity uint32

const (
	SeverityInfo     AlarmSeverity = 1
	SeverityWarning  AlarmSeverity = 2
	SeverityCritical AlarmSeverity = 3
)

type AlarmCategory uint32

const (
	CategoryAttack AlarmCategory = 1
	CategoryWave   AlarmCategory = 2 // 流量波动
	CategoryDevice AlarmCategory = 3
	CategorySystem AlarmCategory = 4
)

// AttackEvent / AttackMinute / Alarm / AlarmEnvelope —— proto security.proto 镜像
type AttackEvent struct {
	AttackID      string
	ZoneID        int32
	ZoneName      string
	AttackType    AttackType
	TargetPrefix  string
	StartMs       int64
	EndMs         int64
	PeakBps       int64
	PeakPps       int64
	Confidence    float32
	TopSources    []string // ≤100
	EvidenceJSON  string
	Status        AttackStatus
	MitigationID  string
}

type AttackMinute struct {
	AttackID    string
	MinuteEpoch int64
	BpsIn       int64
	PpsIn       int64
	BpsOut      int64
	PpsOut      int64
	NewFlows    uint64
	SynRatio    float32
	UdpRatio    float32
	TopSources  []string
	TopPorts    []uint32
}

type Alarm struct {
	AlarmID    string
	Source     string // analytics|bgp|system
	Severity   AlarmSeverity
	Category   AlarmCategory
	RaiseMs    int64
	ClearMs    int64
	Subject    string
	DetailJSON string
	ZoneID     int32
	AttackID   string
}

// AlarmEnvelope —— alarms topic 信封
type AlarmEnvelope struct {
	// 恰好一个非 nil
	Alarm  *Alarm
	Attack *AttackEvent
}

// AggrRow / 批次信封（flows.aggr.minute topic，09 §2）
type AggrRow struct {
	Minute     int64 // epoch 秒，分钟对齐
	Exporter   string
	DeviceID   uint32
	InIf       uint32
	OutIf      uint32
	Direction  Direction
	ZoneID     int32
	SrcAS      uint32
	DstAS      uint32
	Proto      uint32
	DstPort    uint32
	AppID      uint32
	BytesSum   uint64
	PacketsSum uint64
	FlowsCount uint64
}

type AggrMinuteBatch struct {
	Rows    []AggrRow
	BatchID uint64 // 幂等：PG export_batches 去重（09 §2）
}

type AttackMinuteBatch struct {
	Rows    []AttackMinute
	BatchID uint64
}

// TemplateRecord —— flow.templates topic（compact，Collector 模板 WAL）
type TemplateRecord struct {
	Exporter   string
	ObsDomain  uint32
	TemplateID uint32
	Body       []byte
	Version    uint64
	TsMs       int64
}

// MitigationEvent —— bgp.mitigations topic（R9 回执）
type MitigationEvent struct {
	MitigationID string
	Action       string // blackhole|flowspec|withdraw
	Prefix       string
	ExpireAtMs   int64 // 0=长期
	Result       string // applied|withdrawn|failed
	AttackID     string
	TsMs         int64
}
