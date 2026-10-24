package inserter

import (
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/SchearLoe/lucidnet/shared"
)

// ErrInvalidRecord —— 消息映射校验失败哨兵错误（调用方 errors.Is 判定）。
var ErrInvalidRecord = errors.New("invalid record")

const (
	ipVersion4 uint32 = 4
	ipVersion6 uint32 = 6

	// v4MappedPrefix —— IPv4 映射地址前缀 ::ffff:0:0/96（docs/00 §1）。
	v4MappedPrefix = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff"
)

// IsV4Mapped —— 16B 地址是否为 ::ffff: 映射（docs/00 §1）。
func IsV4Mapped(b [16]byte) bool { return string(b[:12]) == v4MappedPrefix }

// DayOfUnixSec —— 分片路由的 day 维度（UTC 日期，YYYY-MM-DD）。
func DayOfUnixSec(sec int64) string {
	if sec < 0 {
		sec = 0
	}
	return time.Unix(sec, 0).UTC().Format("2006-01-02")
}

// MapFlowRecord —— flows.raw 消息 → flows_raw 行（列序 docs/00 §4 DDL）。
//
// 16B IP → CH IPv6 语义：CH IPv6 列按 16B 网络序原样存储，IPv4 记录以
// ::ffff:a.b.c.d 映射形式写入（docs/00 §1，写者填充 ip_version 不靠推导），
// v4-mapped 存储无膨胀，映射地址 16 字节直接可写、无需转换函数。
//
// 注意：FlowRecord.zone_side / src_geo / dst_geo / bgp_next_hop 在 flows_raw
// DDL（docs/00 §4）中无对应列，明细落库即丢失——契约缺口见模块 README。
func MapFlowRecord(rec shared.FlowRecord) (FlowsRawRow, error) {
	if rec.IPVersion != ipVersion4 && rec.IPVersion != ipVersion6 {
		return FlowsRawRow{}, fmt.Errorf("map flow record: ip_version %d not in {4,6}: %w", rec.IPVersion, ErrInvalidRecord)
	}
	if rec.IPVersion == ipVersion4 && (!IsV4Mapped(rec.SrcIP) || !IsV4Mapped(rec.DstIP)) {
		return FlowsRawRow{}, fmt.Errorf("map flow record: ipv4 addresses must be ::ffff: mapped (docs/00 §1): %w", ErrInvalidRecord)
	}
	if rec.TimeStartMs < 0 {
		return FlowsRawRow{}, fmt.Errorf("map flow record: negative time_start_ms %d: %w", rec.TimeStartMs, ErrInvalidRecord)
	}
	if rec.Proto > 0xFF {
		return FlowsRawRow{}, fmt.Errorf("map flow record: proto %d exceeds UInt8: %w", rec.Proto, ErrInvalidRecord)
	}
	if rec.SrcPort > 0xFFFF || rec.DstPort > 0xFFFF {
		return FlowsRawRow{}, fmt.Errorf("map flow record: port exceeds UInt16 (src=%d dst=%d): %w", rec.SrcPort, rec.DstPort, ErrInvalidRecord)
	}
	return FlowsRawRow{
		TimeSecond: time.Unix(rec.TimeStartMs/1000, 0).UTC(),
		TimeMs:     uint16(rec.TimeStartMs % 1000),
		Exporter:   rec.Exporter,
		DeviceID:   rec.DeviceID,
		InIf:       rec.InIf,
		OutIf:      rec.OutIf,
		SrcIP:      rec.SrcIP,
		DstIP:      rec.DstIP,
		SrcPort:    uint16(rec.SrcPort),
		DstPort:    uint16(rec.DstPort),
		Proto:      uint8(rec.Proto),
		IPVersion:  uint8(rec.IPVersion),
		Packets:    rec.Packets,
		Bytes:      rec.Bytes,
		// tcp_flags/tos：DDL 为 UInt8 而 proto 字段为位掩码 uint32（含 NS/ECE/CWR
		// 扩展位），>0xFF 按位截断——契约缺口见模块 README。
		TCPFlags:   uint8(rec.TCPFlags & 0xFF),
		TOS:        uint8(rec.TOS & 0xFF),
		SampleRate: rec.SampleRate,
		SrcAS:      rec.SrcAS,
		DstAS:      rec.DstAS,
		AppID:      rec.AppID,
		ZoneID:     rec.ZoneID,
		IfRole:     rec.IfRole,
	}, nil
}

// MapAggrMinuteRow —— AggrRow → aggr_minute 行。
// Bytes/Packets/Flows 为聚合原值，Sink 写入时包 sumState()/countState()
// 生成 AggregateFunction 中间态（docs/09 §2）。
func MapAggrMinuteRow(row shared.AggrRow) (AggrMinuteRow, error) {
	if row.Minute < 0 {
		return AggrMinuteRow{}, fmt.Errorf("map aggr row: negative minute %d: %w", row.Minute, ErrInvalidRecord)
	}
	if row.Proto > 0xFF {
		return AggrMinuteRow{}, fmt.Errorf("map aggr row: proto %d exceeds UInt8: %w", row.Proto, ErrInvalidRecord)
	}
	if row.DstPort > 0xFFFF {
		return AggrMinuteRow{}, fmt.Errorf("map aggr row: dst_port %d exceeds UInt16: %w", row.DstPort, ErrInvalidRecord)
	}
	if row.Direction > shared.DirIntra {
		return AggrMinuteRow{}, fmt.Errorf("map aggr row: direction %d not in {0,1,2,3}: %w", row.Direction, ErrInvalidRecord)
	}
	return AggrMinuteRow{
		Minute:    time.Unix(row.Minute, 0).UTC(),
		Exporter:  row.Exporter,
		DeviceID:  row.DeviceID,
		InIf:      row.InIf,
		OutIf:     row.OutIf,
		Direction: uint8(row.Direction),
		ZoneID:    row.ZoneID,
		SrcAS:     row.SrcAS,
		DstAS:     row.DstAS,
		Proto:     uint8(row.Proto),
		DstPort:   uint16(row.DstPort),
		AppID:     row.AppID,
		Bytes:     row.BytesSum,
		Packets:   row.PacketsSum,
		Flows:     row.FlowsCount,
	}, nil
}

// MapAttackMinuteRow —— AttackMinute → attack_minutes 行。
func MapAttackMinuteRow(row shared.AttackMinute) (AttackMinuteRow, error) {
	if row.AttackID == "" {
		return AttackMinuteRow{}, fmt.Errorf("map attack minute: empty attack_id: %w", ErrInvalidRecord)
	}
	if row.MinuteEpoch < 0 {
		return AttackMinuteRow{}, fmt.Errorf("map attack minute: negative minute_epoch %d: %w", row.MinuteEpoch, ErrInvalidRecord)
	}
	return AttackMinuteRow{
		AttackID:   row.AttackID,
		Minute:     time.Unix(row.MinuteEpoch, 0).UTC(),
		BpsIn:      row.BpsIn,
		PpsIn:      row.PpsIn,
		BpsOut:     row.BpsOut,
		PpsOut:     row.PpsOut,
		NewFlows:   row.NewFlows,
		SynRatio:   row.SynRatio,
		UdpRatio:   row.UdpRatio,
		TopSources: slices.Clone(row.TopSources),
		TopPorts:   slices.Clone(row.TopPorts),
	}, nil
}

// MapAttackEvent —— AttackEvent → attacks 行（docs/09 §8：alarms 消费 → attacks）。
func MapAttackEvent(ev shared.AttackEvent) (AttackEventRow, error) {
	if ev.AttackID == "" {
		return AttackEventRow{}, fmt.Errorf("map attack event: empty attack_id: %w", ErrInvalidRecord)
	}
	return AttackEventRow{
		AttackID:     ev.AttackID,
		ZoneID:       ev.ZoneID,
		ZoneName:     ev.ZoneName,
		AttackType:   uint32(ev.AttackType),
		TargetPrefix: ev.TargetPrefix,
		StartMs:      ev.StartMs,
		EndMs:        ev.EndMs,
		PeakBps:      ev.PeakBps,
		PeakPps:      ev.PeakPps,
		Confidence:   ev.Confidence,
		TopSources:   slices.Clone(ev.TopSources),
		EvidenceJSON: ev.EvidenceJSON,
		Status:       uint32(ev.Status),
		MitigationID: ev.MitigationID,
	}, nil
}

// MapAlarm —— Alarm → 告警历史行（目标表 DDL 缺口，见模块 README）。
func MapAlarm(a shared.Alarm) (AlarmHistoryRow, error) {
	if a.AlarmID == "" {
		return AlarmHistoryRow{}, fmt.Errorf("map alarm: empty alarm_id: %w", ErrInvalidRecord)
	}
	return AlarmHistoryRow{
		AlarmID:    a.AlarmID,
		Source:     a.Source,
		Severity:   uint32(a.Severity),
		Category:   uint32(a.Category),
		RaiseMs:    a.RaiseMs,
		ClearMs:    a.ClearMs,
		Subject:    a.Subject,
		DetailJSON: a.DetailJSON,
		ZoneID:     a.ZoneID,
		AttackID:   a.AttackID,
	}, nil
}

// MapAlarmEnvelope —— alarms 信封拆包（docs/09 §2 oneof）：Attack → attacks 行、
// Alarm → 告警历史行；恰好一个非空载荷。
func MapAlarmEnvelope(env shared.AlarmEnvelope) ([]AttackEventRow, []AlarmHistoryRow, error) {
	switch {
	case env.Attack != nil:
		row, err := MapAttackEvent(*env.Attack)
		if err != nil {
			return nil, nil, err
		}
		return []AttackEventRow{row}, nil, nil
	case env.Alarm != nil:
		row, err := MapAlarm(*env.Alarm)
		if err != nil {
			return nil, nil, err
		}
		return nil, []AlarmHistoryRow{row}, nil
	default:
		return nil, nil, fmt.Errorf("map alarm envelope: empty payload: %w", ErrInvalidRecord)
	}
}
