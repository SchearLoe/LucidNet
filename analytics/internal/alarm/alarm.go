// Package alarm —— alarms topic 发布接口（09 §2：AlarmEnvelope oneof Alarm/AttackEvent，
// key=zone_id，生产者 Analytics → LucidBGP/网关/Inserter）。
//
// 骨架提供：内存 channel 开发实现（DevPublisher）+ Kafka 桩（TODO franz-go）；
// AttackEvent → AlarmEnvelope 的 severity/category 映射；fsm.Emitter 适配器。
// 非并发安全（单事件循环内调用，见 cmd/lucid-analytics）。
package alarm

import (
	"errors"
	"fmt"

	"github.com/SchearLoe/lucidnet/shared"
)

// ErrKafkaNotImplemented —— Kafka 生产桩未实现（M2 接 franz-go）。
var ErrKafkaNotImplemented = errors.New("alarm: kafka publisher not implemented (TODO dd/03 §8; topic " + shared.TopicAlarms + ")")

// Publisher —— alarms / attacks.minutes 发布接口。
type Publisher interface {
	// PublishAlarm 发布 alarms 信封（topic=shared.TopicAlarms，key=zone_id）。
	PublishAlarm(env *shared.AlarmEnvelope) error
	// PublishAttackMinutes 发布攻击分钟详情（topic=shared.TopicAttacksMinutes，key=attack_id，dd/03 §6.2）。
	PublishAttackMinutes(batch *shared.AttackMinuteBatch) error
	Close() error
}

// EnvelopeForAttack —— AttackEvent → AlarmEnvelope（oneof 仅携带 AttackEvent，
// Inserter 落 attacks 表；独立 Alarm 消息（CategoryWave 等）由告警通道另行发布，
// TODO dd/03 §6.3）。
func EnvelopeForAttack(ev *shared.AttackEvent) (*shared.AlarmEnvelope, error) {
	if ev == nil {
		return nil, errors.New("alarm: nil attack event")
	}
	return &shared.AlarmEnvelope{Attack: ev}, nil
}

// AlarmForAttack —— 由攻击事件生成通用告警（severity/category 映射：
// 候选=警告、确认/处置=严重、缓解/关闭=提示；ANOMALY 归 CategoryWave）。
func AlarmForAttack(ev *shared.AttackEvent) (*shared.Alarm, error) {
	if ev == nil {
		return nil, errors.New("alarm: nil attack event")
	}
	var sev shared.AlarmSeverity
	switch ev.Status {
	case shared.AttackCandidate:
		sev = shared.SeverityWarning
	case shared.AttackConfirmed, shared.AttackMitigating:
		sev = shared.SeverityCritical
	default: // AttackMitigated / AttackClosed / 未知
		sev = shared.SeverityInfo
	}
	cat := shared.CategoryAttack
	if ev.AttackType == shared.AttackAnomaly {
		cat = shared.CategoryWave // 流量波动（dd/03 §4.3）
	}
	return &shared.Alarm{
		AlarmID:  "alm-" + ev.AttackID,
		Source:   "analytics",
		Severity: sev,
		Category: cat,
		RaiseMs:  ev.StartMs,
		Subject:  fmt.Sprintf("zone %d attack %d status %d", ev.ZoneID, ev.AttackType, ev.Status),
		ZoneID:   ev.ZoneID,
		AttackID: ev.AttackID,
	}, nil
}

// DevPublisher —— 内存 channel 开发实现（演示/单测；缓冲满即丢弃并计数）。
type DevPublisher struct {
	ch     chan *shared.AlarmEnvelope
	minute chan *shared.AttackMinuteBatch

	droppedAlarm  uint64
	droppedMinute uint64
	published     uint64
}

// NewDevPublisher 构造内存发布器（缓冲 alarms buf 条）。
func NewDevPublisher(buf int) *DevPublisher {
	if buf <= 0 {
		buf = 256
	}
	return &DevPublisher{
		ch:     make(chan *shared.AlarmEnvelope, buf),
		minute: make(chan *shared.AttackMinuteBatch, 16),
	}
}

// PublishAlarm —— 非阻塞入队；缓冲满丢弃（开发模式不背压）。
func (p *DevPublisher) PublishAlarm(env *shared.AlarmEnvelope) error {
	if env == nil {
		return errors.New("alarm: nil envelope")
	}
	p.published++
	select {
	case p.ch <- env:
		return nil
	default:
		p.droppedAlarm++
		return fmt.Errorf("alarm: dev channel full, envelope dropped (dropped=%d)", p.droppedAlarm)
	}
}

// PublishAttackMinutes —— 攻击分钟批（开发模式）。
func (p *DevPublisher) PublishAttackMinutes(batch *shared.AttackMinuteBatch) error {
	if batch == nil {
		return errors.New("alarm: nil attack minute batch")
	}
	select {
	case p.minute <- batch:
		return nil
	default:
		p.droppedMinute++
		return fmt.Errorf("alarm: dev minute channel full, batch dropped (dropped=%d)", p.droppedMinute)
	}
}

// Alarms —— 订阅 alarms 信封流（测试/演示消费端）。
func (p *DevPublisher) Alarms() <-chan *shared.AlarmEnvelope { return p.ch }

// AttackMinutes —— 订阅分钟批流。
func (p *DevPublisher) AttackMinutes() <-chan *shared.AttackMinuteBatch { return p.minute }

// Stats —— 发布统计。
type Stats struct {
	Published     uint64
	DroppedAlarm  uint64
	DroppedMinute uint64
}

func (p *DevPublisher) Stats() Stats {
	return Stats{Published: p.published, DroppedAlarm: p.droppedAlarm, DroppedMinute: p.droppedMinute}
}

// Close 关闭通道。
func (p *DevPublisher) Close() error {
	close(p.ch)
	close(p.minute)
	return nil
}

// KafkaPublisher —— Kafka 生产桩：接口占位，M2 以 franz-go 实现
// （producer linger=50ms、batch≥64KB、lz4，09 §2）。
type KafkaPublisher struct {
	Brokers []string
	Topic   string
}

// NewKafkaPublisher —— 构造桩（不建连）。
func NewKafkaPublisher(brokers []string) *KafkaPublisher {
	return &KafkaPublisher{Brokers: brokers, Topic: shared.TopicAlarms}
}

// PublishAlarm —— 桩：恒返回 ErrKafkaNotImplemented。
func (p *KafkaPublisher) PublishAlarm(*shared.AlarmEnvelope) error { return ErrKafkaNotImplemented }

// PublishAttackMinutes —— 桩：恒返回 ErrKafkaNotImplemented。
func (p *KafkaPublisher) PublishAttackMinutes(*shared.AttackMinuteBatch) error {
	return ErrKafkaNotImplemented
}

// Close —— 桩。
func (p *KafkaPublisher) Close() error { return nil }

// AttackEmitter —— fsm.Emitter 适配器：状态机事件 → alarms topic。
type AttackEmitter struct {
	Pub Publisher
}

// EmitAttack 实现 fsm.Emitter。
func (e AttackEmitter) EmitAttack(ev *shared.AttackEvent) {
	env, err := EnvelopeForAttack(ev)
	if err != nil {
		return
	}
	if err := e.Pub.PublishAlarm(env); err != nil {
		// 开发模式下缓冲满属预期；生产实现接重试/指标（TODO M2，docs/11 §9）
		_ = err
	}
}
