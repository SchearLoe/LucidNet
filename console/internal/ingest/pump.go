package ingest

import (
	"context"
	"log/slog"
	"time"

	"github.com/SchearLoe/lucidnet/shared"

	"github.com/SchearLoe/lucidnet/console/internal/codec"
	"github.com/SchearLoe/lucidnet/console/internal/hub"
)

// Sink —— 泵的下游（内存近端缓存 + WS hub 的组合，测试可替换）。
type Sink interface {
	UpsertAttack(*shared.AttackEvent)
	AppendAlarm(*shared.Alarm)
	Publish(hub.Message)
}

// Pump —— gateway.ws 消费泵：Polls → 解码 → Sink（store+hub）→ CommitMarks。
// 解码失败：记录日志并继续提交（毒丸消息不应卡死实时通道；近端缓存可容忍丢失，
// 权威数据在 Storage Inserter 侧独立消费）。
type Pump struct {
	consumer Consumer
	dec      codec.Codec
	sink     Sink
	log      *slog.Logger
}

// NewPump 构造。
func NewPump(c Consumer, dec codec.Codec, sink Sink, log *slog.Logger) *Pump {
	if log == nil {
		log = slog.Default()
	}
	return &Pump{consumer: c, dec: dec, sink: sink, log: log}
}

// Run 阻塞消费直到 ctx 取消；返回 ctx.Err()。
func (p *Pump) Run(ctx context.Context) error {
	for {
		recs, err := p.consumer.Polls(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			p.log.Error("ingest polls failed", "module", "gateway", "err", err)
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(time.Second): // 退避重试
			}
			continue
		}
		for _, r := range recs {
			p.handle(r)
		}
		if err := p.consumer.CommitMarks(ctx, recs); err != nil && ctx.Err() == nil {
			p.log.Warn("ingest commit failed", "module", "gateway", "err", err)
		}
	}
}

func (p *Pump) handle(r Record) {
	nowMs := r.Timestamp.UnixMilli()
	if nowMs <= 0 {
		nowMs = time.Now().UnixMilli()
	}
	switch r.Topic {
	case shared.TopicAlarms:
		env, err := p.dec.DecodeAlarmEnvelope(r.Value)
		if err != nil {
			p.logWarn("alarms", err)
			return
		}
		switch {
		case env.Alarm != nil:
			p.sink.AppendAlarm(env.Alarm)
			p.sink.Publish(hub.Message{
				Topic: shared.TopicAlarms, Type: "alarm",
				ZoneID: env.Alarm.ZoneID, TsMs: orNow(env.Alarm.RaiseMs, nowMs),
				Data: env.Alarm,
			})
		case env.Attack != nil:
			p.sink.UpsertAttack(env.Attack)
			p.sink.Publish(hub.Message{
				Topic: shared.TopicAlarms, Type: "attack",
				ZoneID: env.Attack.ZoneID, TsMs: orNow(env.Attack.StartMs, nowMs),
				Data: env.Attack,
			})
		}
	case shared.TopicBGPMitigations:
		m, err := p.dec.DecodeMitigationEvent(r.Value)
		if err != nil {
			p.logWarn("bgp.mitigations", err)
			return
		}
		p.sink.Publish(hub.Message{
			Topic: shared.TopicBGPMitigations, Type: "mitigation",
			ZoneID: 0, TsMs: orNow(m.TsMs, nowMs),
			Data: m,
		})
	default:
		p.log.Warn("ingest unexpected topic", "module", "gateway", "topic", r.Topic)
	}
}

func (p *Pump) logWarn(topic string, err error) {
	p.log.Warn("ingest decode failed", "module", "gateway", "topic", topic, "err", err)
}

func orNow(v, nowMs int64) int64 {
	if v > 0 {
		return v
	}
	return nowMs
}
