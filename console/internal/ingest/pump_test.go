package ingest

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/SchearLoe/lucidnet/shared"

	"github.com/SchearLoe/lucidnet/console/internal/codec"
	"github.com/SchearLoe/lucidnet/console/internal/hub"
)

// memSink —— 测试桩（store + hub 组合的最小实现）。
type memSink struct {
	attacks []*shared.AttackEvent
	alarms  []*shared.Alarm
	msgs    []hub.Message
}

func (s *memSink) UpsertAttack(a *shared.AttackEvent) { s.attacks = append(s.attacks, a) }
func (s *memSink) AppendAlarm(a *shared.Alarm)        { s.alarms = append(s.alarms, a) }
func (s *memSink) Publish(m hub.Message)              { s.msgs = append(s.msgs, m) }

// TestPumpAlarmEnvelope —— alarms topic：Alarm / AttackEvent 两类载荷分发（docs/09 §2）。
func TestPumpAlarmEnvelope(t *testing.T) {
	c := NewChannelConsumer(8)
	sink := &memSink{}
	p := NewPump(c, codec.JSONCodec{}, sink, slog.Default())

	c.Inject(Record{
		Topic: shared.TopicAlarms,
		Value: []byte(`{"alarm":{"alarm_id":"al-1","source":"analytics","severity":3,"category":1,"raise_ms":1700000000000,"zone_id":101,"attack_id":"at-1"}}`),
	})
	c.Inject(Record{
		Topic: shared.TopicAlarms,
		Value: []byte(`{"attack":{"attack_id":"at-1","zone_id":101,"zone_name":"客户A","attack_type":1,"status":2,"peak_bps":123456789}}`),
	})

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	// Polls 两条 → handle → CommitMarks（本测试直接驱动 handle 语义经由 Run 不便截断，改用 Run+ctx 超时）。
	go func() { _ = p.Run(ctx) }()

	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if len(sink.msgs) >= 2 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if len(sink.alarms) != 1 || sink.alarms[0].AlarmID != "al-1" {
		t.Fatalf("alarms = %+v", sink.alarms)
	}
	if len(sink.attacks) != 1 || sink.attacks[0].AttackID != "at-1" || sink.attacks[0].Status != shared.AttackConfirmed {
		t.Fatalf("attacks = %+v", sink.attacks)
	}
	if len(sink.msgs) != 2 {
		t.Fatalf("published = %d, want 2", len(sink.msgs))
	}
	if sink.msgs[0].Type != "alarm" || sink.msgs[0].ZoneID != 101 {
		t.Fatalf("msg0 = %+v", sink.msgs[0])
	}
	if sink.msgs[1].Type != "attack" {
		t.Fatalf("msg1 = %+v", sink.msgs[1])
	}
}

// TestPumpMitigation —— bgp.mitigations：R9 回执进 WS 流（zone 未知广播）。
func TestPumpMitigation(t *testing.T) {
	c := NewChannelConsumer(8)
	sink := &memSink{}
	p := NewPump(c, codec.JSONCodec{}, sink, slog.Default())

	c.Inject(Record{
		Topic: shared.TopicBGPMitigations,
		Value: []byte(`{"mitigation_id":"m-1","action":"blackhole","prefix":"203.0.113.0/24","result":"applied","attack_id":"at-1","ts_ms":1700000001000}`),
	})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	go func() { _ = p.Run(ctx) }()

	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if len(sink.msgs) >= 1 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if len(sink.msgs) != 1 {
		t.Fatalf("published = %d, want 1", len(sink.msgs))
	}
	m := sink.msgs[0]
	if m.Topic != shared.TopicBGPMitigations || m.Type != "mitigation" || m.TsMs != 1700000001000 {
		t.Fatalf("msg = %+v", m)
	}
}

// TestPumpPoisonSkipped —— 毒丸消息不中断泵（解码失败跳过继续）。
func TestPumpPoisonSkipped(t *testing.T) {
	c := NewChannelConsumer(8)
	sink := &memSink{}
	p := NewPump(c, codec.JSONCodec{}, sink, slog.Default())

	c.Inject(Record{Topic: shared.TopicAlarms, Value: []byte("not-json")})
	c.Inject(Record{Topic: shared.TopicAlarms, Value: []byte(`{"alarm":{"alarm_id":"ok"}}`)})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	go func() { _ = p.Run(ctx) }()

	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if len(sink.alarms) >= 1 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if len(sink.alarms) != 1 {
		t.Fatalf("alarms = %d, want 1 (poison skipped)", len(sink.alarms))
	}
}
