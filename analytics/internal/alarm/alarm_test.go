package alarm

import (
	"errors"
	"testing"

	"github.com/SchearLoe/lucidnet/shared"
)

func TestDevPublisherRoundTrip(t *testing.T) {
	t.Parallel()
	pub := NewDevPublisher(8)
	ev := &shared.AttackEvent{AttackID: "a1", ZoneID: 7, Status: shared.AttackConfirmed}
	env, err := EnvelopeForAttack(ev)
	if err != nil {
		t.Fatal(err)
	}
	if err := pub.PublishAlarm(env); err != nil {
		t.Fatal(err)
	}
	if err := pub.PublishAttackMinutes(&shared.AttackMinuteBatch{BatchID: 1}); err != nil {
		t.Fatal(err)
	}
	got := <-pub.Alarms()
	if got.Attack == nil || got.Attack.AttackID != "a1" || got.Alarm != nil {
		t.Fatalf("envelope oneof should carry attack only: %+v", got)
	}
	if b := <-pub.AttackMinutes(); b.BatchID != 1 {
		t.Fatalf("minute batch = %+v", b)
	}
	if st := pub.Stats(); st.Published != 1 || st.DroppedAlarm != 0 {
		t.Fatalf("stats = %+v", st)
	}
	if err := pub.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestDevPublisherOverflowDrops(t *testing.T) {
	t.Parallel()
	pub := NewDevPublisher(1)
	for i := 0; i < 3; i++ {
		_ = pub.PublishAlarm(&shared.AlarmEnvelope{Attack: &shared.AttackEvent{AttackID: "x"}})
	}
	if st := pub.Stats(); st.DroppedAlarm != 2 {
		t.Fatalf("dropped = %d, want 2", st.DroppedAlarm)
	}
}

func TestNilInputs(t *testing.T) {
	t.Parallel()
	pub := NewDevPublisher(1)
	if _, err := EnvelopeForAttack(nil); err == nil {
		t.Fatal("nil attack should error")
	}
	if _, err := AlarmForAttack(nil); err == nil {
		t.Fatal("nil attack should error")
	}
	if err := pub.PublishAlarm(nil); err == nil {
		t.Fatal("nil envelope should error")
	}
	if err := pub.PublishAttackMinutes(nil); err == nil {
		t.Fatal("nil batch should error")
	}
}

func TestAlarmForAttackMapping(t *testing.T) {
	t.Parallel()
	cases := []struct {
		status     shared.AttackStatus
		attackType shared.AttackType
		wantSev    shared.AlarmSeverity
		wantCat    shared.AlarmCategory
	}{
		{shared.AttackCandidate, shared.AttackSYNFlood, shared.SeverityWarning, shared.CategoryAttack},
		{shared.AttackConfirmed, shared.AttackSYNFlood, shared.SeverityCritical, shared.CategoryAttack},
		{shared.AttackMitigating, shared.AttackUDPFlood, shared.SeverityCritical, shared.CategoryAttack},
		{shared.AttackMitigated, shared.AttackSweep, shared.SeverityInfo, shared.CategoryAttack},
		{shared.AttackClosed, shared.AttackAnomaly, shared.SeverityInfo, shared.CategoryWave},
	}
	for _, tc := range cases {
		alm, err := AlarmForAttack(&shared.AttackEvent{
			AttackID:   "u1",
			ZoneID:     3,
			AttackType: tc.attackType,
			Status:     tc.status,
			StartMs:    123,
		})
		if err != nil {
			t.Fatal(err)
		}
		if alm.Severity != tc.wantSev || alm.Category != tc.wantCat {
			t.Fatalf("status %d: sev=%d cat=%d, want %d/%d",
				tc.status, alm.Severity, alm.Category, tc.wantSev, tc.wantCat)
		}
		if alm.Source != "analytics" || alm.AttackID != "u1" || alm.ZoneID != 3 {
			t.Fatalf("alarm fields wrong: %+v", alm)
		}
	}
}

func TestKafkaStub(t *testing.T) {
	t.Parallel()
	p := NewKafkaPublisher([]string{"k1:9092"})
	if p.Topic != shared.TopicAlarms {
		t.Fatalf("topic = %q, want %q", p.Topic, shared.TopicAlarms)
	}
	err := p.PublishAlarm(&shared.AlarmEnvelope{})
	if !errors.Is(err, ErrKafkaNotImplemented) {
		t.Fatalf("stub should return ErrKafkaNotImplemented, got %v", err)
	}
	if err := p.PublishAttackMinutes(&shared.AttackMinuteBatch{}); !errors.Is(err, ErrKafkaNotImplemented) {
		t.Fatalf("stub should return ErrKafkaNotImplemented, got %v", err)
	}
}

// TestAttackEmitter —— fsm.Emitter 适配：事件进 channel。
func TestAttackEmitter(t *testing.T) {
	t.Parallel()
	pub := NewDevPublisher(4)
	em := AttackEmitter{Pub: pub}
	em.EmitAttack(&shared.AttackEvent{AttackID: "e1", Status: shared.AttackCandidate})
	em.EmitAttack(nil) // 忽略
	if got := len(pub.Alarms()); got != 1 {
		t.Fatalf("channel len = %d, want 1", got)
	}
}
