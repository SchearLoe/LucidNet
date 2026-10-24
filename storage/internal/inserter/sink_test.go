package inserter

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// TestMemorySink —— 内存 Sink 记录 行/批次。
func TestMemorySink(t *testing.T) {
	ctx := context.Background()
	m := NewMemorySink()
	rows := []FlowsRawRow{{Exporter: "e1"}, {Exporter: "e2"}}
	if err := m.WriteFlowsRaw(ctx, 0, rows); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := m.WriteFlowsRaw(ctx, 0, rows[:1]); err != nil {
		t.Fatalf("write2: %v", err)
	}
	if got := m.Count(TableFlowsRaw, 0); got != 3 {
		t.Errorf("count = %d, want 3", got)
	}
	if got := m.BatchCount(TableFlowsRaw, 0); got != 2 {
		t.Errorf("batches = %d, want 2", got)
	}
	if got := m.Count(TableFlowsRaw, 1); got != 0 {
		t.Errorf("other shard count = %d", got)
	}
	snap := m.Rows(TableFlowsRaw, 0)
	if len(snap) != 3 {
		t.Fatalf("rows snapshot = %d", len(snap))
	}
	if r, ok := snap[0].(FlowsRawRow); !ok || r.Exporter != "e1" {
		t.Errorf("snapshot[0] = %+v", snap[0])
	}
}

// TestMemorySinkAllTables —— 五个写入面均可记录。
func TestMemorySinkAllTables(t *testing.T) {
	ctx := context.Background()
	m := NewMemorySink()
	_ = m.WriteAggrMinute(ctx, 2, []AggrMinuteRow{{Exporter: "e"}})
	_ = m.WriteAttackMinutes(ctx, 2, []AttackMinuteRow{{AttackID: "a"}})
	_ = m.WriteAttacks(ctx, 2, []AttackEventRow{{AttackID: "a"}})
	_ = m.WriteAlarmHistory(ctx, 2, []AlarmHistoryRow{{AlarmID: "x"}})
	for _, tbl := range []string{TableAggrMinute, TableAttackMinutes, TableAttacks, TableAlarmHistory} {
		if m.Count(tbl, 2) != 1 {
			t.Errorf("%s count = %d", tbl, m.Count(tbl, 2))
		}
	}
}

// TestCHSinkStub —— CH 写桩：日志回调 + 恒 nil 错误（空跑拓扑验证）。
func TestCHSinkStub(t *testing.T) {
	var logged strings.Builder
	s := NewCHSink("clickhouse://localhost:9000", func(f string, a ...any) {
		logged.WriteString("LOG ")
	})
	if s.DSN() != "clickhouse://localhost:9000" {
		t.Errorf("dsn = %s", s.DSN())
	}
	ctx := context.Background()
	_ = s.WriteFlowsRaw(ctx, 0, make([]FlowsRawRow, 2))
	_ = s.WriteAggrMinute(ctx, 1, nil)
	_ = s.WriteAttackMinutes(ctx, 1, nil)
	_ = s.WriteAttacks(ctx, 1, nil)
	_ = s.WriteAlarmHistory(ctx, 1, nil)
	if !strings.Contains(logged.String(), "LOG") {
		t.Error("log callback not invoked")
	}
	// 静默模式（nil logf）
	_ = NewCHSink("", nil).WriteFlowsRaw(ctx, 0, nil)
}

// failSink —— 前 ok 次成功后开始失败的 Sink（flush 失败路径测试）。
type failSink struct {
	inner *MemorySink
	ok    int
	err   error
}

func newFailSink(ok int, err error) *failSink {
	return &failSink{inner: NewMemorySink(), ok: ok, err: err}
}

func (f *failSink) dec() error {
	if f.ok <= 0 {
		return f.err
	}
	f.ok--
	return nil
}

func (f *failSink) WriteFlowsRaw(ctx context.Context, shard uint64, rows []FlowsRawRow) error {
	if err := f.dec(); err != nil {
		return err
	}
	return f.inner.WriteFlowsRaw(ctx, shard, rows)
}
func (f *failSink) WriteAggrMinute(ctx context.Context, shard uint64, rows []AggrMinuteRow) error {
	if err := f.dec(); err != nil {
		return err
	}
	return f.inner.WriteAggrMinute(ctx, shard, rows)
}
func (f *failSink) WriteAttackMinutes(ctx context.Context, shard uint64, rows []AttackMinuteRow) error {
	if err := f.dec(); err != nil {
		return err
	}
	return f.inner.WriteAttackMinutes(ctx, shard, rows)
}
func (f *failSink) WriteAttacks(ctx context.Context, shard uint64, rows []AttackEventRow) error {
	if err := f.dec(); err != nil {
		return err
	}
	return f.inner.WriteAttacks(ctx, shard, rows)
}
func (f *failSink) WriteAlarmHistory(ctx context.Context, shard uint64, rows []AlarmHistoryRow) error {
	if err := f.dec(); err != nil {
		return err
	}
	return f.inner.WriteAlarmHistory(ctx, shard, rows)
}

// ensure failSink 满足 Sink。
var _ Sink = (*failSink)(nil)

// TestFailSinkBehavior —— 前置成功后失败。
func TestFailSinkBehavior(t *testing.T) {
	f := newFailSink(1, errors.New("quota exceeded"))
	if err := f.WriteFlowsRaw(context.Background(), 0, nil); err != nil {
		t.Fatalf("first write must succeed: %v", err)
	}
	if err := f.WriteFlowsRaw(context.Background(), 0, nil); err == nil {
		t.Fatal("second write must fail")
	}
}

// TestTableNames —— 表名常量与 docs/11 §7 命名一致。
func TestTableNames(t *testing.T) {
	for got, want := range map[string]string{
		TableFlowsRaw: "flows_raw", TableAggrMinute: "aggr_minute", TableAggrHour: "aggr_hour",
		TableAttackMinutes: "attack_minutes", TableAttacks: "attacks",
	} {
		if got != want {
			t.Errorf("table name %q != %q", got, want)
		}
	}
}
