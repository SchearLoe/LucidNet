package aggregate

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/SchearLoe/lucidnet/shared"
)

// recorder —— 测试用 Publisher，记录全部批次。
type recorder struct {
	batches []*shared.AggrMinuteBatch
}

func (r *recorder) PublishMinuteBatch(batch *shared.AggrMinuteBatch) error {
	r.batches = append(r.batches, batch)
	return nil
}

// failingRecorder —— 首次发布即失败的 Publisher（错误传播路径）。
type failingRecorder struct{ err error }

func (f failingRecorder) PublishMinuteBatch(*shared.AggrMinuteBatch) error { return f.err }

// manualClock —— 注入时间源，测试内手动推进。
type manualClock struct{ t time.Time }

func (c *manualClock) Now() time.Time { return c.t }
func (c *manualClock) Advance(d time.Duration) {
	c.t = c.t.Add(d)
}

var baseTime = time.Unix(3600, 0).UTC() // epoch 分钟 60 起点，便于断言

func newTestAggregator(pub Publisher) (*Aggregator, *manualClock) {
	clk := &manualClock{t: baseTime}
	agg, err := NewAggregator(pub, WithClock(clk.Now))
	if err != nil {
		panic(err)
	}
	return agg, clk
}

// flow —— 构造 FlowRecord；TimeStartMs 以 baseTime 为基准偏移。
func flow(offset time.Duration, mutate func(*shared.FlowRecord)) *shared.FlowRecord {
	rec := &shared.FlowRecord{
		TimeStartMs: baseTime.Add(offset).UnixMilli(),
		Exporter:    "exp-1",
		DeviceID:    7,
		InIf:        10,
		OutIf:       20,
		ZoneID:      101,
		ZoneSide:    uint8(shared.ZoneSideDst),
		IfRole:      shared.IfRoleInBoundary, // boundary↔internal：保留
		Proto:       6,
		DstPort:     443,
		Packets:     3,
		Bytes:       1500,
	}
	if mutate != nil {
		mutate(rec)
	}
	return rec
}

func totalRows(r *recorder) int {
	n := 0
	for _, b := range r.batches {
		n += len(b.Rows)
	}
	return n
}

func TestInternalFilterDrop(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		ifRole   uint8
		wantDrop bool
	}{
		{"both internal", 0, true},
		{"in boundary only", shared.IfRoleInBoundary, false},
		{"out boundary only", shared.IfRoleOutBoundary, false},
		{"both boundary", shared.IfRoleInBoundary | shared.IfRoleOutBoundary, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := &recorder{}
			agg, clk := newTestAggregator(rec)
			if err := agg.Add(flow(0, func(r *shared.FlowRecord) { r.IfRole = tc.ifRole })); err != nil {
				t.Fatalf("Add: %v", err)
			}
			clk.Advance(2 * time.Minute) // 翻过 grace
			if _, err := agg.Flush(); err != nil {
				t.Fatalf("Flush: %v", err)
			}
			got := totalRows(rec)
			if tc.wantDrop && got != 0 {
				t.Fatalf("if_role=%d should drop, got %d rows", tc.ifRole, got)
			}
			if !tc.wantDrop && got != 1 {
				t.Fatalf("if_role=%d should keep, got %d rows", tc.ifRole, got)
			}
			wantDropped := uint64(0)
			if tc.wantDrop {
				wantDropped = 1
			}
			if agg.Stats().DroppedInternal != wantDropped {
				t.Fatalf("dropped_internal = %d, want %d", agg.Stats().DroppedInternal, wantDropped)
			}
		})
	}
}

func TestDirectionFromZoneSideOnly(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		zoneSide shared.ZoneSide
		want     shared.Direction
	}{
		{"dst hit -> in", shared.ZoneSideDst, shared.DirIn},
		{"src hit -> out", shared.ZoneSideSrc, shared.DirOut},
		{"no zone -> unknown", shared.ZoneSideNone, shared.DirUnknown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := &recorder{}
			agg, clk := newTestAggregator(rec)
			if err := agg.Add(flow(0, func(r *shared.FlowRecord) { r.ZoneSide = uint8(tc.zoneSide) })); err != nil {
				t.Fatalf("Add: %v", err)
			}
			_, _ = clk, agg
			if _, err := agg.Flush(); err != nil {
				t.Fatalf("Flush: %v", err)
			}
			if len(rec.batches) != 1 || len(rec.batches[0].Rows) != 1 {
				t.Fatalf("want 1 batch with 1 row, got %+v", rec.batches)
			}
			if got := rec.batches[0].Rows[0].Direction; got != tc.want {
				t.Fatalf("direction = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestAccumulateByDimensionKey(t *testing.T) {
	t.Parallel()
	rec := &recorder{}
	agg, clk := newTestAggregator(rec)

	// 同一键两条：累加
	for i := 0; i < 2; i++ {
		if err := agg.Add(flow(0, nil)); err != nil {
			t.Fatalf("Add: %v", err)
		}
	}
	// 不同 dst_port：新行
	if err := agg.Add(flow(0, func(r *shared.FlowRecord) { r.DstPort = 80 })); err != nil {
		t.Fatalf("Add: %v", err)
	}
	// 不同分钟：独立批
	if err := agg.Add(flow(time.Minute, nil)); err != nil {
		t.Fatalf("Add: %v", err)
	}
	clk.Advance(3 * time.Minute)
	rows, err := agg.Flush()
	if err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if rows != 3 {
		t.Fatalf("published rows = %d, want 3", rows)
	}
	// 分钟 60 的批：同键两行（443 累加 2 条 / 80 一条）
	var batch60 *shared.AggrMinuteBatch
	for _, b := range rec.batches {
		if b.Rows[0].Minute == 3600 {
			batch60 = b
		}
	}
	if batch60 == nil {
		t.Fatalf("minute-3600 batch missing: %+v", rec.batches)
	}
	if len(batch60.Rows) != 2 {
		t.Fatalf("minute 60 rows = %d, want 2", len(batch60.Rows))
	}
	for _, row := range batch60.Rows {
		switch row.DstPort {
		case 443:
			if row.BytesSum != 3000 || row.PacketsSum != 6 || row.FlowsCount != 2 {
				t.Fatalf("443 row sums wrong: %+v", row)
			}
		case 80:
			if row.BytesSum != 1500 || row.FlowsCount != 1 {
				t.Fatalf("80 row sums wrong: %+v", row)
			}
		default:
			t.Fatalf("unexpected dst_port %d", row.DstPort)
		}
	}
	if batch60.BatchID == 0 {
		t.Fatal("batch_id should start at 1")
	}
}

func TestMinuteFlipGraceAndExpiry(t *testing.T) {
	t.Parallel()
	rec := &recorder{}
	agg, clk := newTestAggregator(rec)
	// 分钟 60（3600s）：正常记录
	if err := agg.Add(flow(0, nil)); err != nil {
		t.Fatalf("Add: %v", err)
	}
	// grace 内迟到（+80s < 90s）：仍计入分钟 60
	clk.Advance(80 * time.Second)
	if err := agg.Add(flow(0, func(r *shared.FlowRecord) { r.Bytes = 10 })); err != nil {
		t.Fatalf("Add: %v", err)
	}
	// 翻转前：无发布
	if len(rec.batches) != 0 {
		t.Fatalf("no batch expected before close, got %d", len(rec.batches))
	}
	// 推进到 3600+150s（:00+60s 窗 + 90s grace）：分钟 60 应发布
	clk.Advance(70 * time.Second)
	if err := agg.Add(flow(time.Minute, nil)); err != nil { // 分钟 61 正常记录
		t.Fatalf("Add: %v", err)
	}
	if len(rec.batches) != 1 {
		t.Fatalf("minute 60 should close at +150s, batches=%d", len(rec.batches))
	}
	if rows := rec.batches[0].Rows; len(rows) != 1 || rows[0].BytesSum != 1510 {
		t.Fatalf("minute 60 late record missing: %+v", rows)
	}
	// 过期记录（分钟 60 已关闭）：丢弃
	if err := agg.Add(flow(0, nil)); err != nil {
		t.Fatalf("Add expired: %v", err)
	}
	st := agg.Stats()
	if st.DroppedExpired != 1 {
		t.Fatalf("dropped_expired = %d, want 1", st.DroppedExpired)
	}
	// 分钟 61 在 3760+150 = 3910s 翻转
	clk.Advance(160 * time.Second)
	if err := agg.Add(flow(3*time.Minute, nil)); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if len(rec.batches) != 2 {
		t.Fatalf("minute 61 should close, batches=%d", len(rec.batches))
	}
	if rec.batches[1].BatchID != 2 {
		t.Fatalf("batch_id = %d, want 2 (increments per batch)", rec.batches[1].BatchID)
	}
}

func TestFlushForcesPublish(t *testing.T) {
	t.Parallel()
	rec := &recorder{}
	agg, _ := newTestAggregator(rec)
	if err := agg.Add(flow(0, nil)); err != nil {
		t.Fatalf("Add: %v", err)
	}
	rows, err := agg.Flush()
	if err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if rows != 1 || len(rec.batches) != 1 {
		t.Fatalf("flush rows=%d batches=%d, want 1/1", rows, len(rec.batches))
	}
	// 重复 Flush 幂等
	rows, err = agg.Flush()
	if err != nil || rows != 0 {
		t.Fatalf("second flush rows=%d err=%v, want 0/nil", rows, err)
	}
}

func TestPublisherErrorPropagates(t *testing.T) {
	t.Parallel()
	sentinel := errors.New("kafka down")
	clk := &manualClock{t: baseTime}
	agg, err := NewAggregator(failingRecorder{err: sentinel}, WithClock(clk.Now))
	if err != nil {
		t.Fatalf("NewAggregator: %v", err)
	}
	if err := agg.Add(flow(0, nil)); err != nil {
		t.Fatalf("Add: %v", err)
	}
	clk.Advance(3 * time.Minute)
	err = agg.Add(flow(0, nil))
	if !errors.Is(err, sentinel) {
		t.Fatalf("error should wrap sentinel with %%w, got %v", err)
	}
}

func TestInternalExcludeBypass(t *testing.T) {
	t.Parallel()
	// internal_exclude=false（全局视图旁路，dd/03 §2.2）：纯互联记录保留
	rec := &recorder{}
	clk := &manualClock{t: baseTime}
	agg, err := NewAggregator(rec, WithInternalExclude(false), WithClock(clk.Now))
	if err != nil {
		t.Fatalf("NewAggregator: %v", err)
	}
	if err := agg.Add(flow(0, func(r *shared.FlowRecord) { r.IfRole = 0 })); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if _, err := agg.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if got := totalRows(rec); got != 1 {
		t.Fatalf("bypass should keep internal-interconnect record, got %d rows", got)
	}
	if st := agg.Stats(); st.DroppedInternal != 0 {
		t.Fatalf("bypass dropped_internal = %d, want 0", st.DroppedInternal)
	}
}

func TestNilRecord(t *testing.T) {
	t.Parallel()
	agg, _ := newTestAggregator(&recorder{})
	if err := agg.Add(nil); err == nil {
		t.Fatal("nil record should error")
	}
}

func TestNilPublisherRejected(t *testing.T) {
	t.Parallel()
	if _, err := NewAggregator(nil); err == nil {
		t.Fatal("nil publisher should error")
	}
}

func TestFloorMinute(t *testing.T) {
	t.Parallel()
	cases := []struct {
		ms   int64
		want int64
	}{
		{3600_000, 3600},
		{3600_999, 3600},
		{3659_999, 3600},
		{3660_000, 3660},
		{0, 0},
	}
	for _, tc := range cases {
		if got := floorMinute(tc.ms); got != tc.want {
			t.Errorf("floorMinute(%d) = %d, want %d", tc.ms, got, tc.want)
		}
	}
}

func BenchmarkAggregatorAdd(b *testing.B) {
	agg, _ := newTestAggregator(&recorder{})
	rec := flow(0, nil)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rec.DstPort = uint32(i % 65536)
		if err := agg.Add(rec); err != nil {
			b.Fatal(err)
		}
	}
}

func ExampleNewAggregator() {
	agg, err := NewAggregator(&recorder{})
	if err != nil {
		fmt.Println(err)
		return
	}
	_ = agg
	// Output:
}
