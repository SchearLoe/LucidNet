package export

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
)

// flakySource —— 前 failN 次 FetchRows 报错（重试语义测试），之后转真源。
type flakySource struct {
	inner   *SequenceSource
	failN   int
	failErr error
	mu      sync.Mutex
}

func (f *flakySource) FetchRows(ctx context.Context, j Job, cursor string, limit int) ([]Row, string, error) {
	f.mu.Lock()
	if f.failN > 0 {
		f.failN--
		f.mu.Unlock()
		return nil, "", f.failErr
	}
	f.mu.Unlock()
	return f.inner.FetchRows(ctx, j, cursor, limit)
}

func (f *flakySource) EstimateRows(ctx context.Context, j Job) int64 {
	return f.inner.EstimateRows(ctx, j)
}

// newTestRunner —— 组装执行器 + 固定时钟。
func newTestRunner(t *testing.T, source RowSource) (*Runner, *MemoryStore, *MemoryProgressStore, *MemoryCursorStore, *bytes.Buffer) {
	t.Helper()
	store := NewMemoryStore(func() int64 { return 1771900000 })
	progress := NewMemoryProgressStore()
	cursors := NewMemoryCursorStore()
	var buf bytes.Buffer
	runner, err := NewRunner(store, progress, cursors, source, func(Job) (io.Writer, error) {
		return &buf, nil
	})
	if err != nil {
		t.Fatalf("new runner: %v", err)
	}
	return runner, store, progress, cursors, &buf
}

// newQueued —— 建一个已入队的任务（带 1 个过滤条件以驱动取证头注释）。
func newQueued(t *testing.T, store Store) Job {
	t.Helper()
	j := validJob()
	j.ID = "job-run-1"
	dstPort := uint32(443)
	j.Filters.DstPort = &dstPort
	if err := store.Create(context.Background(), j); err != nil {
		t.Fatalf("create: %v", err)
	}
	return j
}

// TestRunnerSuccess —— 全量成功：done、进度 1、URL/ExpiresAt、产物含头与行。
func TestRunnerSuccess(t *testing.T) {
	runner, store, progress, cursors, buf := newTestRunner(t, NewSequenceSource(5))
	runner.SetNow(func() int64 { return 1771900000 })
	newQueued(t, store)
	runner.SetBatchRows(2)

	if err := runner.Run(context.Background(), "job-run-1"); err != nil {
		t.Fatalf("run: %v", err)
	}
	j, _ := store.Get(context.Background(), "job-run-1")
	if j.Status != StatusDone || j.Progress != 1 {
		t.Fatalf("final = %s %.2f", j.Status, j.Progress)
	}
	if !strings.HasPrefix(j.URL, "exports/job-run-1/") {
		t.Errorf("url = %q", j.URL)
	}
	if want := int64(1771900000 + 24*3600); j.ExpiresAt != want {
		t.Errorf("expires_at = %d, want %d", j.ExpiresAt, want)
	}
	if d, tot, _ := progress.Get(context.Background(), "job-run-1"); d != 5 || tot != 5 {
		t.Errorf("progress = %d/%d, want 5/5", d, tot)
	}
	if cur, _ := cursors.Load(context.Background(), "job-run-1"); cur != "" {
		t.Errorf("cursor after done = %q, want cleared", cur)
	}
	out := buf.String()
	if !strings.Contains(out, "# LucidNet flow export") {
		t.Error("output missing header comment")
	}
	if !strings.Contains(out, "# fields=") || !strings.Contains(out, "| filters=") {
		t.Error("output missing traceability header (docs/00 §7)")
	}
	if got := strings.Count(out, "\n"); got < 1+1+5 { // 2 头注释 + 1 列头 + 5 行
		t.Errorf("output lines = %d, want >= 7:\n%s", got, out)
	}
	if !strings.Contains(out, "::ffff:") {
		t.Error("output missing v4-mapped rows (odd rows are v4)")
	}
}

// TestRunnerIdempotentRerun —— 终态任务重跑为 no-op。
func TestRunnerIdempotentRerun(t *testing.T) {
	runner, store, _, _, _ := newTestRunner(t, NewSequenceSource(2))
	newQueued(t, store)
	if err := runner.Run(context.Background(), "job-run-1"); err != nil {
		t.Fatalf("run1: %v", err)
	}
	if err := runner.Run(context.Background(), "job-run-1"); err != nil {
		t.Fatalf("run2 (terminal) must be no-op, got %v", err)
	}
	j, _ := store.Get(context.Background(), "job-run-1")
	if j.Status != StatusDone {
		t.Errorf("status = %s", j.Status)
	}
}

// TestRunnerResumeFromCursor —— 预置游标续跑：跳过已处理行、不重写头部。
func TestRunnerResumeFromCursor(t *testing.T) {
	runner, store, progress, cursors, buf := newTestRunner(t, NewSequenceSource(6))
	newQueued(t, store)
	runner.SetBatchRows(3)
	// 模拟中断：任务已 running、游标=3（前 3 行已写出）
	j, _ := store.Get(context.Background(), "job-run-1")
	_ = j.Start()
	_ = store.Update(context.Background(), j)
	if err := cursors.Save(context.Background(), "job-run-1", "3"); err != nil {
		t.Fatalf("save cursor: %v", err)
	}

	if err := runner.Run(context.Background(), "job-run-1"); err != nil {
		t.Fatalf("run: %v", err)
	}
	out := buf.String()
	if strings.Contains(out, "# LucidNet flow export") {
		t.Error("resumed part must not rewrite header (new volume TODO semantics)")
	}
	if got := strings.Count(strings.TrimSpace(out), "\n") + 1; got != 3 {
		t.Errorf("resumed rows = %d, want 3:\n%s", got, out)
	}
	if d, _, _ := progress.Get(context.Background(), "job-run-1"); d != 3 {
		t.Errorf("progress done = %d, want 3（续跑批内计数口径，TODO 全局累计）", d)
	}
	j2, _ := store.Get(context.Background(), "job-run-1")
	if j2.Status != StatusDone {
		t.Errorf("status = %s", j2.Status)
	}
}

// TestRunnerRetryThenFail —— 取数持续失败：重试 3 次后落 failed。
func TestRunnerRetryThenFail(t *testing.T) {
	runner, store, _, _, _ := newTestRunner(t, &flakySource{
		inner: NewSequenceSource(4), failN: 99, failErr: errors.New("ch unavailable"),
	})
	newQueued(t, store)
	runner.SetBatchRows(2)

	err := runner.Run(context.Background(), "job-run-1")
	if err == nil || !strings.Contains(err.Error(), "ch unavailable") {
		t.Fatalf("run err = %v, want wrapped ch unavailable", err)
	}
	j, _ := store.Get(context.Background(), "job-run-1")
	if j.Status != StatusFailed || !strings.Contains(j.Error, "ch unavailable") {
		t.Fatalf("final = %+v", j)
	}
}

// TestRunnerRetrySucceeds —— 前 2 次失败第 3 次成功：重试后正常完成。
func TestRunnerRetrySucceeds(t *testing.T) {
	runner, store, _, _, _ := newTestRunner(t, &flakySource{
		inner: NewSequenceSource(2), failN: 2, failErr: errors.New("transient"),
	})
	newQueued(t, store)
	if err := runner.Run(context.Background(), "job-run-1"); err != nil {
		t.Fatalf("run: %v", err)
	}
	j, _ := store.Get(context.Background(), "job-run-1")
	if j.Status != StatusDone {
		t.Fatalf("status = %s", j.Status)
	}
}

// TestRunnerMissingJob —— 不存在的任务返回 ErrJobNotFound。
func TestRunnerMissingJob(t *testing.T) {
	runner, _, _, _, _ := newTestRunner(t, NewSequenceSource(1))
	if err := runner.Run(context.Background(), "ghost"); !errors.Is(err, ErrJobNotFound) {
		t.Fatalf("err = %v, want ErrJobNotFound", err)
	}
}

// TestRunnerWriterError —— 打开产物失败 → failed。
func TestRunnerWriterError(t *testing.T) {
	store := NewMemoryStore(func() int64 { return 1 })
	progress := NewMemoryProgressStore()
	cursors := NewMemoryCursorStore()
	runner, err := NewRunner(store, progress, cursors, NewSequenceSource(1),
		func(Job) (io.Writer, error) { return nil, errors.New("disk full") })
	if err != nil {
		t.Fatalf("new runner: %v", err)
	}
	newQueued(t, store)
	if err := runner.Run(context.Background(), "job-run-1"); err == nil {
		t.Fatal("expect error")
	}
	j, _ := store.Get(context.Background(), "job-run-1")
	if j.Status != StatusFailed {
		t.Fatalf("status = %s", j.Status)
	}
}

// TestSequenceSource —— 合成源游标语义。
func TestSequenceSource(t *testing.T) {
	ctx := context.Background()
	s := NewSequenceSource(5)
	if got := s.EstimateRows(ctx, Job{}); got != 5 {
		t.Errorf("estimate = %d", got)
	}
	rows, next, err := s.FetchRows(ctx, Job{}, "", 2)
	if err != nil || len(rows) != 2 || next != "2" {
		t.Fatalf("fetch1 = %d rows, next=%q, err=%v", len(rows), next, err)
	}
	rows, next, err = s.FetchRows(ctx, Job{}, next, 10)
	if err != nil || len(rows) != 3 || next != "" {
		t.Fatalf("fetch2 = %d rows, next=%q, err=%v", len(rows), next, err)
	}
	if _, _, err := s.FetchRows(ctx, Job{}, next, 10); err != nil {
		t.Fatalf("exhausted fetch err = %v", err)
	}
	if _, _, err := s.FetchRows(ctx, Job{}, "bogus", 10); err == nil {
		t.Fatal("bad cursor must fail")
	}
	if _, _, err := s.FetchRows(ctx, Job{}, "", 0); err == nil {
		t.Fatal("zero limit must fail")
	}
}
