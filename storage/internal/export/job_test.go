package export

import (
	"context"
	"errors"
	"testing"
	"time"
)

// validJob —— 合法新建任务基准。
func validJob() Job {
	return Job{
		ID:        "job-0001",
		Type:      JobFlows,
		TimeStart: 1771901100,
		TimeEnd:   1771901100 + 3600,
		Format:    FormatText,
		Status:    StatusQueued,
	}
}

// TestValidateNewJob —— 新建任务校验表驱动（dd/04 §5.1）。
func TestValidateNewJob(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*Job)
		want error
	}{
		{"ok", func(*Job) {}, nil},
		{"ok attack_flows with id", func(j *Job) { j.Type = JobAttackFlows; j.AttackID = "01JTEST" }, nil},
		{"ok empty format defaults text", func(j *Job) { j.Format = "" }, nil},
		{"empty type", func(j *Job) { j.Type = "" }, ErrInvalidJob},
		{"bad type", func(j *Job) { j.Type = JobType("bogus") }, ErrInvalidJob},
		{"attack_flows without id", func(j *Job) { j.Type = JobAttackFlows }, ErrInvalidJob},
		{"zero start", func(j *Job) { j.TimeStart = 0 }, ErrInvalidJob},
		{"end<=start", func(j *Job) { j.TimeEnd = j.TimeStart }, ErrInvalidJob},
		{"window>72h", func(j *Job) { j.TimeEnd = j.TimeStart + int64(72*time.Hour/time.Second) + 1 }, ErrInvalidJob},
		{"window=72h ok", func(j *Job) { j.TimeEnd = j.TimeStart + int64(72*time.Hour/time.Second) }, nil},
		{"bad format", func(j *Job) { j.Format = Format("xlsx") }, ErrInvalidJob},
		{"bad sample", func(j *Job) { j.Sample = "half" }, ErrInvalidJob},
		{"sample downscale ok", func(j *Job) { j.Sample = "downscale_10x" }, nil},
		{"bad field", func(j *Job) { j.Fields = []string{"*"} }, ErrInvalidJob},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			j := validJob()
			c.mut(&j)
			err := ValidateNewJob(j)
			if c.want == nil {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if !errors.Is(err, c.want) {
				t.Fatalf("error = %v, want %v", err, c.want)
			}
		})
	}
}

// TestJobStateMachine —— 状态机迁移矩阵（queued→running→done|failed；终态锁死）。
func TestJobStateMachine(t *testing.T) {
	if !CanTransition(StatusQueued, StatusRunning) {
		t.Error("queued→running must be allowed")
	}
	if !CanTransition(StatusRunning, StatusDone) || !CanTransition(StatusRunning, StatusFailed) {
		t.Error("running→done|failed must be allowed")
	}
	for _, bad := range []struct{ from, to Status }{
		{StatusQueued, StatusDone}, {StatusQueued, StatusFailed},
		{StatusDone, StatusRunning}, {StatusDone, StatusFailed}, {StatusDone, StatusDone},
		{StatusFailed, StatusRunning}, {StatusFailed, StatusDone}, {StatusFailed, StatusFailed},
	} {
		if CanTransition(bad.from, bad.to) {
			t.Errorf("transition %s→%s must be rejected", bad.from, bad.to)
		}
	}

	j := validJob()
	if err := j.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	if err := j.Start(); err == nil {
		t.Fatal("running→running via Start must fail")
	}
	if err := j.Finish("exports/1/part-000001.txt.gz", 1771901200); err != nil {
		t.Fatalf("finish: %v", err)
	}
	if j.Status != StatusDone || j.Progress != 1 || j.URL == "" {
		t.Fatalf("finish state wrong: %+v", j)
	}
	if want := int64(1771901200 + 24*3600); j.ExpiresAt != want {
		t.Errorf("expires_at = %d, want %d (24h, docs/00 §6)", j.ExpiresAt, want)
	}
	if err := j.Fail("x"); err == nil {
		t.Fatal("done→failed must fail")
	}

	j2 := validJob()
	if err := j2.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	if err := j2.Fail("boom"); err != nil {
		t.Fatalf("fail: %v", err)
	}
	if j2.Status != StatusFailed || j2.Error != "boom" {
		t.Fatalf("fail state wrong: %+v", j2)
	}
	if !j2.Terminal() {
		t.Error("failed is terminal")
	}
}

// TestSetProgressClamp —— 进度截断 0..1。
func TestSetProgressClamp(t *testing.T) {
	j := validJob()
	j.SetProgress(-1)
	if j.Progress != 0 {
		t.Errorf("negative clamp: %v", j.Progress)
	}
	j.SetProgress(2)
	if j.Progress != 1 {
		t.Errorf("overflow clamp: %v", j.Progress)
	}
}

// TestMemoryStore —— 任务库增改查 + 状态机强校验。
func TestMemoryStore(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore(func() int64 { return 1771900000 })

	if err := s.Create(ctx, validJob()); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := s.Create(ctx, validJob()); !errors.Is(err, ErrDuplicateJobID) {
		t.Fatalf("duplicate create err = %v, want ErrDuplicateJobID", err)
	}
	bad := validJob()
	bad.ID = "job-0002"
	bad.Type = JobType("bogus")
	if err := s.Create(ctx, bad); !errors.Is(err, ErrInvalidJob) {
		t.Fatalf("invalid create err = %v, want ErrInvalidJob", err)
	}
	noQueued := validJob()
	noQueued.ID = "job-0003"
	noQueued.Status = StatusDone
	if err := s.Create(ctx, noQueued); err == nil {
		t.Fatal("create with non-queued status must fail")
	}

	got, err := s.Get(ctx, "job-0001")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Status != StatusQueued {
		t.Fatalf("status = %s", got.Status)
	}
	if _, err := s.Get(ctx, "nope"); !errors.Is(err, ErrJobNotFound) {
		t.Fatalf("missing get err = %v, want ErrJobNotFound", err)
	}

	got.Start()
	if err := s.Update(ctx, got); err != nil {
		t.Fatalf("update queued→running: %v", err)
	}
	got.SetProgress(0.5)
	if err := s.Update(ctx, got); err != nil { // 同状态原地进度更新
		t.Fatalf("update running→running: %v", err)
	}
	got.Status = StatusDone
	got.Progress = 1
	if err := s.Update(ctx, got); err != nil {
		t.Fatalf("update running→done: %v", err)
	}
	skip := got
	skip.Status = StatusRunning
	if err := s.Update(ctx, skip); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("done→running err = %v, want ErrInvalidTransition", err)
	}
	if err := s.Update(ctx, Job{ID: "ghost"}); !errors.Is(err, ErrJobNotFound) {
		t.Fatalf("ghost update err = %v", err)
	}
}

// TestMemoryProgressStore —— 进度桩读写。
func TestMemoryProgressStore(t *testing.T) {
	ctx := context.Background()
	p := NewMemoryProgressStore()
	d, tot, err := p.Get(ctx, "j1")
	if err != nil || d != 0 || tot != 0 {
		t.Fatalf("initial get = %d,%d,%v", d, tot, err)
	}
	if err := p.Set(ctx, "j1", 42, 100); err != nil {
		t.Fatalf("set: %v", err)
	}
	if d, tot, _ = p.Get(ctx, "j1"); d != 42 || tot != 100 {
		t.Fatalf("get = %d,%d", d, tot)
	}
	if err := p.Set(ctx, "", 1, 1); err == nil {
		t.Fatal("empty job id must fail")
	}
}

// TestMemoryCursorStore —— 游标续跑桩读写清。
func TestMemoryCursorStore(t *testing.T) {
	ctx := context.Background()
	c := NewMemoryCursorStore()
	if cur, err := c.Load(ctx, "j1"); err != nil || cur != "" {
		t.Fatalf("initial load = %q,%v", cur, err)
	}
	if err := c.Save(ctx, "j1", "500"); err != nil {
		t.Fatalf("save: %v", err)
	}
	if cur, _ := c.Load(ctx, "j1"); cur != "500" {
		t.Fatalf("load = %q", cur)
	}
	if err := c.Clear(ctx, "j1"); err != nil {
		t.Fatalf("clear: %v", err)
	}
	if cur, _ := c.Load(ctx, "j1"); cur != "" {
		t.Fatalf("after clear = %q", cur)
	}
	if err := c.Clear(ctx, "j1"); err != nil { // 幂等
		t.Fatalf("double clear: %v", err)
	}
	if err := c.Save(ctx, "", "x"); err == nil {
		t.Fatal("empty job id must fail")
	}
}
