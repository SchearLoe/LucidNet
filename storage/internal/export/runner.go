package export

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/SchearLoe/lucidnet/storage/internal/query"
)

// Runner 默认参数（docs/dd/04 §5.2：失败切片重试 3 次）。
const (
	DefaultBatchRows = 1000
	DefaultRetries   = 3
)

// WriterFactory —— 每任务构造产物写出流（真实实现：本地 NVMe 临时文件 →
// 分卷 2GB/卷 → 上传 MinIO exports/{job}/{part}.txt.gz，dd/04 §5.2；
// 骨架：单 writer、不分卷，TODO 见模块 README）。
type WriterFactory func(j Job) (io.Writer, error)

// Runner —— 导出任务执行器骨架（dd/04 §5.2 执行器）：
// 状态机迁移 + 游标续跑 + 进度上报 + 失败重试（3 次）+ 尾部收尾。
type Runner struct {
	store     Store
	progress  ProgressStore
	cursors   CursorStore
	source    RowSource
	writers   WriterFactory
	batchRows int
	retries   int
	nowSec    func() int64
}

// NewRunner 组装执行器；batchRows/retries ≤0 时取默认值。
func NewRunner(store Store, progress ProgressStore, cursors CursorStore,
	source RowSource, writers WriterFactory,
) (*Runner, error) {
	switch {
	case store == nil:
		return nil, fmt.Errorf("new runner: nil store")
	case progress == nil:
		return nil, fmt.Errorf("new runner: nil progress store")
	case cursors == nil:
		return nil, fmt.Errorf("new runner: nil cursor store")
	case source == nil:
		return nil, fmt.Errorf("new runner: nil row source")
	case writers == nil:
		return nil, fmt.Errorf("new runner: nil writer factory")
	}
	return &Runner{
		store:     store,
		progress:  progress,
		cursors:   cursors,
		source:    source,
		writers:   writers,
		batchRows: DefaultBatchRows,
		retries:   DefaultRetries,
		nowSec:    func() int64 { return time.Now().Unix() },
	}, nil
}

// SetBatchRows 覆盖单批行数（测试用）。
func (r *Runner) SetBatchRows(n int) {
	if n > 0 {
		r.batchRows = n
	}
}

// SetNow 注入秒级时钟（测试/统一时钟源用）。
func (r *Runner) SetNow(now func() int64) {
	if now != nil {
		r.nowSec = now
	}
}

// Run 执行任务至终态；ctx 取消时保留 running + 游标（可续跑）后返回。
// 终态任务幂等跳过（重跑保护）。
func (r *Runner) Run(ctx context.Context, jobID string) error {
	job, err := r.store.Get(ctx, jobID)
	if err != nil {
		return err
	}
	if job.Terminal() {
		return nil
	}
	if job.Status == StatusQueued {
		if err := job.Start(); err != nil {
			return err
		}
		if err := r.store.Update(ctx, job); err != nil {
			return fmt.Errorf("runner start job %s: %w", jobID, err)
		}
	}

	cursor, err := r.cursors.Load(ctx, jobID)
	if err != nil {
		return fmt.Errorf("runner load cursor job %s: %w", jobID, err)
	}

	w, err := r.writers(job)
	if err != nil {
		return r.fail(ctx, job, fmt.Sprintf("open writer: %v", err))
	}
	formatter, err := NewFormatter(job.Format, jobMeta(job))
	if err != nil {
		return r.fail(ctx, job, fmt.Sprintf("new formatter: %v", err))
	}
	// 续跑语义：骨架每次 Run 均新开 writer，头部注释随新分卷重复写入
	//（分卷拼接规则 TODO，见模块 README）；fresh 任务（无游标）才写头。
	if cursor == "" {
		if _, err := io.WriteString(w, formatter.Header(jobMeta(job))); err != nil {
			return r.fail(ctx, job, fmt.Sprintf("write header: %v", err))
		}
	}

	total := r.source.EstimateRows(ctx, job)
	var processed int64
	done := false
	for !done {
		if err := ctx.Err(); err != nil {
			// 保留 running + 已存游标：下次 Run 续跑（dd/04 §5.2 任务中断可续）
			return nil
		}
		rows, next, err := r.fetchWithRetry(ctx, job, cursor)
		if err != nil {
			return r.fail(ctx, job, err.Error())
		}
		for i := range rows {
			s, err := formatter.Row(rows[i])
			if err != nil {
				return r.fail(ctx, job, err.Error())
			}
			if _, err := io.WriteString(w, s); err != nil {
				return r.fail(ctx, job, fmt.Sprintf("write row: %v", err))
			}
		}
		processed += int64(len(rows))
		cursor = next
		if err := r.cursors.Save(ctx, jobID, cursor); err != nil {
			return r.fail(ctx, job, fmt.Sprintf("save cursor: %v", err))
		}
		if total > 0 {
			job.SetProgress(float64(processed) / float64(total))
		}
		if err := r.progress.Set(ctx, jobID, processed, total); err != nil {
			return r.fail(ctx, job, fmt.Sprintf("set progress: %v", err))
		}
		job.UpdatedAt = r.nowSec()
		if uerr := r.store.Update(ctx, job); uerr != nil {
			return fmt.Errorf("runner update progress job %s: %w", jobID, uerr)
		}
		if cursor == "" {
			done = true
		}
	}

	url := "exports/" + jobID + "/part-000001.txt.gz" // MinIO 对象键骨架（TODO 上传）
	if err := job.Finish(url, r.nowSec()); err != nil {
		return fmt.Errorf("runner finish job %s: %w", jobID, err)
	}
	if err := r.store.Update(ctx, job); err != nil {
		return fmt.Errorf("runner persist done job %s: %w", jobID, err)
	}
	_ = r.cursors.Clear(ctx, jobID)
	return nil
}

// fetchWithRetry —— 取数失败重试（dd/04 §5.2：失败切片重试 3 次）。
func (r *Runner) fetchWithRetry(ctx context.Context, j Job, cursor string) ([]Row, string, error) {
	var lastErr error
	for attempt := 0; attempt <= r.retries; attempt++ {
		rows, next, err := r.source.FetchRows(ctx, j, cursor, r.batchRows)
		if err == nil {
			return rows, next, nil
		}
		lastErr = err
		if ctx.Err() != nil {
			return nil, "", ctx.Err()
		}
	}
	return nil, "", fmt.Errorf("fetch rows after %d retries (cursor %q): %w", r.retries, cursor, lastErr)
}

// fail —— 任务落 failed 终态并返回错误。
func (r *Runner) fail(ctx context.Context, job Job, msg string) error {
	if err := job.Fail(msg); err != nil {
		return errors.Join(err, fmt.Errorf("runner fail job %s: %s", job.ID, msg))
	}
	if err := r.store.Update(ctx, job); err != nil {
		return fmt.Errorf("runner persist failed job %s: %w（原因: %s）", job.ID, err, msg)
	}
	return fmt.Errorf("export job %s failed: %s", job.ID, msg)
}

// jobMeta —— 任务 → 文件头取证元数据（docs/00 §7）。
func jobMeta(j Job) Meta {
	fields := j.Fields
	if len(fields) == 0 {
		fields = query.DefaultFields
	}
	return Meta{
		ZoneID:      j.ZoneID,
		ZoneName:    j.ZoneName,
		WindowStart: time.Unix(j.TimeStart, 0).UTC(),
		WindowEnd:   time.Unix(j.TimeEnd, 0).UTC(),
		Fields:      fields,
		Filters:     FilterSummary(j.Filters),
	}
}
