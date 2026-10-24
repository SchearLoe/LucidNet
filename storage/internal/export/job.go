package export

import (
	"errors"
	"fmt"
	"time"

	"github.com/SchearLoe/lucidnet/storage/internal/query"
)

// 任务参数约束（docs/dd/04 §5.1/§5.3）。
const (
	// MaxJobWindow —— 异步导出时间窗上限（dd/04 §5.1：≤72h）。
	MaxJobWindow = 72 * time.Hour
	// LinkTTL —— 导出产物下载链接有效期（docs/00 §6：24h）。
	LinkTTL = 24 * time.Hour
)

// JobType —— 导出任务类型（docs/dd/04 §5.1：flows|attack_flows|aggr|attacks）。
type JobType string

// 导出任务类型枚举。
const (
	JobFlows       JobType = "flows"        // R6 大窗口明细
	JobAttackFlows JobType = "attack_flows" // R5 攻击取证（自动填充窗口+zone）
	JobAggr        JobType = "aggr"         // 聚合数据
	JobAttacks     JobType = "attacks"      // 攻击列表/分钟数据
)

// Status —— 任务状态机（docs/dd/04 §5.1：queued|running|done|failed）。
type Status string

// 任务状态枚举。
const (
	StatusQueued  Status = "queued"
	StatusRunning Status = "running"
	StatusDone    Status = "done"
	StatusFailed  Status = "failed"
)

// 任务模型哨兵错误。
var (
	ErrInvalidJob        = errors.New("invalid export job")
	ErrJobNotFound       = errors.New("export job not found")
	ErrInvalidTransition = errors.New("invalid export job status transition")
	ErrDuplicateJobID    = errors.New("duplicate export job id")
)

// validTransitions —— 状态机迁移表（终态 done/failed 不可再迁移）。
var validTransitions = map[Status][]Status{
	StatusQueued:  {StatusRunning},
	StatusRunning: {StatusDone, StatusFailed},
	StatusDone:    {},
	StatusFailed:  {},
}

// CanTransition —— from→to 是否为合法状态迁移。
func CanTransition(from, to Status) bool {
	for _, s := range validTransitions[from] {
		if s == to {
			return true
		}
	}
	return false
}

// Job —— 导出任务模型（docs/dd/04 §5.1）。
// 时间参数 epoch 秒（docs/09 §6 裁定：跨模块查询 API 统一 epoch 秒）。
type Job struct {
	ID        string        `json:"job_id"`
	Type      JobType       `json:"type"`
	AttackID  string        `json:"attack_id,omitempty"` // attack_flows 时必填，Console 预填窗口+zone
	ZoneID    int32         `json:"zone_id"`
	ZoneName  string        `json:"zone_name,omitempty"`
	TimeStart int64         `json:"time_start"` // epoch 秒
	TimeEnd   int64         `json:"time_end"`   // epoch 秒
	Fields    []string      `json:"fields,omitempty"`
	Filters   query.Filters `json:"filters,omitempty"`
	Format    Format        `json:"format"` // text|csv|jsonl（默认 text）
	Sample    string        `json:"sample"` // raw|downscale_10x（dd/04 §5.1）
	Status    Status        `json:"status"`
	Progress  float64       `json:"progress"`             // 0..1
	URL       string        `json:"url,omitempty"`        // 产物下载（MinIO exports/{job}/{part}.txt.gz）
	ExpiresAt int64         `json:"expires_at,omitempty"` // epoch 秒；done 时 = 完成+24h
	Error     string        `json:"error,omitempty"`
	CreatedAt int64         `json:"created_at"` // epoch 秒
	UpdatedAt int64         `json:"updated_at"` // epoch 秒
}

// Window 返回任务时间窗时长。
func (j Job) Window() time.Duration { return time.Duration(j.TimeEnd-j.TimeStart) * time.Second }

// ValidateNewJob —— 新建任务校验（dd/04 §5.1）。
func ValidateNewJob(j Job) error {
	switch j.Type {
	case JobFlows, JobAttackFlows, JobAggr, JobAttacks:
	case "":
		return fmt.Errorf("validate job %s: empty type: %w", j.ID, ErrInvalidJob)
	default:
		return fmt.Errorf("validate job %s: type %q not in {flows,attack_flows,aggr,attacks}: %w", j.ID, j.Type, ErrInvalidJob)
	}
	if j.Type == JobAttackFlows && j.AttackID == "" {
		return fmt.Errorf("validate job %s: attack_flows requires attack_id: %w", j.ID, ErrInvalidJob)
	}
	if j.TimeStart <= 0 || j.TimeEnd <= j.TimeStart {
		return fmt.Errorf("validate job %s: time window %d..%d: %w", j.ID, j.TimeStart, j.TimeEnd, ErrInvalidJob)
	}
	if j.Window() > MaxJobWindow {
		return fmt.Errorf("validate job %s: window %s exceeds %s: %w", j.ID, j.Window(), MaxJobWindow, ErrInvalidJob)
	}
	switch j.Format {
	case FormatText, FormatCSV, FormatJSONL, "":
	default:
		return fmt.Errorf("validate job %s: format %q: %w", j.ID, j.Format, ErrInvalidJob)
	}
	switch j.Sample {
	case "", "raw", "downscale_10x":
	default:
		return fmt.Errorf("validate job %s: sample %q not in {raw,downscale_10x}: %w", j.ID, j.Sample, ErrInvalidJob)
	}
	if _, err := query.CheckFields(j.Fields); err != nil {
		return fmt.Errorf("validate job %s: %v: %w", j.ID, err, ErrInvalidJob)
	}
	return nil
}

// Start —— queued→running。
func (j *Job) Start() error {
	if !CanTransition(j.Status, StatusRunning) {
		return fmt.Errorf("job %s: %s→%s: %w", j.ID, j.Status, StatusRunning, ErrInvalidTransition)
	}
	j.Status = StatusRunning
	j.Progress = 0
	return nil
}

// SetProgress —— running 内更新进度（非状态迁移；0..1 截断）。
func (j *Job) SetProgress(p float64) {
	if p < 0 {
		p = 0
	}
	if p > 1 {
		p = 1
	}
	j.Progress = p
}

// Finish —— running→done；记录产物 URL 与 24h 有效期（docs/00 §6）。
func (j *Job) Finish(url string, nowSec int64) error {
	if !CanTransition(j.Status, StatusDone) {
		return fmt.Errorf("job %s: %s→%s: %w", j.ID, j.Status, StatusDone, ErrInvalidTransition)
	}
	j.Status = StatusDone
	j.Progress = 1
	j.URL = url
	j.ExpiresAt = nowSec + int64(LinkTTL/time.Second)
	return nil
}

// Fail —— running→failed；记录错误摘要。
func (j *Job) Fail(msg string) error {
	if !CanTransition(j.Status, StatusFailed) {
		return fmt.Errorf("job %s: %s→%s: %w", j.ID, j.Status, StatusFailed, ErrInvalidTransition)
	}
	j.Status = StatusFailed
	j.Error = msg
	return nil
}

// Terminal —— 任务是否处于终态（幂等重跑保护）。
func (j Job) Terminal() bool { return j.Status == StatusDone || j.Status == StatusFailed }
