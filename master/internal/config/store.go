package config

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"
)

// 配置版本与发布（docs/dd/07 §5 / hld/07 §4）：
//
//	Console/gRPC 触发 → Master 校验（schema+业务规则）→ PG 事务（权威）→
//	etcd 发布（version++，各组件 watch 接收）→ 节点经 Heartbeat 通道 ACK →
//	全 ACK 标 active；180s 未全 ACK：标 partial 回告警（保留运行，差异窗口记录）。
//	etcd 发布失败即拒绝变更 —— 对应 etcd 多数派丢失时"集群只读保护"（docs/dd/07 §7）。
//
// PG 持久化补偿重试（docs/dd/07 §1 "失败补偿重试队列"）：发布失败版本标 failed +
// 落 outbox（migration 0002 config_outbox）→ Run 循环按指数退避重投 → 成功关单转
// published 并恢复 ACK 跟踪，或人工取消关单；Master 重启扫描 pending 续补。

// VersionState —— 版本状态。
type VersionState string

const (
	VersionPublished  VersionState = "published" // 已发布 etcd，等待 ACK
	VersionActive     VersionState = "active"    // 全部目标节点 ACK
	VersionPartial    VersionState = "partial"   // 超时未全 ACK（已 ACK 节点运行新版本）
	VersionFailed     VersionState = "failed"    // PG 已落、etcd 未发布（补偿重试中）
	VersionRolledBack VersionState = "rolled_back"
)

// Version —— 配置版本记录。
type Version struct {
	Scope     string
	Version   uint64
	State     VersionState
	DataJSON  []byte
	CreatedBy string
	CreatedAt time.Time
	// ACK 汇总：Required=目标节点，Acked=已确认节点（内存维护，落库为 ack_summary）
	Required   []string
	Acked      []string
	RollbackOf uint64 // >0 表示由该版本回滚产生
}

// AckSummary —— ack_summary JSONB 列结构。
type AckSummary struct {
	Required []string `json:"required"`
	Acked    []string `json:"acked"`
}

// VersionsStore —— 版本台账存储抽象（PG 权威 + 内存桩）。
type VersionsStore interface {
	SaveVersion(ctx context.Context, v Version, summary AckSummary) error
	GetVersion(ctx context.Context, scope string, version uint64) (Version, error)
	LatestVersion(ctx context.Context, scope string) (Version, error)
	ListVersions(ctx context.Context, scope string, limit int) ([]Version, error)
	SetVersionState(ctx context.Context, scope string, version uint64, st VersionState, summary AckSummary) error
	TrimVersions(ctx context.Context, scope string, keep int) error
	Close() error
}

// ErrNotFound —— 版本不存在。
var ErrNotFound = errors.New("config: version not found")

// Publisher —— etcd 发布抽象（键空间 docs/09 §5）。
type Publisher interface {
	Publish(ctx context.Context, scope string, env Envelope) error
}

// NopPublisher —— 无 etcd 开发模式空实现（仅内存版本台账）。
type NopPublisher struct{}

// Publish 实现 Publisher。
func (NopPublisher) Publish(context.Context, string, Envelope) error { return nil }

// TargetResolver —— 作用域目标节点解析（在线节点中的受影响角色）。
type TargetResolver interface {
	ResolveTargets(ctx context.Context, scope string) ([]string, error)
}

// CmdSink —— reload 命令下发（经 Heartbeat 下行流；docs/09 §9-⑤：配置数据走 etcd
// watch，命令仅作"版本已更新，请应用"的触发与 ACK 载体）。
type CmdSink interface {
	SendReload(ctx context.Context, nodeID, cmdID, scope string, version uint64) error
}

// Observability —— 发布链路可观测钩子（Prometheus 指标由装配层注入实现；nil 忽略）。
type Observability interface {
	// PublishAttempt 每次 etcd 发布尝试（首投与补偿重投）后回调。
	PublishAttempt(scope string, err error, elapsed time.Duration)
	// AckPartial ACK 超时标 partial 时回调。
	AckPartial(scope string, version uint64, acked, required int)
	// OutboxDepth 补偿队列 pending 深度采样（每轮扫描回调一次）。
	OutboxDepth(pending int)
}

// Options —— Store 装配项。
type Options struct {
	KeepVersions int           // 每作用域保留版本数（hld/07 §4：最近 20）
	AckTimeout   time.Duration // 全 ACK 等待（dd/07 §5：180s）
	Publisher    Publisher
	Targets      TargetResolver
	CmdSink      CmdSink
	Validators   map[string]Validator
	Now          func() time.Time
	// Outbox —— 持久化补偿队列（nil = 内存实现，仅开发模式）
	Outbox OutboxStore
	// PollEvery —— 补偿扫描周期（默认 500ms）
	PollEvery time.Duration
	// RetryBase / RetryMax —— 重投指数退避基数与上限（默认 1s / 5min：
	// 1s→2s→4s→…→封顶 5min）
	RetryBase time.Duration
	RetryMax  time.Duration
	// Obs —— 可观测钩子（nil 忽略）
	Obs Observability
}

// Validator —— 作用域数据校验函数。
type Validator func(data []byte) error

// DefaultValidators —— 内置校验表。
func DefaultValidators() map[string]Validator {
	return map[string]Validator{
		ScopeZones:        ValidateZones,
		ScopeForwardRules: ValidateForwardRules,
		ScopeAnalytics:    ValidateJSONDoc,
		// /lucid/config/collector/{node} 由 validatorFor 动态匹配
	}
}

func (o *Options) fill() {
	if o.KeepVersions <= 0 {
		o.KeepVersions = 20
	}
	if o.AckTimeout <= 0 {
		o.AckTimeout = 180 * time.Second
	}
	if o.Publisher == nil {
		o.Publisher = NopPublisher{}
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Outbox == nil {
		o.Outbox = NewMemOutbox()
	}
	if o.PollEvery <= 0 {
		o.PollEvery = 500 * time.Millisecond
	}
	if o.RetryBase <= 0 {
		o.RetryBase = time.Second
	}
	if o.RetryMax <= 0 {
		o.RetryMax = 5 * time.Minute
	}
}

// ErrReadOnly —— 集群只读保护（非 leader / etcd 不可用）。
var ErrReadOnly = errors.New("cluster is read-only: config changes rejected")

// Store —— 配置管理入口。
type Store struct {
	versions VersionsStore
	opts     Options
	outbox   OutboxStore

	mu       sync.Mutex
	trackers map[string]*ackTracker // scope → 进行中的 ACK 跟踪
	closed   chan struct{}
}

// NewStore 构造配置管理器。
func NewStore(versions VersionsStore, opts Options) *Store {
	opts.fill()
	if opts.Validators == nil {
		opts.Validators = DefaultValidators()
	}
	return &Store{
		versions: versions,
		opts:     opts,
		outbox:   opts.Outbox,
		trackers: map[string]*ackTracker{},
		closed:   make(chan struct{}),
	}
}

// Run —— 补偿重试循环：周期扫描 outbox pending（Master 重启扫描 pending 续补），
// 到期条目重投 etcd；成功关单转 published，失败按指数退避顺延（docs/dd/07 §1）。
func (s *Store) Run(ctx context.Context) {
	t := time.NewTicker(s.opts.PollEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.closed:
			return
		case <-t.C:
			s.processDue(ctx)
		}
	}
}

// processDue 扫描到期补偿单并重投。
func (s *Store) processDue(ctx context.Context) {
	now := s.opts.Now()
	entries, err := s.outbox.PendingDue(ctx, now, 16)
	if err != nil {
		log.Printf(`{"level":"error","module":"master.config","msg":"outbox scan","err":%q}`, err.Error())
		return
	}
	if s.opts.Obs != nil {
		if n, err := s.outbox.PendingCount(ctx); err == nil {
			s.opts.Obs.OutboxDepth(n)
		}
	}
	for _, e := range entries {
		s.retryOne(ctx, e)
	}
}

// retryOne 单条补偿重投。
func (s *Store) retryOne(ctx context.Context, e OutboxEntry) {
	env := Envelope{Version: e.Version, UpdatedAt: s.opts.Now(), Data: e.Payload}
	start := s.opts.Now()
	err := s.opts.Publisher.Publish(ctx, e.Scope, env)
	elapsed := s.opts.Now().Sub(start)
	if s.opts.Obs != nil {
		s.opts.Obs.PublishAttempt(e.Scope, err, elapsed)
	}
	if err != nil {
		next := s.opts.Now().Add(s.backoff(e.Attempt + 1))
		if merr := s.outbox.MarkAttempt(ctx, e.ID, next, err.Error()); merr != nil {
			log.Printf(`{"level":"error","module":"master.config","msg":"outbox mark attempt","id":%d,"err":%q}`, e.ID, merr.Error())
		}
		log.Printf(`{"level":"warn","module":"master.config","msg":"publish retry failed","scope":%q,"version":%d,"attempt":%d,"next_retry":%q,"err":%q}`,
			e.Scope, e.Version, e.Attempt+1, next.Format(time.RFC3339), err.Error())
		return
	}
	if err := s.outbox.MarkDone(ctx, e.ID); err != nil {
		log.Printf(`{"level":"error","module":"master.config","msg":"outbox close","id":%d,"err":%q}`, e.ID, err.Error())
	}
	// 关单 → 版本转 published + 恢复 ACK 跟踪 + reload 触发（与首投成功同路径）
	_ = s.versions.SetVersionState(ctx, e.Scope, e.Version, VersionPublished,
		AckSummary{Required: e.Required})
	s.beginAckWatch(ctx, e.Scope, e.Version, e.Required)
	s.dispatchReload(ctx, e.Scope, e.Version, e.Required)
	log.Printf(`{"level":"info","module":"master.config","msg":"publish retry recovered","scope":%q,"version":%d,"attempts":%d}`,
		e.Scope, e.Version, e.Attempt+1)
}

// backoff 第 attempt 次重试的退避时长：base×2^(attempt-1)，封顶 RetryMax。
func (s *Store) backoff(attempt int) time.Duration {
	d := s.opts.RetryBase
	for i := 1; i < attempt; i++ {
		d *= 2
		if d >= s.opts.RetryMax {
			return s.opts.RetryMax
		}
	}
	return d
}

// CancelPending 人工取消待重试补偿单（版本保持 failed；经重发新版本恢复，docs/dd/07 §1）。
func (s *Store) CancelPending(ctx context.Context, scope string, version uint64) error {
	return s.outbox.Cancel(ctx, scope, version)
}

// PendingOutbox 待重试补偿单（运维查询）。
func (s *Store) PendingOutbox(ctx context.Context) ([]OutboxEntry, error) {
	return s.outbox.ListPending(ctx)
}

// Close 停止补偿循环与底层存储。
func (s *Store) Close() error {
	select {
	case <-s.closed:
	default:
		close(s.closed)
	}
	if err := s.outbox.Close(); err != nil {
		return err
	}
	return s.versions.Close()
}

func (s *Store) validatorFor(scope string) Validator {
	if v, ok := s.opts.Validators[scope]; ok {
		return v
	}
	if _, ok := IsCollectorScope(scope); ok {
		return ValidateJSONDoc
	}
	return nil
}

// Publish 发布配置（REST /api/v1/admin/publish 与 gRPC PublishConfig 共同入口）。
func (s *Store) Publish(ctx context.Context, scope string, data []byte, actor string) (uint64, error) {
	if !ValidScope(scope) {
		return 0, fmt.Errorf("invalid config scope %q", scope)
	}
	if s.opts.Targets == nil {
		return 0, ErrReadOnly // 未装配目标解析（无 etcd/leader 通道）→ 只读保护
	}
	vfn := s.validatorFor(scope)
	if vfn == nil {
		return 0, fmt.Errorf("no validator registered for scope %q", scope)
	}
	if err := vfn(data); err != nil {
		return 0, fmt.Errorf("config validation failed for %s: %w", scope, err)
	}
	latest, err := s.versions.LatestVersion(ctx, scope)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return 0, fmt.Errorf("query latest version for %s: %w", scope, err)
	}
	next := latest.Version + 1
	targets, err := s.opts.Targets.ResolveTargets(ctx, scope)
	if err != nil {
		return 0, fmt.Errorf("resolve targets for %s: %w", scope, err)
	}
	v := Version{
		Scope: scope, Version: next, State: VersionPublished,
		DataJSON: append([]byte(nil), data...), CreatedBy: actor,
		CreatedAt: s.opts.Now(), Required: targets,
	}
	// ① PG 权威（docs/dd/07 §1：PG 权威 → 事务后发 etcd）
	if err := s.versions.SaveVersion(ctx, v, AckSummary{Required: targets}); err != nil {
		return 0, fmt.Errorf("save version for %s: %w", scope, err)
	}
	// ② etcd 发布（失败 → 只读保护语义 + outbox 持久化补偿）
	env := Envelope{Version: next, UpdatedAt: s.opts.Now(), Data: v.DataJSON}
	pubStart := s.opts.Now()
	pubErr := s.opts.Publisher.Publish(ctx, scope, env)
	if s.opts.Obs != nil {
		s.opts.Obs.PublishAttempt(scope, pubErr, s.opts.Now().Sub(pubStart))
	}
	if pubErr != nil {
		_ = s.versions.SetVersionState(ctx, scope, next, VersionFailed, AckSummary{})
		entry := OutboxEntry{
			Scope: scope, Version: next, Payload: v.DataJSON, Required: targets,
			NextRetry: s.opts.Now().Add(s.backoff(1)),
		}
		if err := s.outbox.Enqueue(ctx, &entry); err != nil {
			// PG 亦不可用（灾难场景）：只读保护语义不变，显式告警日志等待人工介入
			log.Printf(`{"level":"error","module":"master.config","msg":"outbox enqueue failed","scope":%q,"version":%d,"err":%q}`,
				scope, next, err.Error())
		}
		return 0, fmt.Errorf("publish %s v%d to etcd: %w", scope, next, pubErr)
	}
	// ③ ACK 跟踪 + reload 触发
	s.beginAckWatch(ctx, scope, next, targets)
	s.dispatchReload(ctx, scope, next, targets)
	// ④ 版本保留窗口
	if err := s.versions.TrimVersions(ctx, scope, s.opts.KeepVersions); err != nil {
		log.Printf(`{"level":"warn","module":"master.config","msg":"trim versions","scope":%q,"err":%q}`, scope, err.Error())
	}
	return next, nil
}

func (s *Store) dispatchReload(ctx context.Context, scope string, version uint64, targets []string) {
	if s.opts.CmdSink == nil || len(targets) == 0 {
		return
	}
	cmdID := fmt.Sprintf("%s#v%d#%d", scope, version, s.opts.Now().UnixNano())
	for _, node := range targets {
		if err := s.opts.CmdSink.SendReload(ctx, node, cmdID, scope, version); err != nil {
			log.Printf(`{"level":"warn","module":"master.config","msg":"send reload","node":%q,"scope":%q,"err":%q}`,
				node, scope, err.Error())
		}
	}
}

// ackTracker —— 单次发布的 ACK 跟踪。
type ackTracker struct {
	scope    string
	version  uint64
	required map[string]bool
	mu       sync.Mutex
	timer    *time.Timer
}

func (s *Store) beginAckWatch(ctx context.Context, scope string, version uint64, targets []string) {
	if len(targets) == 0 { // 无在线目标：直接 active（空集群语义）
		_ = s.versions.SetVersionState(ctx, scope, version, VersionActive, AckSummary{})
		return
	}
	t := &ackTracker{scope: scope, version: version, required: map[string]bool{}}
	for _, n := range targets {
		t.required[n] = false
	}
	t.timer = time.AfterFunc(s.opts.AckTimeout, func() { s.ackTimeout(scope, version) })
	s.mu.Lock()
	if old, ok := s.trackers[scope]; ok {
		old.timer.Stop()
	}
	s.trackers[scope] = t
	s.mu.Unlock()
}

func (s *Store) ackTimeout(scope string, version uint64) {
	s.mu.Lock()
	t, ok := s.trackers[scope]
	if !ok || t.version != version {
		s.mu.Unlock()
		return
	}
	delete(s.trackers, scope)
	s.mu.Unlock()
	// 180s 未全 ACK：标 partial 回告警；已 ACK 节点继续新版本，差异窗口记录（docs/dd/07 §5）
	t.mu.Lock()
	acked := t.ackedLocked()
	required := keysOf(t.required)
	t.mu.Unlock()
	_ = s.versions.SetVersionState(context.Background(), scope, version, VersionPartial,
		AckSummary{Required: required, Acked: acked})
	if s.opts.Obs != nil {
		s.opts.Obs.AckPartial(scope, version, len(acked), len(required))
	}
	log.Printf(`{"level":"warn","module":"master.config","msg":"config ack timeout","scope":%q,"version":%d,"acked":%d,"required":%d}`,
		scope, version, len(acked), len(required))
}

func (t *ackTracker) ackedLocked() []string {
	var acked []string
	for n, ok := range t.required {
		if ok {
			acked = append(acked, n)
		}
	}
	return acked
}

func keysOf(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// Ack 节点回执（Heartbeat 通道 metrics_json.ack）。
func (s *Store) Ack(ctx context.Context, nodeID, scope string, version uint64, ok bool, errMsg string) error {
	s.mu.Lock()
	t, tracking := s.trackers[scope]
	s.mu.Unlock()
	if !tracking || t.version != version {
		return nil // 非进行中版本（迟到的 ACK）——幂等忽略
	}
	if _, target := t.required[nodeID]; !target {
		return nil
	}
	if !ok {
		log.Printf(`{"level":"warn","module":"master.config","msg":"config apply failed on node","node":%q,"scope":%q,"version":%d,"err":%q}`,
			nodeID, scope, version, errMsg)
		return nil
	}
	t.mu.Lock()
	t.required[nodeID] = true
	acked := t.ackedLocked()
	done := len(acked) == len(t.required)
	t.mu.Unlock()
	if done {
		s.mu.Lock()
		if cur, exists := s.trackers[scope]; exists && cur == t {
			delete(s.trackers, scope)
		}
		s.mu.Unlock()
		t.timer.Stop()
		return s.versions.SetVersionState(ctx, scope, version, VersionActive,
			AckSummary{Required: keysOf(t.required), Acked: acked})
	}
	return nil
}

// Current 当前生效快照（内存版本台账最新记录；RegisterNode 角色配置组包用）。
func (s *Store) Current(ctx context.Context, scope string) (Envelope, error) {
	v, err := s.versions.LatestVersion(ctx, scope)
	if err != nil {
		return Envelope{}, err
	}
	return Envelope{Version: v.Version, UpdatedAt: v.CreatedAt, Data: v.DataJSON}, nil
}

// Rollback 回滚：历史版本快照以新版本重新发布（单调 version，docs/dd/07 §5）。
func (s *Store) Rollback(ctx context.Context, scope string, toVersion uint64, actor string) (uint64, error) {
	v, err := s.versions.GetVersion(ctx, scope, toVersion)
	if err != nil {
		return 0, fmt.Errorf("get version %s v%d: %w", scope, toVersion, err)
	}
	latest, err := s.versions.LatestVersion(ctx, scope)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return 0, fmt.Errorf("query latest for %s: %w", scope, err)
	}
	if toVersion >= latest.Version {
		return 0, fmt.Errorf("cannot rollback to non-historical version %d", toVersion)
	}
	return s.Publish(ctx, scope, v.DataJSON, actor+":rollback")
}

// ListVersions 版本历史（新→旧）。
func (s *Store) ListVersions(ctx context.Context, scope string, limit int) ([]Version, error) {
	if limit <= 0 {
		limit = s.opts.KeepVersions
	}
	return s.versions.ListVersions(ctx, scope, limit)
}

// GetVersion 单版本查询。
func (s *Store) GetVersion(ctx context.Context, scope string, version uint64) (Version, error) {
	return s.versions.GetVersion(ctx, scope, version)
}
