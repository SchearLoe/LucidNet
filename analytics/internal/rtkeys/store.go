package rtkeys

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

// TTL（09 §6 裁定；dd/03 §7 / §6.1 同口径）。
const (
	// TopNTTL —— Top-K 键过期：10 分钟。
	TopNTTL = 10 * time.Minute
	// EvidenceTTL —— 证据快照键过期：24 小时。
	EvidenceTTL = 24 * time.Hour
)

// 键成分校验。
const (
	maxDimLen      = 32
	maxAttackIDLen = 64
)

var (
	// ErrInvalidDim —— TopN 维度名不合规（小写字母/数字/下划线，≤32 字符）。
	ErrInvalidDim = errors.New("rtkeys: invalid topn dim")
	// ErrInvalidAttackID —— attack id 为空或超长（ULID 26 字符，上限 64）。
	ErrInvalidAttackID = errors.New("rtkeys: invalid attack id")
)

// ValidDim —— TopN 维度名白名单：非空、[a-z0-9_]、≤32 字符。
func ValidDim(dim string) bool {
	if dim == "" || len(dim) > maxDimLen {
		return false
	}
	for i := 0; i < len(dim); i++ {
		c := dim[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_') {
			return false
		}
	}
	return true
}

// ValidAttackID —— attack id 非空且 ≤64 字符。
func ValidAttackID(id string) bool {
	return id != "" && len(id) <= maxAttackIDLen
}

// Store —— Redis 实时键读写接口（M2 接真实客户端，09 §6；键名/TTL 由本包裁定，
// 实现不得自行拼接键）。
type Store interface {
	// SetTopN —— 写滚动 Top-K 载荷：键 TopN(dim, tsSec)，TTL=TopNTTL。
	SetTopN(ctx context.Context, dim string, tsSec int64, payload []byte) error
	// SetEvidence —— 写攻击证据快照：键 Evidence(attackID)，TTL=EvidenceTTL。
	SetEvidence(ctx context.Context, attackID string, payload []byte) error
	// Get —— 按完整键读取（过期视同不存在）；开发自检/测试用。
	Get(ctx context.Context, key string) ([]byte, bool)
}

// DevStore —— Store 内存实现（开发/单测；TTL 以注入时钟判定，惰性过期）。
// 并发安全（内存桩可能被事件循环与读取方共同触碰，与引擎的免锁结构无关）。
type DevStore struct {
	mu  sync.Mutex
	now func() time.Time
	m   map[string]devEntry
}

type devEntry struct {
	payload  []byte
	expireAt time.Time
}

// Option —— 构造选项（docs/11 §3）。
type Option func(*DevStore)

// WithClock 注入时间源（TTL 判定确定性单测）。
func WithClock(now func() time.Time) Option {
	return func(s *DevStore) {
		if now != nil {
			s.now = now
		}
	}
}

// NewDevStore 构造内存实时键存储。
func NewDevStore(opts ...Option) *DevStore {
	s := &DevStore{now: time.Now, m: make(map[string]devEntry)}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// SetTopN 实现 Store（维度名经 ValidDim 校验）。
func (s *DevStore) SetTopN(_ context.Context, dim string, tsSec int64, payload []byte) error {
	if !ValidDim(dim) {
		return fmt.Errorf("rtkeys: set topn %q: %w", dim, ErrInvalidDim)
	}
	s.set(TopN(dim, tsSec), payload, TopNTTL)
	return nil
}

// SetEvidence 实现 Store（attack id 非空校验）。
func (s *DevStore) SetEvidence(_ context.Context, attackID string, payload []byte) error {
	if !ValidAttackID(attackID) {
		return fmt.Errorf("rtkeys: set evidence %q: %w", attackID, ErrInvalidAttackID)
	}
	s.set(Evidence(attackID), payload, EvidenceTTL)
	return nil
}

// Get 实现 Store（惰性清除过期项）。
func (s *DevStore) Get(_ context.Context, key string) ([]byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.m[key]
	if !ok || !s.now().Before(e.expireAt) {
		delete(s.m, key)
		return nil, false
	}
	return e.payload, true
}

// Len —— 未过期键数（统计/测试）。
func (s *DevStore) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	now := s.now()
	for k, e := range s.m {
		if now.Before(e.expireAt) {
			n++
		} else {
			delete(s.m, k)
		}
	}
	return n
}

func (s *DevStore) set(key string, payload []byte, ttl time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[key] = devEntry{payload: append([]byte(nil), payload...), expireAt: s.now().Add(ttl)}
}
