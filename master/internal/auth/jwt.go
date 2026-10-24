package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// JWT 签发/校验（docs/dd/07 §4）：HS256，Master 与网关共享密钥；
// claims {uid, tenant, roles, exp}。RS256 密钥对（LucidBGP 公钥验签）见 TODO。
//
// 说明：MVP 手写 HS256（header.payload.signature，base64url），不引入第三方 JWT 库；
// 算法白名单只允许 HS256，签名比较用 hmac.Equal 恒时比较。

// Typ —— token 用途（刷新令牌不得直接访问业务接口）。
const (
	TypAccess  = "access"
	TypRefresh = "refresh"
)

// DefaultAccessTTL / DefaultRefreshTTL —— hld/07 §2：JWT 签发 15min + 刷新。
const (
	DefaultAccessTTL  = 15 * time.Minute
	DefaultRefreshTTL = 12 * time.Hour
)

// Claims —— JWT 载荷（docs/dd/07 §4）。
type Claims struct {
	UID           int64    `json:"uid"`
	UserName      string   `json:"name"`   // 登录名（审计/回查）
	Tenant        string   `json:"tenant"` // 平台管理员为空（租户隔离豁免）
	Roles         []string `json:"roles"`
	PlatformAdmin bool     `json:"platform_admin,omitempty"`
	Typ           string   `json:"typ"`
	IssuedAt      int64    `json:"iat"`
	ExpiresAt     int64    `json:"exp"`
}

var (
	ErrTokenExpired = errors.New("token expired")
	ErrTokenInvalid = errors.New("token invalid")
)

// Signer —— HS256 签发器。
type Signer struct {
	secret []byte
	now    func() time.Time
}

// NewSigner 构造签名器；now 可注入（测试），nil 取 time.Now。
func NewSigner(secret string, now func() time.Time) *Signer {
	if now == nil {
		now = time.Now
	}
	return &Signer{secret: []byte(secret), now: now}
}

// Sign 签发 token（claims.Exp 由调用方按 TTL 设置；0 时默认不给过期，仅限测试）。
func (s *Signer) Sign(c Claims) (string, error) {
	now := s.now().Unix()
	c.IssuedAt = now
	if c.ExpiresAt == 0 {
		c.ExpiresAt = now + int64(DefaultAccessTTL.Seconds())
	}
	if c.Typ == "" {
		c.Typ = TypAccess
	}
	header := base64url([]byte(`{"alg":"HS256","typ":"JWT"}`))
	payload, err := json.Marshal(c)
	if err != nil {
		return "", fmt.Errorf("marshal jwt claims: %w", err)
	}
	signing := header + "." + base64url(payload)
	mac := hmac.New(sha256.New, s.secret)
	mac.Write([]byte(signing))
	return signing + "." + base64url(mac.Sum(nil)), nil
}

// Verify 校验并解析 token（只接受 HS256；校验 exp）。
func (s *Signer) Verify(token string) (*Claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, ErrTokenInvalid
	}
	headerRaw, err := base64urlDecode(parts[0])
	if err != nil {
		return nil, fmt.Errorf("%w: header", ErrTokenInvalid)
	}
	var header struct {
		Alg string `json:"alg"`
	}
	if err := json.Unmarshal(headerRaw, &header); err != nil || header.Alg != "HS256" {
		return nil, fmt.Errorf("%w: alg", ErrTokenInvalid)
	}
	mac := hmac.New(sha256.New, s.secret)
	mac.Write([]byte(parts[0] + "." + parts[1]))
	want := mac.Sum(nil)
	got, err := base64urlDecode(parts[2])
	if err != nil || !hmac.Equal(want, got) {
		return nil, fmt.Errorf("%w: signature", ErrTokenInvalid)
	}
	payloadRaw, err := base64urlDecode(parts[1])
	if err != nil {
		return nil, fmt.Errorf("%w: payload", ErrTokenInvalid)
	}
	var c Claims
	if err := json.Unmarshal(payloadRaw, &c); err != nil {
		return nil, fmt.Errorf("%w: payload json", ErrTokenInvalid)
	}
	if s.now().Unix() > c.ExpiresAt {
		return nil, ErrTokenExpired
	}
	return &c, nil
}

func base64url(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

func base64urlDecode(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}
