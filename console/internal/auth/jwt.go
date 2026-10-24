package auth

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// ErrInvalidToken —— token 缺失/格式错误/签名不符/过期。
var ErrInvalidToken = errors.New("invalid bearer token")

// Verifier —— HS256 JWT 校验器（docs/dd/07：Master 与网关共享密钥，claims={uid,tenant,roles,exp}）。
type Verifier struct {
	secret []byte
	now    func() time.Time
}

// NewVerifier 构造校验器；secret 为与 Master 共享的 HS256 密钥。
func NewVerifier(secret []byte) *Verifier {
	return &Verifier{secret: secret, now: time.Now}
}

// WithClock 注入时间源（确定性单测，docs/11 §3 Option 惯例）。
func (v *Verifier) WithClock(now func() time.Time) *Verifier {
	v.now = now
	return v
}

// Verify 解析并校验 Bearer token，返回 Claims。
func (v *Verifier) Verify(raw string) (*Claims, error) {
	mc := jwt.MapClaims{}
	_, err := jwt.ParseWithClaims(raw, mc, func(*jwt.Token) (any, error) {
		return v.secret, nil
	}, jwt.WithTimeFunc(v.now), jwt.WithValidMethods([]string{"HS256"}))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}
	uid, _ := mc["uid"].(string)
	if uid == "" {
		return nil, fmt.Errorf("%w: empty uid claim", ErrInvalidToken)
	}
	tenant, _ := mc["tenant"].(string)
	return &Claims{
		UID:    uid,
		Tenant: tenant,
		Roles:  stringList(mc["roles"]),
		Perms:  stringList(mc["perms"]),
	}, nil
}

// MintDevToken —— 签发联调 token（仅 -dev-token 本地工具链使用，生产入口不暴露）。
func MintDevToken(secret []byte, uid, tenant string, perms []Permission, ttl time.Duration) (string, error) {
	list := make([]string, len(perms))
	for i, p := range perms {
		list[i] = string(p)
	}
	now := time.Now()
	claims := jwt.MapClaims{
		"uid":    uid,
		"tenant": tenant,
		"roles":  []string{"admin"},
		"exp":    now.Add(ttl).Unix(),
	}
	if len(list) > 0 {
		claims["perms"] = list
	}
	tok, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(secret)
	if err != nil {
		return "", fmt.Errorf("sign dev token: %w", err)
	}
	return tok, nil
}

func stringList(v any) []string {
	arr, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(arr))
	for _, item := range arr {
		if s, ok := item.(string); ok {
			out = append(out, s)
		}
	}
	return out
}
