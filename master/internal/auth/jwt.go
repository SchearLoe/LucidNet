package auth

import (
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"
)

// JWT 签发/校验（docs/dd/07 §4）：
//   - HS256（默认，开发模式）：Master 与网关共享密钥；
//   - RS256（配置 LUCID_MASTER_JWT_RS256_* 后启用）：私钥仅 Master 持有，
//     公钥经 REST GET /api/v1/auth/jwks 暴露，供 LucidBGP 独立验签（dd/06）。
//
// claims {uid, tenant, roles, perms, exp}。
//
// 说明：手写 JWT（header.payload.signature，base64url），不引入第三方 JWT 库；
// 算法白名单：HS256 恒可用，RS256 在配置密钥对后加入（支持灰度轮换期双验），
// 未知/none 一律拒绝；HMAC 比较用 hmac.Equal 恒时比较。

// Typ —— token 用途（刷新令牌不得直接访问业务接口）。
const (
	TypAccess  = "access"
	TypRefresh = "refresh"
)

// JWT 算法标识（ JOSE alg）。
const (
	AlgHS256 = "HS256"
	AlgRS256 = "RS256"
)

// DefaultAccessTTL / DefaultRefreshTTL —— hld/07 §2：JWT 签发 15min + 刷新。
const (
	DefaultAccessTTL  = 15 * time.Minute
	DefaultRefreshTTL = 12 * time.Hour
)

// Claims —— JWT 载荷（docs/dd/07 §4）。
type Claims struct {
	UID      int64    `json:"uid"`
	UserName string   `json:"name"`   // 登录名（审计/回查）
	Tenant   string   `json:"tenant"` // 平台管理员为空（租户隔离豁免）
	Roles    []string `json:"roles"`
	// Perms —— 角色→权限点展开（<domain>:<action>，支持 * / <domain>:* 通配原样保留，
	// 匹配语义同 rbac.Allowed）。资源网关（Console）直接校验 token 内 perms，为权威来源；
	// 未携带（旧 token）时网关按其严格模式自行回退。omitempty：不签发时与旧契约兼容。
	Perms         []string `json:"perms,omitempty"`
	PlatformAdmin bool     `json:"platform_admin,omitempty"`
	Typ           string   `json:"typ"`
	IssuedAt      int64    `json:"iat"`
	ExpiresAt     int64    `json:"exp"`
}

var (
	ErrTokenExpired = errors.New("token expired")
	ErrTokenInvalid = errors.New("token invalid")
)

// Signer —— JWT 签发/验签器（HS256 基线；经 Option 启用 RS256）。
type Signer struct {
	secret []byte
	rsaKey *rsa.PrivateKey // 非 nil 时签发 RS256 并扩展验签白名单
	kid    string          // RS256 公钥指纹（JWKS kid，RFC 7638）
	now    func() time.Time
}

// Option —— Signer 装配项（docs/11 §3 Option 模式）。
type Option func(*Signer)

// WithRS256 启用 RS256 签发/验签（docs/dd/07 §4：LucidBGP 公钥验签）。
func WithRS256(key *rsa.PrivateKey) Option {
	return func(s *Signer) {
		s.rsaKey = key
		s.kid = keyID(&key.PublicKey)
	}
}

// NewSigner 构造签名器；now 可注入（测试），nil 取 time.Now。
func NewSigner(secret string, now func() time.Time, opts ...Option) *Signer {
	if now == nil {
		now = time.Now
	}
	s := &Signer{secret: []byte(secret), now: now}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// ParsePrivateKeyPEM 解析 PEM 编码的 RSA 私钥（PKCS#8 "PRIVATE KEY" 与
// PKCS#1 "RSA PRIVATE KEY" 均支持；供 LUCID_MASTER_JWT_RS256_* 配置装载）。
func ParsePrivateKeyPEM(pemBytes []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("auth: decode jwt private key pem")
	}
	if k, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		rk, ok := k.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("auth: jwt private key is not RSA")
		}
		return rk, nil
	}
	rk, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("auth: parse jwt private key (pkcs#8/pkcs#1): %w", err)
	}
	return rk, nil
}

// Alg 当前签发算法（验签白名单恒含 HS256；RS256 配置后为签发算法）。
func (s *Signer) Alg() string {
	if s.rsaKey != nil {
		return AlgRS256
	}
	return AlgHS256
}

type jwtHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid,omitempty"`
}

// Sign 签发 token（claims.Exp 由调用方按 TTL 设置；0 时默认不给过期，仅限测试）。
// 配置 RS256 后 access/refresh 均以 RS256 签发（docs/dd/07 §4）。
func (s *Signer) Sign(c Claims) (string, error) {
	now := s.now().Unix()
	c.IssuedAt = now
	if c.ExpiresAt == 0 {
		c.ExpiresAt = now + int64(DefaultAccessTTL.Seconds())
	}
	if c.Typ == "" {
		c.Typ = TypAccess
	}
	payload, err := json.Marshal(c)
	if err != nil {
		return "", fmt.Errorf("marshal jwt claims: %w", err)
	}
	if s.rsaKey != nil {
		header := jwtHeader{Alg: AlgRS256, Typ: "JWT", Kid: s.kid}
		signing, err := encodeSigning(header, payload)
		if err != nil {
			return "", err
		}
		digest := sha256.Sum256([]byte(signing))
		sig, err := rsa.SignPKCS1v15(rand.Reader, s.rsaKey, crypto.SHA256, digest[:])
		if err != nil {
			return "", fmt.Errorf("sign jwt rs256: %w", err)
		}
		return signing + "." + base64url(sig), nil
	}
	header := jwtHeader{Alg: AlgHS256, Typ: "JWT"}
	signing, err := encodeSigning(header, payload)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, s.secret)
	mac.Write([]byte(signing))
	return signing + "." + base64url(mac.Sum(nil)), nil
}

func encodeSigning(header jwtHeader, payload []byte) (string, error) {
	headerRaw, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("marshal jwt header: %w", err)
	}
	return base64url(headerRaw) + "." + base64url(payload), nil
}

// Verify 校验并解析 token（算法白名单：HS256 恒可；RS256 仅在配置密钥对后加入；
// 校验 exp。先验签后解 payload，防算法混淆）。
func (s *Signer) Verify(token string) (*Claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, ErrTokenInvalid
	}
	headerRaw, err := base64urlDecode(parts[0])
	if err != nil {
		return nil, fmt.Errorf("%w: header", ErrTokenInvalid)
	}
	var header jwtHeader
	if err := json.Unmarshal(headerRaw, &header); err != nil {
		return nil, fmt.Errorf("%w: header", ErrTokenInvalid)
	}
	switch header.Alg {
	case AlgHS256:
		mac := hmac.New(sha256.New, s.secret)
		mac.Write([]byte(parts[0] + "." + parts[1]))
		want := mac.Sum(nil)
		got, err := base64urlDecode(parts[2])
		if err != nil || !hmac.Equal(want, got) {
			return nil, fmt.Errorf("%w: signature", ErrTokenInvalid)
		}
	case AlgRS256:
		if s.rsaKey == nil {
			return nil, fmt.Errorf("%w: alg %s not configured", ErrTokenInvalid, AlgRS256)
		}
		sig, err := base64urlDecode(parts[2])
		if err != nil {
			return nil, fmt.Errorf("%w: signature", ErrTokenInvalid)
		}
		digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
		if err := rsa.VerifyPKCS1v15(&s.rsaKey.PublicKey, crypto.SHA256, digest[:], sig); err != nil {
			return nil, fmt.Errorf("%w: signature", ErrTokenInvalid)
		}
	default:
		return nil, fmt.Errorf("%w: alg", ErrTokenInvalid)
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

// ---------- 公钥暴露（REST GET /api/v1/auth/jwks，docs/dd/07 §4） ----------

// JWK —— RSA 公钥 JWK（RFC 7517）。
type JWK struct {
	Kty string `json:"kty"`
	Alg string `json:"alg,omitempty"`
	Use string `json:"use,omitempty"`
	Kid string `json:"kid,omitempty"`
	N   string `json:"n"` // 模数（base64url，无填充）
	E   string `json:"e"` // 指数（base64url，无填充）
}

// JWKS 返回公钥集 JSON（未配置 RS256 时为空集 keys:[]）。
func (s *Signer) JWKS() []byte {
	keys := []JWK{}
	if s.rsaKey != nil {
		keys = append(keys, s.PublicJWK())
	}
	b, err := json.Marshal(map[string]any{"keys": keys})
	if err != nil {
		return []byte(`{"keys":[]}`)
	}
	return b
}

// PublicJWK 当前 RS256 公钥的 JWK 形式（未配置时零值）。
func (s *Signer) PublicJWK() JWK {
	if s.rsaKey == nil {
		return JWK{}
	}
	return JWK{
		Kty: "RSA", Alg: AlgRS256, Use: "sig", Kid: s.kid,
		N: base64url(s.rsaKey.PublicKey.N.Bytes()),
		E: base64url(big.NewInt(int64(s.rsaKey.PublicKey.E)).Bytes()),
	}
}

// PublicKeyPEM 返回 SPKI（PKIX）PEM 公钥（未配置 RS256 时 nil；运维导出用）。
func (s *Signer) PublicKeyPEM() []byte {
	if s.rsaKey == nil {
		return nil
	}
	der, err := x509.MarshalPKIXPublicKey(&s.rsaKey.PublicKey)
	if err != nil {
		return nil
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}

// keyID 公钥指纹（RFC 7638 JWK Thumbprint：SHA-256 后 base64url）。
func keyID(pub *rsa.PublicKey) string {
	canon := fmt.Sprintf(`{"e":"%s","kty":"RSA","n":"%s"}`,
		base64url(big.NewInt(int64(pub.E)).Bytes()), base64url(pub.N.Bytes()))
	sum := sha256.Sum256([]byte(canon))
	return base64url(sum[:])
}

func base64url(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

func base64urlDecode(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}
