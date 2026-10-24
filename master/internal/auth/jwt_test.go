package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"strings"
	"testing"
	"time"
)

func TestSignVerifyRoundTrip(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	s := NewSigner("secret", func() time.Time { return now })
	c := Claims{UID: 7, Tenant: "acme", Roles: []string{"tenant-admin"}, Typ: TypAccess}
	token, err := s.Sign(c)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	got, err := s.Verify(token)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if got.UID != 7 || got.Tenant != "acme" || len(got.Roles) != 1 || got.Roles[0] != "tenant-admin" {
		t.Fatalf("claims mismatch: %+v", got)
	}
	if got.ExpiresAt != now.Unix()+int64(DefaultAccessTTL.Seconds()) {
		t.Fatalf("exp = %d, want %d", got.ExpiresAt, now.Unix()+int64(DefaultAccessTTL.Seconds()))
	}
}

func TestVerifyRejectsTamperAndAlg(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	s := NewSigner("secret", func() time.Time { return now })
	token, _ := s.Sign(Claims{UID: 1})

	// 篡改 payload
	parts := strings.Split(token, ".")
	tampered := parts[0] + "." + parts[1][len(parts[1])-6:] + parts[1][:len(parts[1])-6] + "." + parts[2]
	if _, err := s.Verify(tampered); err == nil {
		t.Fatal("tampered payload accepted")
	}
	// 错误密钥
	other := NewSigner("other-secret", func() time.Time { return now })
	tok2, _ := other.Sign(Claims{UID: 1})
	if _, err := s.Verify(tok2); err == nil {
		t.Fatal("wrong secret accepted")
	}
	// alg=none
	noneToken := "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0." + parts[1] + "."
	if _, err := s.Verify(noneToken); err == nil {
		t.Fatal("alg=none accepted")
	}
}

func TestVerifyExpired(t *testing.T) {
	t0 := time.Unix(1_800_000_000, 0)
	s := NewSigner("secret", func() time.Time { return t0 })
	token, _ := s.Sign(Claims{UID: 1, ExpiresAt: t0.Unix() - 1})
	if _, err := s.Verify(token); err != ErrTokenExpired {
		t.Fatalf("err = %v, want ErrTokenExpired", err)
	}
}

// TestPermsClaimRoundTrip —— perms claim 签发/解析往返；通配项（* / domain:*）
// 原样保留在 claim 内（展开语义由 rbac.Allowed 在校验侧匹配，docs/11 §8）。
func TestPermsClaimRoundTrip(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	s := NewSigner("secret", func() time.Time { return now })
	c := Claims{
		UID:   9,
		Roles: []string{"security-operator"},
		Perms: []string{"overview:read", "zone:*", "attack:handle", "*"},
		Typ:   TypAccess,
	}
	token, err := s.Sign(c)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	got, err := s.Verify(token)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	want := []string{"overview:read", "zone:*", "attack:handle", "*"}
	if len(got.Perms) != len(want) {
		t.Fatalf("perms = %v, want %v", got.Perms, want)
	}
	for i := range want {
		if got.Perms[i] != want[i] {
			t.Fatalf("perms[%d] = %q, want %q（须保序去重原样保留）", i, got.Perms[i], want[i])
		}
	}
}

// TestPermsClaimOmittedWhenEmpty —— 未签发 perms 时 claim 不出现，旧 token 兼容。
func TestPermsClaimOmittedWhenEmpty(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	s := NewSigner("secret", func() time.Time { return now })
	token, err := s.Sign(Claims{UID: 1, Typ: TypAccess})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if got, err := s.Verify(token); err != nil || len(got.Perms) != 0 {
		t.Fatalf("perms = %v err = %v, want empty/nil", got.Perms, err)
	}
	// JSON 载荷不含 perms 键（omitempty；网关 PermsKnown 判定依据）
	parts := strings.Split(token, ".")
	payload, err := base64urlDecode(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	if strings.Contains(string(payload), `"perms"`) {
		t.Fatalf("empty perms must be omitted from payload: %s", payload)
	}
}

// ---------- RS256（docs/dd/07 §4：LucidBGP 公钥验签） ----------

func genRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("gen rsa key: %v", err)
	}
	return k
}

func decodeHeader(t *testing.T, token string) jwtHeader {
	t.Helper()
	raw, err := base64urlDecode(strings.Split(token, ".")[0])
	if err != nil {
		t.Fatalf("decode header: %v", err)
	}
	var h jwtHeader
	if err := json.Unmarshal(raw, &h); err != nil {
		t.Fatalf("header json: %v", err)
	}
	return h
}

// TestRS256RoundTrip —— 配置 RS256 后签发/验签往返；header 带 alg=RS256 + kid。
func TestRS256RoundTrip(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	key := genRSAKey(t)
	s := NewSigner("secret", func() time.Time { return now }, WithRS256(key))
	if s.Alg() != AlgRS256 {
		t.Fatalf("alg = %s, want RS256", s.Alg())
	}
	c := Claims{UID: 7, Tenant: "acme", Roles: []string{"tenant-admin"}, Perms: []string{"zone:*"}, Typ: TypAccess}
	token, err := s.Sign(c)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	h := decodeHeader(t, token)
	if h.Alg != AlgRS256 || h.Kid == "" {
		t.Fatalf("header = %+v, want alg=RS256 with kid", h)
	}
	got, err := s.Verify(token)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if got.UID != 7 || got.Tenant != "acme" || got.Typ != TypAccess || len(got.Perms) != 1 {
		t.Fatalf("claims mismatch: %+v", got)
	}
	// HS256 白名单共存（轮换期旧网关 token 仍可验）
	hs := NewSigner("secret", func() time.Time { return now }, WithRS256(key))
	hsv, err := hs.Sign(Claims{UID: 2})
	if err != nil {
		t.Fatalf("sign hs256: %v", err)
	}
	if got, err := s.Verify(hsv); err != nil || got.UID != 2 {
		t.Fatalf("hs256 coexist verify = %+v err = %v", got, err)
	}
}

// TestRS256RejectsForgedAndConfusedAlg —— 拒伪造签名、拒算法混淆、拒未配置 RS256。
func TestRS256RejectsForgedAndConfusedAlg(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	key := genRSAKey(t)
	other := genRSAKey(t)
	s := NewSigner("secret", func() time.Time { return now }, WithRS256(key))

	token, _ := s.Sign(Claims{UID: 1})
	parts := strings.Split(token, ".")

	// ① 篡改 payload → RS256 验签失败
	tampered := parts[0] + "." + parts[1][len(parts[1])-4:] + parts[1][:len(parts[1])-4] + "." + parts[2]
	if _, err := s.Verify(tampered); err == nil {
		t.Fatal("tampered rs256 payload accepted")
	}
	// ② 他钥签发 → 拒绝
	foreign := NewSigner("secret", func() time.Time { return now }, WithRS256(other))
	fTok, _ := foreign.Sign(Claims{UID: 1})
	if _, err := s.Verify(fTok); err == nil {
		t.Fatal("foreign rs256 key accepted")
	}
	// ③ 算法混淆：把公钥 PEM 当 HS256 密钥伪造 → 拒绝（防 alg downgrade）
	pubPEM := s.PublicKeyPEM()
	mac := hmac.New(sha256.New, pubPEM)
	mac.Write([]byte(parts[0] + "." + parts[1]))
	confused := parts[0] + "." + parts[1] + "." + base64url(mac.Sum(nil))
	if _, err := s.Verify(confused); err == nil {
		t.Fatal("alg-confusion HS256(public key) accepted")
	}
	// ④ 未配置 RS256 的 Signer 拒绝 RS256 token
	hsOnly := NewSigner("secret", func() time.Time { return now })
	if _, err := hsOnly.Verify(token); err == nil {
		t.Fatal("rs256 token accepted by HS256-only signer")
	}
	// ⑤ alg=none / 未知算法拒绝
	if _, err := s.Verify("eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0." + parts[1] + "."); err == nil {
		t.Fatal("alg=none accepted")
	}
	forgedAlg := base64url([]byte(`{"alg":"PS256","typ":"JWT"}`)) + "." + parts[1] + "." + parts[2]
	if _, err := s.Verify(forgedAlg); err == nil {
		t.Fatal("alg=PS256 accepted")
	}
}

// TestJWKSAndPEM —— JWKS 形态（RFC 7517）与 SPKI PEM 导出；kid 为 RFC 7638 指纹。
func TestJWKSAndPEM(t *testing.T) {
	key := genRSAKey(t)
	s := NewSigner("secret", nil, WithRS256(key))
	var set struct {
		Keys []JWK `json:"keys"`
	}
	if err := json.Unmarshal(s.JWKS(), &set); err != nil {
		t.Fatalf("jwks json: %v", err)
	}
	if len(set.Keys) != 1 {
		t.Fatalf("keys = %d, want 1", len(set.Keys))
	}
	jwk := set.Keys[0]
	if jwk.Kty != "RSA" || jwk.Alg != AlgRS256 || jwk.Use != "sig" || jwk.Kid == "" {
		t.Fatalf("jwk = %+v", jwk)
	}
	if jwk.N != base64url(key.PublicKey.N.Bytes()) {
		t.Fatal("jwk modulus mismatch")
	}
	if jwk.Kid != decodeHeader(t, mustSign(t, s)).Kid {
		t.Fatal("jwk kid != token header kid")
	}
	// SPKI PEM 可解析回同一公钥
	if !strings.Contains(string(s.PublicKeyPEM()), "BEGIN PUBLIC KEY") {
		t.Fatalf("public pem = %s", s.PublicKeyPEM())
	}
	// 未配置 RS256：空集 + PEM nil
	hs := NewSigner("secret", nil)
	var empty struct {
		Keys []JWK `json:"keys"`
	}
	if err := json.Unmarshal(hs.JWKS(), &empty); err != nil || len(empty.Keys) != 0 {
		t.Fatalf("hs256 jwks = %s err = %v", hs.JWKS(), err)
	}
	if hs.PublicKeyPEM() != nil {
		t.Fatal("hs256 signer must not expose pem")
	}
}

// TestParsePrivateKeyPEM —— PKCS#8 / PKCS#1 PEM 装载与拒错。
func TestParsePrivateKeyPEM(t *testing.T) {
	key := genRSAKey(t)
	p8, err := x509MarshalPKCS8(key)
	if err != nil {
		t.Fatalf("marshal pkcs8: %v", err)
	}
	got, err := ParsePrivateKeyPEM(p8)
	if err != nil || got.N.Cmp(key.N) != 0 {
		t.Fatalf("pkcs8 parse = %v", err)
	}
	p1 := x509MarshalPKCS1(key)
	got, err = ParsePrivateKeyPEM(p1)
	if err != nil || got.N.Cmp(key.N) != 0 {
		t.Fatalf("pkcs1 parse = %v", err)
	}
	if _, err := ParsePrivateKeyPEM([]byte("not a pem")); err == nil {
		t.Fatal("garbage pem accepted")
	}
}

// mustSign 测试辅助：默认 claims 签发。
func mustSign(t *testing.T, s *Signer) string {
	t.Helper()
	tok, err := s.Sign(Claims{UID: 1})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return tok
}

// x509MarshalPKCS8 / x509MarshalPKCS1 —— 测试辅助：私钥 PEM 编码。
func x509MarshalPKCS8(key *rsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

func x509MarshalPKCS1(key *rsa.PrivateKey) []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
}
