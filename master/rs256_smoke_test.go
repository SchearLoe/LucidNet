package master

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/SchearLoe/lucidnet/master/internal/auth"
)

// TestRS256BootSmoke —— 配置 LUCID_MASTER_JWT_RS256_PRIVATE_KEY 后端到端：
// 登录签发 RS256 token（header 带 alg/kid）→ token 可被 RS256 验签器校验
// （等价 LucidBGP 公钥验签路径，dd/07 §4）→ JWKS/PEM 端点暴露匹配公钥。
func TestRS256BootSmoke(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	keyPEM := string(pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: mustMarshalPKCS8(t, key),
	}))

	opts := Default()
	opts.GrpcAddr = "127.0.0.1:29140"
	opts.HTTPAddr = "127.0.0.1:29141"
	opts.AdminPassword = "rs256-pw"
	opts.JWTSecret = "shared-gw-secret"
	opts.JWTRS256KeyPEM = keyPEM

	srv, err := New(opts)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- srv.Run(ctx) }()
	stopped := make(chan struct{})
	go func() {
		if err := <-errCh; err != nil {
			t.Errorf("run: %v", err)
		}
		close(stopped)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-stopped:
		case <-time.After(10 * time.Second):
			t.Error("server did not stop in time")
		}
	})

	base := "http://" + opts.HTTPAddr
	deadline := time.Now().Add(5 * time.Second)
	for {
		if resp, err := http.Get(base + "/healthz"); err == nil {
			_ = resp.Body.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("http server not ready in 5s")
		}
		time.Sleep(20 * time.Millisecond)
	}

	// 登录 → access token
	var login struct {
		Data struct {
			AccessToken string `json:"access_token"`
		} `json:"data"`
	}
	decode(t, mustPOST(t, base+"/api/v1/auth/login",
		`{"username":"admin","password":"rs256-pw"}`), &login)
	if login.Data.AccessToken == "" {
		t.Fatal("no access token")
	}
	token := login.Data.AccessToken

	// header：alg=RS256 + 非空 kid
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("token parts = %d", len(parts))
	}
	headerRaw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("decode header: %v", err)
	}
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(headerRaw, &header); err != nil {
		t.Fatalf("header json: %v", err)
	}
	if header.Alg != "RS256" || header.Kid == "" {
		t.Fatalf("header = %+v, want alg=RS256 with kid", header)
	}

	// 公钥验签路径（模拟 LucidBGP：仅持公钥亦可构造验签器）
	parsed, err := auth.ParsePrivateKeyPEM([]byte(keyPEM))
	if err != nil {
		t.Fatalf("parse key: %v", err)
	}
	verifier := auth.NewSigner("unused-secret", nil, auth.WithRS256(parsed))
	claims, err := verifier.Verify(token)
	if err != nil {
		t.Fatalf("verify rs256 token: %v", err)
	}
	if claims.UserName != "admin" || claims.Typ != auth.TypAccess {
		t.Fatalf("claims = %+v", claims)
	}

	// JWKS 端点：公钥材料 + 与 token header 一致的 kid
	var jwks struct {
		Keys []struct {
			Kty string `json:"kty"`
			Alg string `json:"alg"`
			Kid string `json:"kid"`
			N   string `json:"n"`
		} `json:"keys"`
	}
	decode(t, mustGET(t, base+"/api/v1/auth/jwks"), &jwks)
	if len(jwks.Keys) != 1 || jwks.Keys[0].Kty != "RSA" || jwks.Keys[0].Alg != "RS256" {
		t.Fatalf("jwks = %+v", jwks)
	}
	if jwks.Keys[0].N == "" || jwks.Keys[0].Kid != header.Kid {
		t.Fatalf("jwks kid = %q (token kid %q), modulus empty=%t",
			jwks.Keys[0].Kid, header.Kid, jwks.Keys[0].N == "")
	}
	// PEM 端点 200 且为 SPKI 形态
	pemBody := mustGET(t, base+"/api/v1/auth/jwks.pem")
	if !strings.Contains(pemBody, "BEGIN PUBLIC KEY") {
		t.Fatalf("jwks.pem = %s", pemBody)
	}
}

func mustMarshalPKCS8(t *testing.T, key *rsa.PrivateKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal pkcs8: %v", err)
	}
	return der
}
