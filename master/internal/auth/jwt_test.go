package auth

import (
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
