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
