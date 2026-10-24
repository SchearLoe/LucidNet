package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestVerifyRoundtrip(t *testing.T) {
	secret := []byte("test-secret")
	v := NewVerifier(secret)
	tok, err := MintDevToken(secret, "u1", "tenant-a", []Permission{PermAttackRead, PermZoneRead}, time.Hour)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	claims, err := v.Verify(tok)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if claims.UID != "u1" || claims.Tenant != "tenant-a" {
		t.Fatalf("claims = %+v", claims)
	}
	if len(claims.Perms) != 2 {
		t.Fatalf("perms = %v", claims.Perms)
	}
}

func TestVerifyReject(t *testing.T) {
	secret := []byte("test-secret")
	v := NewVerifier(secret)

	t.Run("wrong secret", func(t *testing.T) {
		tok, _ := MintDevToken([]byte("other"), "u1", "t", nil, time.Hour)
		if _, err := v.Verify(tok); err == nil {
			t.Fatal("expected error for wrong-secret token")
		}
	})
	t.Run("expired", func(t *testing.T) {
		tok, _ := MintDevToken(secret, "u1", "t", nil, -time.Minute)
		if _, err := v.Verify(tok); err == nil {
			t.Fatal("expected error for expired token")
		}
	})
	t.Run("garbage", func(t *testing.T) {
		if _, err := v.Verify("not.a.token"); err == nil {
			t.Fatal("expected error for garbage token")
		}
	})
}

// TestMiddlewarePerm —— 权限检查：严格/宽松、perms 有无（docs/11 §8 权限码）。
func TestMiddlewarePerm(t *testing.T) {
	secret := []byte("s")
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })

	cases := []struct {
		name    string
		strict  bool
		perms   []Permission
		want    int
	}{
		{"strict with perm", true, []Permission{PermAttackRead}, http.StatusOK},
		{"strict without perm", true, []Permission{PermZoneRead}, http.StatusForbidden},
		{"strict no perms claim", true, nil, http.StatusForbidden},
		{"relaxed no perms claim", false, nil, http.StatusOK},
		{"relaxed wrong perm", false, []Permission{PermZoneRead}, http.StatusForbidden},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var denied string
			mw := NewMiddleware(NewVerifier(secret), tc.strict,
				func(w http.ResponseWriter, r *http.Request, _ error) { w.WriteHeader(http.StatusUnauthorized) },
				func(w http.ResponseWriter, r *http.Request) {
					if p, ok := DeniedPerm(r.Context()); ok {
						denied = string(p)
					}
					w.WriteHeader(http.StatusForbidden)
				})
			tok, _ := MintDevToken(secret, "u1", "t", tc.perms, time.Hour)
			req := httptest.NewRequest(http.MethodGet, "/x", nil)
			req.Header.Set("Authorization", "Bearer "+tok)
			// 生产装配顺序：Wrap（注入 Identity）→ RequirePerm；测试保持同序。
			wrapped := mw.Wrap(mw.RequirePerm(PermAttackRead, ok))
			rec := httptest.NewRecorder()
			wrapped.ServeHTTP(rec, req)
			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d (denied=%q)", rec.Code, tc.want, denied)
			}
			if tc.want == http.StatusForbidden && denied != "attack:read" {
				t.Fatalf("denied perm = %q, want attack:read", denied)
			}
		})
	}
}

// TestAccessTokenQuery —— WS 场景 ?access_token= 兜底。
func TestAccessTokenQuery(t *testing.T) {
	secret := []byte("s")
	mw := NewMiddleware(NewVerifier(secret), true,
		func(w http.ResponseWriter, _ *http.Request, _ error) { w.WriteHeader(http.StatusUnauthorized) },
		func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusForbidden) },
	)
	tok, _ := MintDevToken(secret, "u1", "t", []Permission{PermMonitorRead}, time.Hour)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/stream/alarms?access_token="+tok, nil)
	rec := httptest.NewRecorder()
	mw.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := IdentityFrom(r.Context())
		if id == nil || id.UID != "u1" {
			t.Fatal("identity not injected")
		}
	})).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
}
