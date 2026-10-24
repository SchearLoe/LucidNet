package rbac

import "testing"

func TestAllowedPermissionPoints(t *testing.T) {
	cases := []struct {
		perms    []string
		required string
		want     bool
	}{
		{[]string{"zone:read"}, "zone:read", true},
		{[]string{"zone:read"}, "zone:edit", false},
		{[]string{"zone:*"}, "zone:edit", true},
		{[]string{"zone:*"}, "zones:edit", false}, // 前缀必须带冒号对齐
		{[]string{"*"}, "admin:manage", true},
		{[]string{"admin:read", "zone:edit"}, "zone:edit", true},
		{nil, "zone:read", false},
	}
	for _, c := range cases {
		if got := Allowed(c.perms, c.required); got != c.want {
			t.Fatalf("Allowed(%v, %q) = %v", c.perms, c.required, got)
		}
	}
}

func TestPresetRolesShape(t *testing.T) {
	roles := PresetRoles()
	if len(roles) != 4 {
		t.Fatalf("preset roles = %d, want 4", len(roles))
	}
	// 平台管理员全权；观察者只读
	if !Allowed(PresetRolePerms(roles, RolePlatformAdmin), "deploy:upgrade") {
		t.Fatal("platform admin must be all-powerful")
	}
	if Allowed(PresetRolePerms(roles, RoleObserver), "zone:edit") {
		t.Fatal("observer must not edit")
	}
	if !Allowed(PresetRolePerms(roles, RoleSecurityOp), "attack:handle") {
		t.Fatal("security operator must handle attacks")
	}
}

func PresetRolePerms(roles []Role, name string) []string {
	for _, r := range roles {
		if r.Name == name {
			return r.Perms
		}
	}
	return nil
}

func TestPasswordHashRoundTrip(t *testing.T) {
	hash, err := HashPassword("s3cret-Пароль")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	ok, err := VerifyPassword("s3cret-Пароль", hash)
	if err != nil || !ok {
		t.Fatalf("verify correct = %v %v", ok, err)
	}
	ok, _ = VerifyPassword("wrong", hash)
	if ok {
		t.Fatal("wrong password accepted")
	}
	if hash == "pbkdf2$sha256$60000$" || len(hash) < 40 {
		t.Fatalf("hash format suspicious: %q", hash)
	}
}

func TestMemStoreSeedAndLogin(t *testing.T) {
	store := NewMemStore()
	hash, _ := HashPassword("pw")
	if err := store.SeedDefaults(t.Context(), "admin", hash); err != nil {
		t.Fatalf("seed: %v", err)
	}
	u, err := store.GetUserByName(t.Context(), "admin")
	if err != nil || !u.PlatformAdmin || len(u.Roles) != 1 {
		t.Fatalf("admin user = %+v err=%v", u, err)
	}
	// 幂等
	if err := store.SeedDefaults(t.Context(), "admin", hash); err != nil {
		t.Fatalf("reseed: %v", err)
	}
	roles, _ := store.ListRoles(t.Context())
	if len(roles) != 4 {
		t.Fatalf("roles = %d, want 4", len(roles))
	}
}
