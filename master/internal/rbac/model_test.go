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

// TestExpandPerms —— 角色→权限码展开（JWT perms claim 签发输入）：
// 并集去重保序、通配原样保留、未知角色忽略。
func TestExpandPerms(t *testing.T) {
	ledger := append(PresetRoles(), Role{
		Name: "custom", Perms: []string{"zone:edit", "zone:read", "report:*"},
	})
	cases := []struct {
		name      string
		userRoles []string
		want      []string
	}{
		{
			name:      "单角色展开",
			userRoles: []string{RoleObserver},
			want:      PresetRolePerms(PresetRoles(), RoleObserver),
		},
		{
			name:      "多角色并集去重保序",
			userRoles: []string{RoleSecurityOp, RoleObserver},
			want: []string{
				// security-operator 在前（保用户角色顺序），与 observer 重复项只留首次
				"overview:read", "analysis:read",
				"zone:read", "device:read",
				"flows:read", "flows:export",
				"attack:read", "attack:handle",
				"bgp:read", "bgp:handle",
				"report:read", "monitor:read",
				"forward:read", "policy:read",
				"audit:read", "admin:read", "deploy:read",
			},
		},
		{
			name:      "自定义角色通配原样保留",
			userRoles: []string{"custom"},
			want:      []string{"zone:edit", "zone:read", "report:*"},
		},
		{
			name:      "平台管理员全权通配",
			userRoles: []string{RolePlatformAdmin},
			want:      []string{"*"},
		},
		{
			name:      "未知角色忽略",
			userRoles: []string{"ghost", RoleObserver},
			want:      PresetRolePerms(PresetRoles(), RoleObserver),
		},
		{
			name:      "无角色",
			userRoles: nil,
			want:      []string{},
		},
	}
	for _, c := range cases {
		got := ExpandPerms(ledger, c.userRoles)
		if len(got) != len(c.want) {
			t.Fatalf("%s: ExpandPerms = %v, want %v", c.name, got, c.want)
		}
		for i := range c.want {
			if got[i] != c.want[i] {
				t.Fatalf("%s: ExpandPerms[%d] = %q, want %q（全序列 %v）", c.name, i, got[i], c.want[i], got)
			}
		}
	}
	// 展开结果须可直接通过 Allowed 校验（网关权威校验的同语义）
	perms := ExpandPerms(ledger, []string{"custom"})
	if !Allowed(perms, "zone:edit") || !Allowed(perms, "report:manage") || Allowed(perms, "admin:manage") {
		t.Fatalf("expanded perms %v failed wildcard/exact matching", perms)
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
