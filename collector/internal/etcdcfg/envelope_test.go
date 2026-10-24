package etcdcfg

import (
	"errors"
	"testing"
	"time"
)

// TestDecodeEnvelopeNormal —— 正常信封：三字段齐全，data 原文保留。
func TestDecodeEnvelopeNormal(t *testing.T) {
	data := []byte(`{"version":7,"updated_at":"2026-10-25T08:00:00Z","data":[{"id":1,"ips":[{"prefix":"10.0.0.0/8"}]}]}`)
	env, err := Decode(data)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if env.Version != 7 {
		t.Errorf("version = %d, want 7", env.Version)
	}
	want := time.Date(2026, 10, 25, 8, 0, 0, 0, time.UTC)
	if !env.UpdatedAt.Equal(want) {
		t.Errorf("updated_at = %v, want %v", env.UpdatedAt, want)
	}
	// data 原文保留（调用方在信封解包后自行解析）
	wantData := `[{"id":1,"ips":[{"prefix":"10.0.0.0/8"}]}]`
	if string(env.Data) != wantData {
		t.Errorf("data = %s, want %s", env.Data, wantData)
	}
	// RFC3339 带纳秒（Master 写侧 time.Time 序列化）
	if _, err := Decode([]byte(`{"version":1,"updated_at":"2026-10-25T08:00:00.123456789Z","data":{}}`)); err != nil {
		t.Errorf("nanosecond updated_at: %v", err)
	}
	// 零时刻 updated_at 合法（仅记录不判定）
	if _, err := Decode([]byte(`{"version":1,"updated_at":"0001-01-01T00:00:00Z","data":[]}`)); err != nil {
		t.Errorf("zero updated_at: %v", err)
	}
	// 未知字段忽略（只增不改，docs/09 §0）
	if _, err := Decode([]byte(`{"version":1,"updated_at":"2026-10-25T08:00:00Z","data":[],"extra":"x"}`)); err != nil {
		t.Errorf("unknown field: %v", err)
	}
}

// TestDecodeEnvelopeMissingFields —— 缺任一必需字段 → ErrEnvelopeIncomplete。
func TestDecodeEnvelopeMissingFields(t *testing.T) {
	tests := []struct {
		name string
		data string
	}{
		{"missing version", `{"updated_at":"2026-10-25T08:00:00Z","data":[]}`},
		{"missing updated_at", `{"version":1,"data":[]}`},
		{"missing data", `{"version":1,"updated_at":"2026-10-25T08:00:00Z"}`},
		{"all missing", `{}`},
		{"null value", `null`},
	}
	for _, tc := range tests {
		if _, err := Decode([]byte(tc.data)); !errors.Is(err, ErrEnvelopeIncomplete) {
			t.Errorf("%s: err = %v, want ErrEnvelopeIncomplete", tc.name, err)
		}
	}
}

// TestDecodeEnvelopeBarePayload —— 裸 payload 一律报错（与 Master 侧约定一致）。
func TestDecodeEnvelopeBarePayload(t *testing.T) {
	tests := []struct {
		name string
		data string
		want error
	}{
		// zones 形状裸数组 → 不是对象
		{"bare zones array", `[{"id":1,"ips":[{"prefix":"10.0.0.0/8"}]}]`, ErrNotEnvelope},
		// 配置对象裸 payload（缺信封字段）
		{"bare config object", `{"listen":":2055","zone_match":"dst"}`, ErrEnvelopeIncomplete},
		{"bare string", `"zones"`, ErrNotEnvelope},
		{"empty", ``, ErrNotEnvelope},
	}
	for _, tc := range tests {
		if _, err := Decode([]byte(tc.data)); !errors.Is(err, tc.want) {
			t.Errorf("%s: err = %v, want %v", tc.name, err, tc.want)
		}
	}
}

// TestDecodeEnvelopeBadFieldValues —— 字段类型/取值非法。
func TestDecodeEnvelopeBadFieldValues(t *testing.T) {
	tests := []struct {
		name string
		data string
	}{
		{"version zero", `{"version":0,"updated_at":"2026-10-25T08:00:00Z","data":[]}`},
		{"version float", `{"version":1.5,"updated_at":"2026-10-25T08:00:00Z","data":[]}`},
		{"version string", `{"version":"3","updated_at":"2026-10-25T08:00:00Z","data":[]}`},
		{"updated_at not rfc3339", `{"version":1,"updated_at":"yesterday","data":[]}`},
		{"updated_at number", `{"version":1,"updated_at":123,"data":[]}`},
	}
	for _, tc := range tests {
		if _, err := Decode([]byte(tc.data)); err == nil {
			t.Errorf("%s: want error, got nil", tc.name)
		}
	}
}

// TestGuardShouldApplyMarkApplied —— 两阶段版本守卫：新版本应用、≤已应用忽略。
func TestGuardShouldApplyMarkApplied(t *testing.T) {
	g := NewGuard()
	const key = "/lucid/zones"

	// 首见版本（含任意 ≥1）应应用
	if !g.ShouldApply(key, 3) {
		t.Fatal("first-seen version 3: want apply")
	}
	// 尚未 MarkApplied 前，同版本重放仍可应用（坏负载重试语义）
	if !g.ShouldApply(key, 3) {
		t.Error("same version before mark: want apply")
	}
	g.MarkApplied(key, 3)

	// 回落（<）与重放（=）均忽略
	if g.ShouldApply(key, 2) {
		t.Error("lower version 2: want ignore")
	}
	if g.ShouldApply(key, 3) {
		t.Error("replayed version 3: want ignore")
	}
	if g.StaleTotal() != 2 {
		t.Errorf("stale total = %d, want 2", g.StaleTotal())
	}

	// 更新版本应用
	if !g.ShouldApply(key, 4) {
		t.Error("higher version 4: want apply")
	}
	g.MarkApplied(key, 4)
	if g.Applied(key) != 4 {
		t.Errorf("applied = %d, want 4", g.Applied(key))
	}

	// MarkApplied 回落写入防御性忽略
	g.MarkApplied(key, 1)
	if g.Applied(key) != 4 {
		t.Errorf("applied after rollback write = %d, want 4", g.Applied(key))
	}
}

// TestGuardKeysIndependent —— 各键版本台账互不影响。
func TestGuardKeysIndependent(t *testing.T) {
	g := NewGuard()
	zones, nodeCfg := "/lucid/zones", "/lucid/config/collector/node-1"
	g.MarkApplied(zones, 5)
	if !g.ShouldApply(nodeCfg, 1) {
		t.Error("different key first version: want apply")
	}
	if g.ShouldApply(zones, 5) {
		t.Error("zones replay: want ignore")
	}
	if g.Applied(nodeCfg) != 0 {
		t.Errorf("node cfg applied = %d, want 0 (not yet marked)", g.Applied(nodeCfg))
	}
}
