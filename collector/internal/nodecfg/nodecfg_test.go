package nodecfg

import (
	"strings"
	"testing"
)

func TestParseNormal(t *testing.T) {
	data := []byte(`{
		"listen": ":2055",
		"sflow_listen": ":6343",
		"zone_match": "src",
		"sample_registry": {"10.0.0.1": 1000, "10.0.0.2": 1},
		"naming_rules": [{"pattern": "(?i)(to-|-agg-)","role": "internal"}],
		"rib_snapshot_ptr": "rib@20261025"
	}`)
	c, err := Parse(data)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if c.Listen != ":2055" || c.SFlowListen != ":6343" {
		t.Errorf("listen = %q/%q", c.Listen, c.SFlowListen)
	}
	if c.ZoneMatch != "src" {
		t.Errorf("zone_match = %q, want src", c.ZoneMatch)
	}
	if c.SampleRegistry["10.0.0.1"] != 1000 || c.SampleRegistry["10.0.0.2"] != 1 {
		t.Errorf("sample registry = %v", c.SampleRegistry)
	}
	if len(c.NamingRules) != 1 || c.NamingRules[0].Role != "internal" {
		t.Errorf("naming rules = %+v", c.NamingRules)
	}
	if c.RIBSnapshotPtr != "rib@20261025" {
		t.Errorf("rib ptr = %q", c.RIBSnapshotPtr)
	}
}

func TestParseEmptyAndPartial(t *testing.T) {
	// 空/部分配置合法（字段全部 omitempty 语义）
	for name, data := range map[string]string{
		"empty object": `{}`,
		"null":         `null`,
		"partial":      `{"zone_match":"dst"}`,
	} {
		if _, err := Parse([]byte(data)); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestParseInvalid(t *testing.T) {
	tests := []struct {
		name string
		data string
	}{
		{"bare array payload", `[{"id":1}]`},
		{"bare string payload", `"cfg"`},
		{"bad json", `{`},
		{"naming rule bad role", `{"naming_rules":[{"pattern":"x","role":"peer"}]}`},
		{"naming rule empty pattern", `{"naming_rules":[{"pattern":"","role":"internal"}]}`},
	}
	for _, tc := range tests {
		if _, err := Parse([]byte(tc.data)); err == nil {
			t.Errorf("%s: want error, got nil", tc.name)
		}
	}
	// 错误信息可辨识
	if _, err := Parse([]byte(`{"naming_rules":[{"pattern":"x","role":"peer"}]}`)); err == nil || !strings.Contains(err.Error(), "role") {
		t.Errorf("role err = %v, want role context", err)
	}
}
