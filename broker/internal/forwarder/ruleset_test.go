package forwarder

import (
	"strings"
	"testing"
)

func TestValidatePassthroughResampleRejected(t *testing.T) {
	// dd/01 §3.2 #3：passthrough 不支持 resample，配置校验直接拒绝
	snap := &RulesSnapshot{
		Version: 1,
		Rules: []Rule{{
			ID: 1, Enabled: true,
			Destinations: []Destination{
				{Addr: "172.16.0.10:9995", Protocol: ProtocolPassthrough, Resample: &Resample{Mode: ResampleDeterministic, Rate: 10}},
			},
		}},
	}
	if err := snap.Rules[0].Validate(nil); err == nil || !strings.Contains(err.Error(), "passthrough") {
		t.Fatalf("want passthrough×resample reject, got %v", err)
	}
}

func TestValidateSnapshotPartial(t *testing.T) {
	snap := &RulesSnapshot{
		Version: 2,
		Rules: []Rule{
			{ID: 1, Enabled: true, Destinations: []Destination{{Addr: "1.2.3.4:9995", Protocol: ProtocolPassthrough}}},
			{ID: 2, Enabled: true, Destinations: []Destination{{Addr: "1.2.3.4:9995", Protocol: "xml"}}},
			{ID: 3, Enabled: false, Destinations: nil}, // 关闭规则静默跳过
			{ID: 4, Enabled: true, Destinations: nil},  // 无目的地 → 拒绝
		},
	}
	valid, errs := snap.Validate()
	if len(valid) != 1 || valid[0].ID != 1 {
		t.Errorf("valid = %+v", valid)
	}
	if len(errs) != 2 {
		t.Errorf("errs = %v", errs)
	}
}

func TestValidateExporterCap(t *testing.T) {
	groups := map[string][]string{"g": make([]string, 10001)}
	for i := range groups["g"] {
		groups["g"][i] = "10.0.0." + itoa(i%250) // 允许重复：展开按去重计
	}
	// 10001 条但去重后 250 → 合法
	r := Rule{ID: 1, Enabled: true, Match: Match{ExporterGroups: []string{"g"}},
		Destinations: []Destination{{Addr: "1.2.3.4:9995", Protocol: ProtocolPassthrough}}}
	if err := r.Validate(groups); err != nil {
		t.Fatalf("dedup expand should pass: %v", err)
	}
	// 10001 个互异 exporter → 超限拒绝
	unique := make([]string, 0, 10001)
	for i := 0; i < 10001; i++ {
		unique = append(unique, "10."+itoa(i/65536%256)+"."+itoa(i/256%256)+"."+itoa(i%256))
	}
	r2 := Rule{ID: 2, Enabled: true, Match: Match{Exporters: unique},
		Destinations: []Destination{{Addr: "1.2.3.4:9995", Protocol: ProtocolPassthrough}}}
	if err := r2.Validate(nil); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("want cap reject, got %v", err)
	}
}

func TestValidateFilterPrefix(t *testing.T) {
	r := Rule{ID: 1, Enabled: true,
		Destinations: []Destination{{Addr: "1.2.3.4:9995", Protocol: ProtocolIPFIX}},
		FlowFilter:   &FlowFilter{SrcPrefix: "not-a-cidr"}}
	if err := r.Validate(nil); err == nil || !strings.Contains(err.Error(), "CIDR") {
		t.Fatalf("want CIDR reject, got %v", err)
	}
}

func TestCompileExpansion(t *testing.T) {
	snap := &RulesSnapshot{
		Version: 7,
		ExporterGroups: map[string][]string{
			"core-routers": {"10.1.1.2", "10.1.1.3"},
		},
		Rules: []Rule{
			{
				ID: 42, Name: "core→clean", Priority: 10, Enabled: true,
				Match: Match{Exporters: []string{"10.1.1.1"}, ExporterGroups: []string{"core-routers"}},
				Destinations: []Destination{
					{Addr: "172.16.0.10:9995", Protocol: ProtocolPassthrough},
					{Addr: "172.16.0.11:9995", Protocol: ProtocolNetFlow5, Resample: &Resample{Mode: ResampleDeterministic, Rate: 10}},
					{Topic: "flows.raw", Protocol: ProtocolKafka},
				},
			},
			{
				ID: 7, Priority: 5, Enabled: true,
				Match:        Match{Exporters: []string{"10.1.1.1"}},
				Destinations: []Destination{{Addr: "172.16.0.12:4739", Protocol: ProtocolIPFIX}},
			},
		},
	}
	rs, verrs := Compile(snap)
	if len(verrs) != 0 {
		t.Fatalf("verrs = %v", verrs)
	}
	if rs.Version != 7 || rs.RuleCount() != 2 {
		t.Fatalf("version=%d rules=%d", rs.Version, rs.RuleCount())
	}
	// priority 升序：rule 7 先于 42（dd/01 §3.2 #1）
	rules := rs.RulesFor("10.1.1.1")
	if len(rules) != 2 || rules[0].src.ID != 7 || rules[1].src.ID != 42 {
		t.Fatalf("rules order = %d,%d", rules[0].src.ID, rules[1].src.ID)
	}
	// 组展开：10.1.1.2 命中 rule 42
	r42 := rs.RulesFor("10.1.1.2")
	if len(r42) != 1 || r42[0].src.ID != 42 {
		t.Fatalf("group member rules = %+v", r42)
	}
	// 组内去重（10.1.1.2 同时在 exporters 与 group 不重复命中）
	if len(rs.RulesFor("10.1.1.3")) != 1 {
		t.Fatal("dup expansion")
	}
	// 未命中 exporter
	if rs.RulesFor("10.9.9.9") != nil {
		t.Fatal("unmatched exporter must be nil")
	}
	// 目的地指针编译
	if len(rules[1].dests) != 3 || rules[1].dests[0].Addr != "172.16.0.10:9995" {
		t.Fatal("dests not compiled")
	}
}

func TestCompileDisabledRuleNotIndexed(t *testing.T) {
	snap := &RulesSnapshot{
		Version: 3,
		Rules: []Rule{
			{ID: 5, Enabled: true, Match: Match{Exporters: []string{"10.0.0.1"}},
				Destinations: []Destination{{Addr: "1.1.1.1:1", Protocol: ProtocolPassthrough}}},
			{ID: 6, Enabled: false, Match: Match{Exporters: []string{"10.0.0.1"}},
				Destinations: []Destination{{Addr: "1.1.1.1:1", Protocol: ProtocolPassthrough}}},
		},
	}
	rs, _ := Compile(snap)
	if got := rs.RulesFor("10.0.0.1"); len(got) != 1 || got[0].src.ID != 5 {
		t.Fatalf("disabled rule must be dropped, got %+v", got)
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b [20]byte
	p := len(b)
	for i > 0 {
		p--
		b[p] = byte('0' + i%10)
		i /= 10
	}
	return string(b[p:])
}
