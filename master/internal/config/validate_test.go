package config

import (
	"encoding/json"
	"strings"
	"testing"
)

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

func TestValidateZonesPass(t *testing.T) {
	data := mustJSON(t, []ZoneSpec{
		{ID: 1, Name: "customer-a", Tenant: "acme", IPs: []ZoneIPEntry{
			{Prefix: "10.0.0.0/24"}, {Prefix: "2001:db8:1::/48"},
		}},
		{ID: 2, Name: "customer-b", Tenant: "acme", IPs: []ZoneIPEntry{
			{Prefix: "10.0.1.5/32"},
		}, ZoneMatch: "src"},
	})
	if err := ValidateZones(data); err != nil {
		t.Fatalf("validate: %v", err)
	}
}

func TestValidateZonesRejectsV4Overlap(t *testing.T) {
	data := mustJSON(t, []ZoneSpec{
		{ID: 1, Name: "a", Tenant: "t1", IPs: []ZoneIPEntry{{Prefix: "10.0.0.0/24"}}},
		{ID: 2, Name: "b", Tenant: "t2", IPs: []ZoneIPEntry{{Prefix: "10.0.0.128/25"}}},
	})
	err := ValidateZones(data)
	if err == nil || !strings.Contains(err.Error(), "R2 overlap") {
		t.Fatalf("err = %v, want R2 overlap", err)
	}
}

func TestValidateZonesRejectsV6Overlap(t *testing.T) {
	data := mustJSON(t, []ZoneSpec{
		{ID: 1, Name: "a", Tenant: "t1", IPs: []ZoneIPEntry{{Prefix: "2001:db8::/32"}}},
		{ID: 2, Name: "b", Tenant: "t2", IPs: []ZoneIPEntry{{Prefix: "2001:db8:0:1::/64"}}},
	})
	if err := ValidateZones(data); err == nil || !strings.Contains(err.Error(), "R2 overlap") {
		t.Fatalf("err = %v, want R2 overlap", err)
	}
}

func TestValidateZonesRejectsBothMatch(t *testing.T) {
	data := mustJSON(t, []ZoneSpec{
		{ID: 1, Name: "a", Tenant: "t1", IPs: []ZoneIPEntry{{Prefix: "10.0.0.0/24"}}, ZoneMatch: "both"},
	})
	if err := ValidateZones(data); err == nil || !strings.Contains(err.Error(), "both forbidden") {
		t.Fatalf("err = %v, want both forbidden", err)
	}
}

func TestValidateZonesRejectsDupIDAndMissingTenant(t *testing.T) {
	dup := mustJSON(t, []ZoneSpec{
		{ID: 1, Name: "a", Tenant: "t1", IPs: []ZoneIPEntry{{Prefix: "10.0.0.0/24"}}},
		{ID: 1, Name: "b", Tenant: "t1", IPs: []ZoneIPEntry{{Prefix: "10.0.1.0/24"}}},
	})
	if err := ValidateZones(dup); err == nil {
		t.Fatal("dup id accepted")
	}
	miss := mustJSON(t, []ZoneSpec{{ID: 3, Name: "c", IPs: []ZoneIPEntry{{Prefix: "10.0.2.0/24"}}}})
	if err := ValidateZones(miss); err == nil || !strings.Contains(err.Error(), "tenant") {
		t.Fatalf("err = %v, want tenant required", err)
	}
}

// R1：passthrough 目的地带 resample 直接拒绝（docs/dd/01 §3.2-3）。
func TestValidateForwardRulesRejectsPassthroughResample(t *testing.T) {
	data := mustJSON(t, []ForwardRule{{
		ID: 1, Name: "bad", Enabled: true,
		Match: ForwardMatch{Exporters: []string{"10.1.1.1"}},
		Destinations: []ForwardDest{{
			Addr: "172.16.0.10:9995", Protocol: "passthrough",
			Resample: &Resample{Mode: "deterministic", Rate: 10},
		}},
	}})
	err := ValidateForwardRules(data)
	if err == nil || !strings.Contains(err.Error(), "passthrough does not support resample") {
		t.Fatalf("err = %v, want passthrough resample rejected", err)
	}
}

func TestValidateForwardRulesPass(t *testing.T) {
	data := mustJSON(t, []ForwardRule{
		{
			ID: 42, Name: "core→clean", Priority: 10, Enabled: true,
			Match: ForwardMatch{Exporters: []string{"10.1.1.1", "10.1.1.2"}, ExporterGroups: []string{"core-routers"}},
			Destinations: []ForwardDest{
				{Addr: "172.16.0.10:9995", Protocol: "passthrough"},
				{Addr: "172.16.0.11:9995", Protocol: "netflow5", Resample: &Resample{Mode: "deterministic", Rate: 10}},
				{Addr: "172.16.0.12:4739", Protocol: "ipfix", Resample: &Resample{Mode: "random", Rate: 5}},
			},
		},
	})
	if err := ValidateForwardRules(data); err != nil {
		t.Fatalf("validate: %v", err)
	}
}

func TestValidateForwardRulesRejectsBadProtocolAndIP(t *testing.T) {
	badProto := mustJSON(t, []ForwardRule{{
		ID: 1, Name: "x", Match: ForwardMatch{Exporters: []string{"10.1.1.1"}},
		Destinations: []ForwardDest{{Addr: "1.2.3.4:9995", Protocol: "sflow"}},
	}})
	if err := ValidateForwardRules(badProto); err == nil {
		t.Fatal("bad protocol accepted")
	}
	badIP := mustJSON(t, []ForwardRule{{
		ID: 1, Name: "x", Match: ForwardMatch{Exporters: []string{"not-an-ip"}},
		Destinations: []ForwardDest{{Addr: "1.2.3.4:9995", Protocol: "passthrough"}},
	}})
	if err := ValidateForwardRules(badIP); err == nil {
		t.Fatal("bad exporter ip accepted")
	}
}

func TestValidateJSONDoc(t *testing.T) {
	if err := ValidateJSONDoc([]byte(`{"internal_exclude":true}`)); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if err := ValidateJSONDoc([]byte(`[1,2]`)); err == nil {
		t.Fatal("array accepted for object scope")
	}
}

func TestScopeHelpers(t *testing.T) {
	if !ValidScope(ScopeZones) || !ValidScope(CollectorScope("n1")) {
		t.Fatal("valid scope rejected")
	}
	if ValidScope(ScopeAssignFlow) || ValidScope(CollectorScope("")) || ValidScope("/nope") {
		t.Fatal("invalid scope accepted")
	}
	if id, ok := IsCollectorScope("/lucid/config/collector/n-1"); !ok || id != "n-1" {
		t.Fatalf("IsCollectorScope = %q %v", id, ok)
	}
	if got := ScopeTargets(ScopeForwardRules); len(got) != 1 || got[0] != "broker" {
		t.Fatalf("ScopeTargets(forward) = %v", got)
	}
}
