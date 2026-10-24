package snmp

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/SchearLoe/lucidnet/collector/internal/enrich"
)

func rolePtr(r enrich.IfRole) *enrich.IfRole { return &r }

func newTestEngine(t *testing.T) *RuleEngine {
	t.Helper()
	e, err := NewRuleEngine([]string{"core-r1", "core-r2"}, nil) // nil → dd/02 §5.2 预置规则
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}
	return e
}

// TestRuleEnginePriorityTable —— dd/02 §5.2 判定优先级（首中即定，role_source 记录依据）。
func TestRuleEnginePriorityTable(t *testing.T) {
	e := newTestEngine(t)
	tests := []struct {
		name   string
		ev     RoleEvidence
		role   enrich.IfRole
		source RoleSource
	}{
		{
			// 优先级 1：manual 压过一切（含 LLDP/命名同时命中）
			name:   "manual wins over lldp and naming",
			ev:     RoleEvidence{IfDescr: "to-core-x", LLDPNeighborSysName: "core-r1", ManualRole: rolePtr(enrich.IfRoleBoundary)},
			role:   enrich.IfRoleBoundary,
			source: RoleSourceManual,
		},
		{
			// 环回：ifType=softwareLoopback(24) → internal（不参与业务计量）
			name:   "software loopback",
			ev:     RoleEvidence{IfDescr: "LoopBack0", IfType: ianaIfTypeSoftwareLoopback},
			role:   enrich.IfRoleInternal,
			source: RoleSourceLoopback,
		},
		{
			// 管理口：ifDescr 含 Mgmt → internal
			name:   "mgmt interface",
			ev:     RoleEvidence{IfDescr: "MgmtEth0/0/CPU0"},
			role:   enrich.IfRoleInternal,
			source: RoleSourceLoopback,
		},
		{
			// 优先级 2：LLDP 邻居 ∈ 纳管清单 → internal
			name:   "lldp neighbor managed",
			ev:     RoleEvidence{IfDescr: "GE1/0/1", LLDPNeighborSysName: "core-r1"},
			role:   enrich.IfRoleInternal,
			source: RoleSourceLLDP,
		},
		{
			// LLDP 邻居不在纳管清单 → 不判 internal，继续走优先级
			name:   "lldp neighbor unmanaged falls through to default",
			ev:     RoleEvidence{IfDescr: "GE1/0/2", LLDPNeighborSysName: "other-vendor"},
			role:   enrich.IfRoleBoundary,
			source: RoleSourceDefault,
		},
		{
			// 优先级 3：OSPF/ISIS 邻接 → internal（压过命名 boundary）
			name:   "igp adjacency beats naming",
			ev:     RoleEvidence{IfDescr: "cust-access-1", IGPAdjacency: true},
			role:   enrich.IfRoleInternal,
			source: RoleSourceIGP,
		},
		{
			// 优先级 4：命名规则 internal 预置（to-|Z_|ge.*core|-agg-|LAG）
			name:   "naming internal preset",
			ev:     RoleEvidence{IfDescr: "to-core-r1"},
			role:   enrich.IfRoleInternal,
			source: RoleSourceNaming,
		},
		{
			name:   "naming internal agg",
			ev:     RoleEvidence{IfDescr: "xe-0/0/0-agg-2"},
			role:   enrich.IfRoleInternal,
			source: RoleSourceNaming,
		},
		{
			// 命名规则 boundary 预置（cust|client|eth-trunk.*c[0-9]+）
			name:   "naming boundary preset",
			ev:     RoleEvidence{IfDescr: "GigE0/1-custA"},
			role:   enrich.IfRoleBoundary,
			source: RoleSourceNaming,
		},
		{
			// ifAlias 命中同样有效
			name:   "naming via if_alias",
			ev:     RoleEvidence{IfDescr: "GigE0/2", IfAlias: "client-link-7"},
			role:   enrich.IfRoleBoundary,
			source: RoleSourceNaming,
		},
		{
			// 优先级 5：默认 → boundary + unknown（UI 黄色提示人工确认）
			name:   "default boundary unknown",
			ev:     RoleEvidence{IfDescr: "GigE0/3"},
			role:   enrich.IfRoleBoundary,
			source: RoleSourceDefault,
		},
	}
	for _, tc := range tests {
		dec, err := e.Identify(context.Background(), tc.ev)
		if err != nil {
			t.Fatalf("%s: identify: %v", tc.name, err)
		}
		if dec.Role != tc.role || dec.Source != tc.source {
			t.Errorf("%s: = (%v,%s), want (%v,%s)", tc.name, dec.Role, dec.Source, tc.role, tc.source)
		}
		// unknown 仅 default 判定出现
		if dec.Unknown != (tc.source == RoleSourceDefault) {
			t.Errorf("%s: unknown = %v, want %v", tc.name, dec.Unknown, tc.source == RoleSourceDefault)
		}
		// evidence_json 必须可解析且 source 一致
		var ev evidenceJSON
		if err := json.Unmarshal([]byte(dec.Evidence), &ev); err != nil {
			t.Errorf("%s: evidence json: %v (%q)", tc.name, err, dec.Evidence)
		} else if ev.Source != tc.source {
			t.Errorf("%s: evidence source = %s, want %s", tc.name, ev.Source, tc.source)
		}
	}
}

func TestRuleEngineManualCanMarkInternal(t *testing.T) {
	e := newTestEngine(t)
	dec, err := e.Identify(context.Background(), RoleEvidence{
		IfDescr: "GigE0/1-custA", ManualRole: rolePtr(enrich.IfRoleInternal),
	})
	if err != nil {
		t.Fatalf("identify: %v", err)
	}
	if dec.Role != enrich.IfRoleInternal || dec.Source != RoleSourceManual {
		t.Errorf("manual internal = (%v,%s), want (internal,manual)", dec.Role, dec.Source)
	}
}

func TestNewRuleEngineBadRegex(t *testing.T) {
	_, err := NewRuleEngine(nil, []NamingRule{{Pattern: "([", Role: enrich.IfRoleInternal}})
	if err == nil {
		t.Fatal("bad regex: want error")
	}
	if !strings.Contains(err.Error(), "compile naming rule") {
		t.Errorf("err = %v, want compile naming rule context", err)
	}
}
