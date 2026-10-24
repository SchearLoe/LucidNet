package admin

import (
	"testing"
)

func TestCheckVersionMonotonic(t *testing.T) {
	var cur uint64
	// 首个合法版本
	v, err := checkVersion("/lucid/assign/flow", &cur, []byte(`{"version":5,"entries":[]}`))
	if err != nil || v != 5 {
		t.Fatalf("v=%d err=%v", v, err)
	}
	cur = v
	// 旧版本拒绝
	if _, err := checkVersion("/lucid/assign/flow", &cur, []byte(`{"version":4}`)); err == nil {
		t.Fatal("stale version must be rejected")
	}
	// 同版本拒绝（重放）
	if _, err := checkVersion("/lucid/assign/flow", &cur, []byte(`{"version":5}`)); err == nil {
		t.Fatal("replayed version must be rejected")
	}
	// 非法 JSON
	if _, err := checkVersion("/lucid/assign/flow", &cur, []byte(`{`)); err == nil {
		t.Fatal("bad json must be rejected")
	}
	// 0 版本拒绝
	if _, err := checkVersion("/lucid/assign/flow", &cur, []byte(`{"version":0}`)); err == nil {
		t.Fatal("version 0 must be rejected")
	}
}

func TestParseMasterCmdAndAck(t *testing.T) {
	// NodeAck{ok=1 true, config_json="{}"}
	ack := []byte{0x08, 0x01, 0x12, 0x02, '{', '}'}
	ok, cfg := parseNodeAck(ack)
	if !ok || cfg != "{}" {
		t.Fatalf("ack = %v %q", ok, cfg)
	}
	// MasterCmd{type="reload", payload_json="{}"}
	var b []byte
	b = append(b, 0x0a, 6)
	b = append(b, "reload"...)
	b = append(b, 0x12, 0x02, '{', '}')
	cmd, got := parseMasterCmd(b)
	if !got || cmd.Type != "reload" || cmd.PayloadJSON != "{}" {
		t.Fatalf("cmd = %+v got=%v", cmd, got)
	}
}
