package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/SchearLoe/lucidnet/collector/internal/etcdcfg"
	"github.com/SchearLoe/lucidnet/collector/internal/zone"
	"github.com/SchearLoe/lucidnet/shared"
)

// e2e 冒烟：UDP v5 数据报 → 解码 → 富化（zone/rib）→ file 输出 → 优雅退出。
// 覆盖 main.go 组装链路（dispatcher/pipeline/producer/listener/关闭顺序）。

// buildV5Datagram —— 手工构造 NetFlow v5 报文（头 24B + 记录 48B）。
func buildV5Datagram() []byte {
	h := make([]byte, 24)
	binary.BigEndian.PutUint16(h[0:2], 5)       // version
	binary.BigEndian.PutUint16(h[2:4], 1)       // count
	binary.BigEndian.PutUint32(h[4:8], 100_000) // sysuptime(ms)
	binary.BigEndian.PutUint32(h[8:12], 1_700_000_000)
	binary.BigEndian.PutUint32(h[12:16], 500_000_000) // unix_nsecs
	binary.BigEndian.PutUint32(h[16:20], 42)          // flow_sequence
	h[20], h[21] = 1, 2                               // engine_type/id
	// h[22:24] sampling = 0

	r := make([]byte, 48)
	binary.BigEndian.PutUint32(r[0:4], 0xC0000217)  // src 192.0.2.23
	binary.BigEndian.PutUint32(r[4:8], 0xCB007107)  // dst 203.0.113.7
	binary.BigEndian.PutUint32(r[8:12], 0xCB007101) // nexthop 203.0.113.1
	binary.BigEndian.PutUint16(r[12:14], 5)         // input
	binary.BigEndian.PutUint16(r[14:16], 9)         // output
	binary.BigEndian.PutUint32(r[16:20], 1000)      // dPkts
	binary.BigEndian.PutUint32(r[20:24], 150_000)   // dOctets
	binary.BigEndian.PutUint32(r[24:28], 50_000)    // first
	binary.BigEndian.PutUint32(r[28:32], 90_000)    // last
	binary.BigEndian.PutUint16(r[32:34], 1024)      // srcport
	binary.BigEndian.PutUint16(r[34:36], 443)       // dstport
	r[37], r[38], r[39] = 0x12, 6, 0x2e             // tcp_flags / proto / tos
	binary.BigEndian.PutUint16(r[40:42], 65001)     // src_as
	binary.BigEndian.PutUint16(r[42:44], 65002)     // dst_as
	return append(h, r...)
}

func TestEndToEndV5ToOutput(t *testing.T) {
	dir := t.TempDir()
	zonesPath := filepath.Join(dir, "zones.json")
	nodeCfgPath := filepath.Join(dir, "node-config.json")
	ribPath := filepath.Join(dir, "rib.json")
	outPath := filepath.Join(dir, "flows.jsonl")

	// 挑空闲端口（bind :0 探测后释放，微小竞态对本地 e2e 可接受）
	probe, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	port := probe.LocalAddr().(*net.UDPAddr).Port
	probe.Close()

	// /lucid/zones 值（信封，09 §5 2026-10-25 裁定；文件为 etcd watch 开发替身）
	zones := `{"version":3,"updated_at":"2026-10-25T08:00:00Z","data":[
		{"id":7,"name":"cust-a","tenant":"t1",
		 "ips":[{"prefix":"203.0.113.0/24"}],"policy_id":1}]}`
	rib := `[{"prefix":"203.0.113.0/24","asn":64512,"peer_as":64500}]`
	if err := os.WriteFile(zonesPath, []byte(zones), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ribPath, []byte(rib), 0o600); err != nil {
		t.Fatal(err)
	}
	// /lucid/config/collector/{node} 值（信封）：监听地址覆盖 flag + zone_match + 采样登记表
	nodeCfg := `{"version":2,"updated_at":"2026-10-25T08:00:01Z","data":{
		"listen":"127.0.0.1:` + strconv.Itoa(port) + `",
		"zone_match":"dst",
		"sample_registry":{"10.255.0.1":1}}}`
	if err := os.WriteFile(nodeCfgPath, []byte(nodeCfg), 0o600); err != nil {
		t.Fatal(err)
	}

	f := flags{
		listen:         ":19999", // 应被 node 配置覆盖为上方探测端口
		node:           "test-node",
		zonesFile:      zonesPath,
		nodeConfigFile: nodeCfgPath,
		zoneMatch:      "dst",
		out:            "file",
		outFile:        outPath,
		ribFile:        ribPath,
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- runCollector(ctx, f) }()

	// 持续发包直至窗口结束（绑定竞态容忍；首包丢失不影响断言）
	dg := buildV5Datagram()
	sender, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := sender.Write(dg); err != nil {
			cancel()
			t.Fatalf("send: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	sender.Close()

	// 优雅退出：取消 → 关 socket → 冲刷 → 返回
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("runCollector: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("runCollector did not exit after cancel")
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) == 0 || lines[0] == "" {
		t.Fatal("no output lines produced")
	}
	var env struct {
		Topic  string `json:"topic"`
		KeyHex string `json:"key_hex"`
		Record struct {
			Exporter    string `json:"exporter"`
			DstIP       string `json:"dst_ip"`
			Proto       uint32 `json:"proto"`
			DstPort     uint32 `json:"dst_port"`
			DstAS       uint32 `json:"dst_as"`
			ZoneID      int32  `json:"zone_id"`
			ZoneSide    uint32 `json:"zone_side"`
			IfRole      uint32 `json:"if_role"`
			TimeStartMs int64  `json:"time_start_ms"`
		} `json:"record"`
	}
	if err := json.Unmarshal([]byte(lines[0]), &env); err != nil {
		t.Fatalf("unmarshal output line: %v\nline: %s", err, lines[0])
	}
	if env.Topic != "flows.raw" {
		t.Errorf("topic = %q, want flows.raw", env.Topic)
	}
	if env.Record.DstIP != "203.0.113.7" || env.Record.Proto != 6 || env.Record.DstPort != 443 {
		t.Errorf("decoded fields = %+v", env.Record)
	}
	if env.Record.TimeStartMs != 1_699_999_950_500 {
		t.Errorf("time_start_ms = %d, want 1699999950500（unix_secs+sysuptime 换算）", env.Record.TimeStartMs)
	}
	if env.Record.DstAS != 64512 {
		t.Errorf("dst_as = %d, want 64512（RIB 快照富化覆盖）", env.Record.DstAS)
	}
	if env.Record.ZoneID != 7 || env.Record.ZoneSide != 1 {
		t.Errorf("zone = (%d,%d), want (7,1)（dst 命中 → ZoneSideDst，09 §3）", env.Record.ZoneID, env.Record.ZoneSide)
	}
	// 设备/接口角色未知 → unknown 按 boundary：两位均置位（09 §3）
	if env.Record.IfRole != 3 {
		t.Errorf("if_role = %d, want 3（unknown 按 boundary，两位均 1）", env.Record.IfRole)
	}
}

// —— 信封配置入口单测（applyZonesSnapshot / applyNodeConfig；09 §5 2026-10-25 信封裁定） ——

// ip16 —— 地址文本 → 16B（v4 用 ::ffff: 映射）。
func ip16(s string) [16]byte {
	a := netip.MustParseAddr(s)
	var b [16]byte
	if a.Is4() {
		v4 := a.As4()
		b[10], b[11] = 0xff, 0xff
		copy(b[12:16], v4[:])
	} else {
		b = a.As16()
	}
	return b
}

func TestApplyZonesSnapshotEnvelope(t *testing.T) {
	m := zone.NewMatcher(zone.MatchDst)
	g := etcdcfg.NewGuard()

	v1 := `{"version":1,"updated_at":"2026-10-25T08:00:00Z","data":[{"id":7,"ips":[{"prefix":"203.0.113.0/24"}]}]}`
	v2 := `{"version":2,"updated_at":"2026-10-25T08:01:00Z","data":[{"id":8,"ips":[{"prefix":"198.51.100.0/24"}]}]}`

	// 正常信封 v1 → 应用
	if err := applyZonesSnapshot(m, g, []byte(v1)); err != nil {
		t.Fatalf("apply v1: %v", err)
	}
	if id, ok := m.Lookup(ip16("203.0.113.7")); !ok || id != 7 {
		t.Errorf("v1 lookup = (%d,%v), want (7,true)", id, ok)
	}
	if g.Applied(shared.EtcdKeyZones) != 1 {
		t.Errorf("applied = %d, want 1", g.Applied(shared.EtcdKeyZones))
	}

	// v2 → 全量换树（旧 zone 移除）
	if err := applyZonesSnapshot(m, g, []byte(v2)); err != nil {
		t.Fatalf("apply v2: %v", err)
	}
	if id, ok := m.Lookup(ip16("198.51.100.1")); !ok || id != 8 {
		t.Errorf("v2 lookup = (%d,%v), want (8,true)", id, ok)
	}
	if id, ok := m.Lookup(ip16("203.0.113.7")); ok || id != 0 {
		t.Errorf("v1 zone must be removed after v2, got (%d,%v)", id, ok)
	}

	// 版本回落 v1 → 忽略（不报错、不回退树、stale 计数）
	if err := applyZonesSnapshot(m, g, []byte(v1)); err != nil {
		t.Fatalf("stale apply must not error: %v", err)
	}
	if id, ok := m.Lookup(ip16("198.51.100.1")); !ok || id != 8 {
		t.Errorf("stale apply changed tree: (%d,%v), want still v2 zone 8", id, ok)
	}
	if g.Applied(shared.EtcdKeyZones) != 2 || g.StaleTotal() != 1 {
		t.Errorf("applied=%d stale=%d, want 2/1", g.Applied(shared.EtcdKeyZones), g.StaleTotal())
	}

	// 裸 payload（zones 形状数组，无信封）→ 报错
	if err := applyZonesSnapshot(m, g, []byte(`[{"id":7,"ips":[{"prefix":"203.0.113.0/24"}]}]`)); err == nil {
		t.Error("bare payload must be rejected")
	}
	// 信封缺字段 → 报错
	if err := applyZonesSnapshot(m, g, []byte(`{"version":1,"data":[]}`)); err == nil {
		t.Error("incomplete envelope must be rejected")
	}
	// 信封合法但 payload 非法（坏 CIDR）→ 报错且版本未记账（同版本重试语义）
	badPayload := `{"version":5,"updated_at":"2026-10-25T08:02:00Z","data":[{"id":9,"ips":[{"prefix":"not-a-cidr"}]}]}`
	if err := applyZonesSnapshot(m, g, []byte(badPayload)); err == nil {
		t.Error("invalid payload must be rejected")
	}
	if g.Applied(shared.EtcdKeyZones) != 2 {
		t.Errorf("failed apply must not mark version: applied=%d, want 2", g.Applied(shared.EtcdKeyZones))
	}
	if !g.ShouldApply(shared.EtcdKeyZones, 5) {
		t.Error("version 5 must still be applicable after failed apply (two-phase guard)")
	}
}

func TestApplyNodeConfig(t *testing.T) {
	m := zone.NewMatcher(zone.MatchDst) // flag 缺省 dst
	g := etcdcfg.NewGuard()

	// 裸 payload 对象（无信封字段）→ 报错
	if _, err := applyNodeConfig(m, g, "n1", []byte(`{"zone_match":"src"}`)); err == nil {
		t.Error("bare config object must be rejected")
	}

	// 正常信封：zone_match 覆盖 + 负载返回（listen/采样登记表）
	env := `{"version":4,"updated_at":"2026-10-25T08:00:00Z","data":{
		"zone_match":"src","listen":":9999","sample_registry":{"10.0.0.1":100}}}`
	cfg, err := applyNodeConfig(m, g, "n1", []byte(env))
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if m.MatchField() != zone.MatchSrc {
		t.Errorf("zone_match = %v, want src（etcd 覆盖 flag 缺省）", m.MatchField())
	}
	if cfg.Listen != ":9999" || cfg.SampleRegistry["10.0.0.1"] != 100 {
		t.Errorf("returned config = %+v", cfg)
	}
	if g.Applied(shared.EtcdKeyConfigCollector+"n1") != 4 {
		t.Errorf("applied = %d, want 4", g.Applied(shared.EtcdKeyConfigCollector+"n1"))
	}

	// 版本回落 → 忽略：zone_match 不被旧值改回
	stale := `{"version":3,"updated_at":"2026-10-25T07:00:00Z","data":{"zone_match":"dst"}}`
	if _, err := applyNodeConfig(m, g, "n1", []byte(stale)); err != nil {
		t.Fatalf("stale apply must not error: %v", err)
	}
	if m.MatchField() != zone.MatchSrc {
		t.Errorf("stale apply changed zone_match to %v", m.MatchField())
	}
	if g.StaleTotal() != 1 {
		t.Errorf("stale total = %d, want 1", g.StaleTotal())
	}

	// 非法 zone_match（both，09 §3 禁止）→ 报错
	bad := `{"version":5,"updated_at":"2026-10-25T08:01:00Z","data":{"zone_match":"both"}}`
	if _, err := applyNodeConfig(m, g, "n1", []byte(bad)); err == nil || !strings.Contains(err.Error(), "zone_match") {
		t.Errorf("zone_match=both err = %v, want zone_match validation error", err)
	}

	// 不同节点键版本台账独立
	if _, err := applyNodeConfig(m, g, "n2", []byte(`{"version":1,"updated_at":"2026-10-25T08:00:00Z","data":{}}`)); err != nil {
		t.Fatalf("apply n2: %v", err)
	}
	if g.Applied(shared.EtcdKeyConfigCollector+"n2") != 1 {
		t.Errorf("n2 applied = %d, want 1", g.Applied(shared.EtcdKeyConfigCollector+"n2"))
	}
}
