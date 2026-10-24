package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
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
	ribPath := filepath.Join(dir, "rib.json")
	outPath := filepath.Join(dir, "flows.jsonl")

	zones := `[{"id":7,"name":"cust-a","tenant":"t1",
		"ips":[{"prefix":"203.0.113.0/24"}],"policy_id":1}]`
	rib := `[{"prefix":"203.0.113.0/24","asn":64512,"peer_as":64500}]`
	if err := os.WriteFile(zonesPath, []byte(zones), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ribPath, []byte(rib), 0o600); err != nil {
		t.Fatal(err)
	}

	// 挑空闲端口（bind :0 探测后释放，微小竞态对本地 e2e 可接受）
	probe, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	port := probe.LocalAddr().(*net.UDPAddr).Port
	probe.Close()

	f := flags{
		listen:    net.JoinHostPort("127.0.0.1", strconv.Itoa(port)),
		out:       "file",
		outFile:   outPath,
		zonesFile: zonesPath,
		zoneMatch: "dst",
		ribFile:   ribPath,
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
