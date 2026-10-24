package flb

import (
	"net"
	"testing"
	"time"
)

func TestCompileAssign(t *testing.T) {
	snap := &AssignSnapshot{
		Version: 12,
		Entries: []AssignEntry{
			{Exporter: "10.1.1.1", Collector: "10.0.0.11:9995"},
			{Exporter: "10.1.1.2", Collector: "10.0.0.11:9995"},
			{Exporter: "10.1.1.3", Collector: "10.0.0.12:9995"},
			{Exporter: "", Collector: "10.0.0.13:9995"}, // 非法条目忽略
			{Exporter: "10.1.1.4", Collector: ""},       // 非法条目忽略
		},
	}
	tbl := CompileAssign(snap)
	if tbl.Version != 12 || tbl.Len() != 3 {
		t.Fatalf("table = v%d n=%d", tbl.Version, tbl.Len())
	}
	if got, _ := tbl.Assigned("10.1.1.1"); got != "10.0.0.11:9995" {
		t.Errorf("assigned = %s", got)
	}
	if cs := tbl.Collectors(); len(cs) != 2 {
		t.Errorf("collectors dedup = %v", cs)
	}
}

func TestTablePtrAtomic(t *testing.T) {
	var tp TablePtr
	if t0 := tp.Load(); t0.Len() != 0 {
		t.Fatal("fresh table must be empty")
	}
	tp.Store(CompileAssign(&AssignSnapshot{Version: 1, Entries: []AssignEntry{{Exporter: "e", Collector: "c"}}}))
	if _, ok := tp.Load().Assigned("e"); !ok {
		t.Fatal("atomic swap lost entry")
	}
}

// TestDispatcherForward —— 查表命中 → 转发到真实本地 UDP collector 桩。
func TestDispatcherForward(t *testing.T) {
	c1 := listenUDP(t)
	c2 := listenUDP(t)
	h := NewHealth(0, 0, nil)
	d := NewDispatcher(nil, h, nil)
	d.Table().Store(CompileAssign(&AssignSnapshot{
		Version: 1,
		Entries: []AssignEntry{{Exporter: "10.1.1.1", Collector: c1.LocalAddr().String()}},
	}))
	d.Forward([]byte("hello-flow"), "10.1.1.1")
	buf := make([]byte, 1500)
	_ = c1.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := c1.ReadFrom(buf)
	if err != nil {
		t.Fatalf("collector1 recv: %v", err)
	}
	if string(buf[:n]) != "hello-flow" {
		t.Errorf("payload = %q", buf[:n])
	}
	// 未知 exporter → 哈希落到候选之一（c1/c2 未登记时无候选 → 丢弃，不 panic）
	d2 := NewDispatcher(nil, NewHealth(0, 0, nil), nil)
	d2.Table().Store(CompileAssign(&AssignSnapshot{Version: 1}))
	d2.Forward([]byte("x"), "10.9.9.9") // 无候选：丢弃路径（无 panic 即通过）
	_ = c2
}

// TestDispatcherHealthFallback —— 分配节点不健康 → 哈希兜底到健康候选（dd/01 §2.3）。
func TestDispatcherHealthFallback(t *testing.T) {
	c1 := listenUDP(t)
	c2 := listenUDP(t)
	var events []string
	h := NewHealth(3, 60*time.Second, func(addr string, down bool) {
		events = append(events, addr)
	})
	d := NewDispatcher(nil, h, nil)
	d.Table().Store(CompileAssign(&AssignSnapshot{
		Version: 1,
		Entries: []AssignEntry{
			{Exporter: "10.1.1.7", Collector: c1.LocalAddr().String()},
			// c2 进入候选池（另一 exporter 的分配）；兜底哈希在其健康时可选它
			{Exporter: "10.9.9.9", Collector: c2.LocalAddr().String()},
		},
	}))

	// 将 c1 标记 down：3 次失败
	now := time.Now()
	for i := 0; i < 3; i++ {
		h.RecordFail(c1.LocalAddr().String(), now)
	}
	if h.IsHealthy(c1.LocalAddr().String(), now) {
		t.Fatal("c1 should be down after 3 failures")
	}
	d.Forward([]byte("fallback"), "10.1.1.7")
	buf := make([]byte, 1500)
	_ = c2.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, _, err := c2.ReadFrom(buf); err != nil {
		t.Fatalf("fallback to c2 failed: %v", err)
	}
}

// TestHealthRestoreAfter —— 60s 未被 Master 纠正则恢复信 Master（dd/01 §2.3）。
func TestHealthRestoreAfter(t *testing.T) {
	h := NewHealth(3, 50*time.Millisecond, nil)
	now := time.Now()
	for i := 0; i < 3; i++ {
		h.RecordFail("10.0.0.1:9995", now)
	}
	if h.IsHealthy("10.0.0.1:9995", now) {
		t.Fatal("must be down")
	}
	if !h.IsHealthy("10.0.0.1:9995", now.Add(60*time.Millisecond)) {
		t.Fatal("must restore after restoreAfter")
	}
	// 恢复后 RecordOK 清零
	h.RecordOK("10.0.0.1:9995")
	if !h.IsHealthy("10.0.0.1:9995", now.Add(70*time.Millisecond)) {
		t.Fatal("must stay healthy after OK")
	}
}

func listenUDP(t *testing.T) *net.UDPConn {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn.(*net.UDPConn)
}
