package ingest

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"
)

// TestPoolRoundtrip —— 收包回调拿到完整数据报与源地址。
func TestPoolRoundtrip(t *testing.T) {
	got := make(chan []byte, 1)
	gotAddr := make(chan netip.Addr, 1)
	pool := NewPool(func(dg []byte, src netip.Addr) {
		b := make([]byte, len(dg))
		copy(b, dg)
		got <- b
		gotAddr <- src
	}, 1, 1<<20)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// 先占一个 UDP socket 获取系统可用端口再释放
	probe, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("no udp: %v", err)
	}
	port := probe.LocalAddr().(*net.UDPAddr).Port
	probe.Close()

	// SO_REUSEPORT 语义：Unix 可复用刚释放端口；Windows 回退单 socket 绑定
	if err := pool.Start(ctx, "127.0.0.1", []int{port}); err != nil {
		t.Skipf("cannot bind port %d: %v", port, err)
	}
	defer pool.Close()

	cli, err := net.Dial("udp", net.JoinHostPort("127.0.0.1", itoa(port)))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if _, err := cli.Write([]byte("ping")); err != nil {
		t.Fatalf("write: %v", err)
	}
	select {
	case b := <-got:
		if string(b) != "ping" {
			t.Errorf("payload = %q", b)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no packet received")
	}
	select {
	case a := <-gotAddr:
		if !a.IsValid() || a.String() != "127.0.0.1" {
			t.Errorf("src = %v", a)
		}
	case <-time.After(time.Second):
		t.Fatal("no src addr")
	}
	if pool.Packets() < 1 {
		t.Errorf("packets counter = %d", pool.Packets())
	}
}

// TestPoolCloseIdempotent —— Close 幂等且唤醒收包协程。
func TestPoolCloseIdempotent(t *testing.T) {
	pool := NewPool(func([]byte, netip.Addr) {}, 1, 1<<20)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	probe, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("no udp: %v", err)
	}
	port := probe.LocalAddr().(*net.UDPAddr).Port
	probe.Close()
	if err := pool.Start(ctx, "127.0.0.1", []int{port}); err != nil {
		t.Skipf("bind failed: %v", err)
	}
	pool.Close()
	pool.Close() // 幂等
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b [8]byte
	p := len(b)
	for i > 0 {
		p--
		b[p] = byte('0' + i%10)
		i /= 10
	}
	return string(b[p:])
}
