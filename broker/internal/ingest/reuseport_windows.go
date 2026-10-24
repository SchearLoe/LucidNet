//go:build windows || plan9 || js || wasip1

package ingest

import (
	"fmt"
	"net"
)

// listenReuseport —— 非 Unix 平台回退：无 SO_REUSEPORT 语义（Windows 无对应选项），
// 单 socket 监听；SO_RCVBUF 尽力设置。生产部署目标为 Linux（dd/08）。
func listenReuseport(addr string, port, rcvBuf int) (net.PacketConn, error) {
	lc := net.ListenConfig{}
	conn, err := lc.ListenPacket(nil, "udp", net.JoinHostPort(addr, fmt.Sprint(port)))
	if err != nil {
		return nil, err
	}
	if rcvBuf > 0 {
		if c, ok := conn.(*net.UDPConn); ok {
			_ = c.SetReadBuffer(rcvBuf)
		}
	}
	return conn, nil
}
