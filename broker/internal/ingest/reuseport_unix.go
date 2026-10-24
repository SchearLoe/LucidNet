//go:build linux || darwin || freebsd || netbsd || openbsd

package ingest

import (
	"fmt"
	"net"
	"syscall"
)

// listenReuseport —— SO_REUSEPORT 监听（dd/01 §1：N socket/端口，内核分散收包）；
// SO_RCVBUF ≥64MB（dd/01 §2.5，受 net.core.rmem_max 上限制约）。
func listenReuseport(addr string, port, rcvBuf int) (net.PacketConn, error) {
	lc := net.ListenConfig{Control: controlReuseport(rcvBuf)}
	conn, err := lc.ListenPacket(nil, "udp", net.JoinHostPort(addr, fmt.Sprint(port)))
	if err != nil {
		return nil, err
	}
	return conn, nil
}

func controlReuseport(rcvBuf int) func(network, address string, c syscall.RawConn) error {
	return func(network, address string, c syscall.RawConn) error {
		var ctlErr error
		err := c.Control(func(fd uintptr) {
			if e := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEPORT, 1); e != nil {
				ctlErr = e
				return
			}
			if rcvBuf > 0 {
				if e := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF, rcvBuf); e != nil {
					ctlErr = e
				}
			}
		})
		if err != nil {
			return err
		}
		return ctlErr
	}
}
