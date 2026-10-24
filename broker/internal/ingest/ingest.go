// Package ingest —— UDP 收包监听（dd/01 §1）：每端口 N 个 SO_REUSEPORT socket
// （每 CPU 一进程模型的用户态等价物，RSS+AFFINITY 由内核/部署侧保证）。
package ingest

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"

	"github.com/SchearLoe/lucidnet/broker/internal/config"
)

// Handler —— 收包回调（datagram 缓冲归 ingest 所有，回调返回后即复用；
// 需要滞留的下游自行拷贝）。
type Handler func(datagram []byte, src netip.Addr)

// Pool —— 一组监听 socket（跨端口）。
type Pool struct {
	h       Handler
	rcvBuf  int
	workers int

	conns   []net.PacketConn
	wg      sync.WaitGroup
	packets atomic.Int64
	closed  atomic.Bool
}

// NewPool 构造（workers≤0 取 config 缺省）。
func NewPool(h Handler, workers, rcvBuf int) *Pool {
	if workers <= 0 {
		workers = config.DefaultWorkersPerPort
	}
	if rcvBuf <= 0 {
		rcvBuf = config.DefaultRcvBufBytes
	}
	return &Pool{h: h, rcvBuf: rcvBuf, workers: workers}
}

// Packets 收包总数（自监控）。
func (p *Pool) Packets() int64 { return p.packets.Load() }

// Start —— 打开全部端口监听并启动收包协程；任一端口失败即整体失败（幂等回收已开 socket）。
func (p *Pool) Start(ctx context.Context, addr string, ports []int) error {
	for _, port := range ports {
		for i := 0; i < p.workers; i++ {
			conn, err := listenReuseport(addr, port, p.rcvBuf)
			if err != nil {
				p.Close()
				return fmt.Errorf("ingest: listen %s:%d (worker %d): %w", addr, port, i, err)
			}
			p.conns = append(p.conns, conn)
			p.wg.Add(1)
			go p.serve(ctx, conn)
		}
	}
	return nil
}

// serve —— 单 socket 收包循环（内联处理：FLB 同步写、Forwarder 异步目的地队列，
// 收包路径无阻塞点，dd/01 §6 性能账）。
func (p *Pool) serve(ctx context.Context, conn net.PacketConn) {
	defer p.wg.Done()
	buf := make([]byte, 0xFFFF) // UDP 数据报上限
	for {
		if err := ctx.Err(); err != nil {
			return
		}
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil || p.closed.Load() {
				return // ctx 取消或 Pool 已关闭：正常退出
			}
			continue // 瞬时读错误（Windows WSAECONNRESET 等）：继续收
		}
		p.packets.Add(1)
		ua, ok := addr.(*net.UDPAddr)
		if !ok {
			continue
		}
		src, ok := netip.AddrFromSlice(ua.IP)
		if !ok {
			continue
		}
		p.h(buf[:n], src)
	}
}

// Close 关闭全部 socket（等待协程退出；幂等）。
func (p *Pool) Close() {
	p.closed.Store(true)
	for _, c := range p.conns {
		_ = c.Close()
	}
	p.wg.Wait()
	p.conns = nil
}
