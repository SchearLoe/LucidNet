package rpc

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// CmdHub —— 下行命令队列（docs/09 §4：Deploy 命令通道复用 Master.Heartbeat 下行流，
// docs/dd/08 §3.1/3.2；docs/dd/07 §1 Heartbeat 下行：重载配置/排水）。
//
// 语义：每节点一条 FIFO 队列 + 每流投递；组件未连接时命令驻留，重连后投递。
// 队列满（默认 256）时拒绝新命令（调用方回错，Console 可见）。

// Cmd —— 下行命令。
type Cmd struct {
	ID          string    `json:"id,omitempty"` // deploy_command: Command.id（dd/08 §3.2）
	Type        string    `json:"type"`         // reload|drain|deploy_command
	PayloadJSON string    `json:"payload"`
	CreatedAt   time.Time `json:"created_at"`
}

// 命令类型常量（proto MasterCmd.type 注释契约）。
const (
	CmdTypeReload        = "reload"
	CmdTypeDrain         = "drain"
	CmdTypeDeployCommand = "deploy_command"
)

// Hub —— 命令中枢。
type Hub struct {
	mu      sync.Mutex
	queues  map[string][]Cmd
	waiters map[string]map[int]chan struct{}
	nextID  int
	max     int
}

// NewHub 构造。
func NewHub() *Hub {
	return &Hub{
		queues:  map[string][]Cmd{},
		waiters: map[string]map[int]chan struct{}{},
		max:     256,
	}
}

// Push 入队（节点队列满返回错误）。
func (h *Hub) Push(nodeID string, c Cmd) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	q := h.queues[nodeID]
	if len(q) >= h.max {
		return fmt.Errorf("command queue full for node %s", nodeID)
	}
	h.queues[nodeID] = append(q, c)
	h.notifyLocked(nodeID)
	return nil
}

// Pop 弹出一条命令（无命令时等待直至有命令/ctx 结束；虚假唤醒内部消化）。
func (h *Hub) Pop(ctx context.Context, nodeID string) (Cmd, error) {
	for {
		h.mu.Lock()
		if len(h.queues[nodeID]) > 0 {
			c := h.queues[nodeID][0]
			h.queues[nodeID] = h.queues[nodeID][1:]
			h.mu.Unlock()
			return c, nil
		}
		h.nextID++
		id := h.nextID
		ch := make(chan struct{}, 1)
		if h.waiters[nodeID] == nil {
			h.waiters[nodeID] = map[int]chan struct{}{}
		}
		h.waiters[nodeID][id] = ch
		h.mu.Unlock()

		select {
		case <-ctx.Done():
			h.removeWaiter(nodeID, id)
			return Cmd{}, ctx.Err()
		case <-ch:
			// 有通知：回到队首检查（队列为空则继续等待）
		}
	}
}

func (h *Hub) notifyLocked(nodeID string) {
	for _, ch := range h.waiters[nodeID] {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}

func (h *Hub) removeWaiter(nodeID string, id int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if m, ok := h.waiters[nodeID]; ok {
		delete(m, id)
		if len(m) == 0 {
			delete(h.waiters, nodeID)
		}
	}
}

// Pending 队列深度（运维观测）。
func (h *Hub) Pending(nodeID string) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.queues[nodeID])
}
