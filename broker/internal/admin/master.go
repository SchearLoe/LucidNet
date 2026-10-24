package admin

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/SchearLoe/lucidnet/broker/internal/wire"
)

// MasterAgent —— Master 注册/心跳（docs/09 §4：RegisterNode + Heartbeat 双向流，端口 9140）。
//
// 实现说明：gen/go 生成代码尚未接入（docs/09 §0），本文件按 proto/lucidnet/v1/service.proto
// 手工编解码 NodeInfo/NodeStat/MasterCmd，经 grpc 原始码流调用；生成代码就绪后替换。
type MasterAgent struct {
	addr    string // host:port（shared.AddrMasterGRPC 基线 :9140）
	nodeID  string
	role    string
	host    string
	cores   uint32
	memGB   uint32
	metrics func() string // 心跳摘要 JSON（Prometheus 为主通道，此为心跳摘要）
	onCmd   func(MasterCmd)
	log     *slog.Logger

	closeOnce sync.Once
}

// MasterCmd —— Heartbeat 下行命令（dd/08 §3：reload|drain|deploy_command）。
type MasterCmd struct {
	Type        string
	PayloadJSON string
}

// NewMasterAgent 构造（metrics/onCmd 可 nil）。
func NewMasterAgent(addr, nodeID, host string, cores, memGB uint32, metrics func() string, onCmd func(MasterCmd), log *slog.Logger) *MasterAgent {
	if log == nil {
		log = slog.Default()
	}
	if metrics == nil {
		metrics = func() string { return "{}" }
	}
	if onCmd == nil {
		onCmd = func(MasterCmd) {}
	}
	return &MasterAgent{
		addr:    addr,
		nodeID:  nodeID,
		role:    "broker",
		host:    host,
		cores:   cores,
		memGB:   memGB,
		metrics: metrics,
		onCmd:   onCmd,
		log:     log,
	}
}

// rawCodec —— grpc 透传码流（消息已由 wire 包手工编码）。
type rawCodec struct{}

func (rawCodec) Marshal(v any) ([]byte, error) {
	if b, ok := v.([]byte); ok {
		return b, nil
	}
	return nil, fmt.Errorf("admin: raw codec expects []byte, got %T", v)
}

func (rawCodec) Unmarshal(data []byte, v any) error {
	if p, ok := v.(*[]byte); ok {
		*p = data
		return nil
	}
	return fmt.Errorf("admin: raw codec expects *[]byte, got %T", v)
}

func (rawCodec) Name() string { return "lucid-raw-proto" }

const (
	methodRegister  = "/lucidnet.v1.Master/RegisterNode"
	methodHeartbeat = "/lucidnet.v1.Master/Heartbeat"
)

// Run —— 注册 + 心跳主循环（断线重连，间隔=心跳周期；ctx 取消退出）。
func (a *MasterAgent) Run(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 10 * time.Second
	}
	for ctx.Err() == nil {
		if err := a.session(ctx, interval); err != nil && ctx.Err() == nil {
			a.log.Warn("admin: master session ended", "addr", a.addr, "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(interval):
		}
	}
}

// session —— 单次连接生命周期：注册 → 心跳双向流。
func (a *MasterAgent) session(ctx context.Context, interval time.Duration) error {
	conn, err := grpc.NewClient(a.addr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(grpc.ForceCodec(rawCodec{})),
	)
	if err != nil {
		return fmt.Errorf("admin: dial master %s: %w", a.addr, err)
	}
	defer conn.Close() //nolint:errcheck // 会话退出关闭

	// RegisterNode（unary）
	req := a.marshalNodeInfo()
	var ack []byte
	if err := conn.Invoke(ctx, methodRegister, req, &ack); err != nil {
		return fmt.Errorf("admin: register node: %w", err)
	}
	ok, _ := parseNodeAck(ack)
	if !ok {
		return fmt.Errorf("admin: register rejected by master")
	}
	a.log.Info("admin: registered with master", "addr", a.addr, "node", a.nodeID)

	// Heartbeat（bidi stream：上行 NodeStat / 下行 MasterCmd）
	desc := &grpc.StreamDesc{StreamName: "Heartbeat", ServerStreams: true, ClientStreams: true}
	cs, err := conn.NewStream(ctx, desc, methodHeartbeat)
	if err != nil {
		return fmt.Errorf("admin: open heartbeat stream: %w", err)
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		if err := cs.SendMsg(a.marshalNodeStat()); err != nil {
			return fmt.Errorf("admin: send heartbeat: %w", err)
		}
		var reply []byte
		if err := cs.RecvMsg(&reply); err != nil {
			return fmt.Errorf("admin: recv master cmd: %w", err)
		}
		if cmd, ok := parseMasterCmd(reply); ok {
			a.handleCmd(cmd)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
	}
}

// handleCmd —— 下行命令（reload：MVP 记录日志；配置面以 etcd watch 为准，docs/09 裁定⑤）。
func (a *MasterAgent) handleCmd(cmd MasterCmd) {
	a.log.Info("admin: master command", "type", cmd.Type, "payload", cmd.PayloadJSON)
	a.onCmd(cmd)
}

// marshalNodeInfo —— NodeInfo{id,role,host,cores,mem_gb}。
func (a *MasterAgent) marshalNodeInfo() []byte {
	var w wire.Writer
	w.String(1, a.nodeID)
	w.String(2, a.role)
	w.String(3, a.host)
	w.Uint(4, uint64(a.cores))
	w.Uint(5, uint64(a.memGB))
	return bytes.Clone(w.Bytes())
}

// marshalNodeStat —— NodeStat{node_id,ts_ms,metrics_json}。
func (a *MasterAgent) marshalNodeStat() []byte {
	var w wire.Writer
	w.String(1, a.nodeID)
	w.Int(2, time.Now().UnixMilli())
	w.String(3, a.metrics())
	return bytes.Clone(w.Bytes())
}

// parseNodeAck —— NodeAck{ok=1 bool,config_json=2 string}。
func parseNodeAck(b []byte) (bool, string) {
	var ok bool
	cfgJSON := ""
	rd := wire.NewReader(b)
	for {
		f, err := rd.Next()
		if err != nil || f.Number == 0 {
			break
		}
		switch f.Number {
		case 1:
			ok = f.Varint != 0
		case 2:
			cfgJSON = string(f.Bytes)
		}
	}
	return ok, cfgJSON
}

// parseMasterCmd —— MasterCmd{type=1,payload_json=2}。
func parseMasterCmd(b []byte) (MasterCmd, bool) {
	var cmd MasterCmd
	rd := wire.NewReader(b)
	for {
		f, err := rd.Next()
		if err != nil || f.Number == 0 {
			return cmd, cmd.Type != ""
		}
		switch f.Number {
		case 1:
			cmd.Type = string(f.Bytes)
		case 2:
			cmd.PayloadJSON = string(f.Bytes)
		}
	}
}
