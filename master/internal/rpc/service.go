package rpc

import (
	"context"
	"fmt"
	"io"
	"log"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/SchearLoe/lucidnet/master/internal/assign"
	"github.com/SchearLoe/lucidnet/master/internal/config"
	lucidnetv1 "github.com/SchearLoe/lucidnet/master/internal/masterpb"
	"github.com/SchearLoe/lucidnet/master/internal/registry"
)

// Master gRPC 服务（docs/09 §4，端口 9140 = shared.AddrMasterGRPC）。
// 服务属主 Master：RegisterNode / Heartbeat(双向流) / PublishConfig / WatchAssign。

// Deps —— 服务依赖（由根包装配注入，避免包间环）。
type Deps struct {
	Registry *registry.Registry
	Config   *config.Store
	Assigner *assign.Assigner
	Hub      *Hub
	// Leader 只读判定（配置变更类 RPC 拒绝非 leader；docs/dd/07 §7）
	Leader func() bool
	// Now 测试时钟。
	Now func() time.Time
}

// Service —— lucidnetv1.MasterServer 实现。
type Service struct {
	lucidnetv1.UnimplementedMasterServer
	d Deps
}

// NewService 构造。
func NewService(d Deps) *Service {
	if d.Now == nil {
		d.Now = time.Now
	}
	if d.Hub == nil {
		d.Hub = NewHub()
	}
	return &Service{d: d}
}

// Hub 命令中枢（restapi 触发排水命令用）。
func (s *Service) Hub() *Hub { return s.d.Hub }

// RegisterNode 节点注册：自报角色/容量（含 nics 网卡档案，Mbps→Gbps 换算入权重，
// docs/dd/07 §2）→ 返回角色配置（docs/dd/07 §1）。
func (s *Service) RegisterNode(ctx context.Context, info *lucidnetv1.NodeInfo) (*lucidnetv1.NodeAck, error) {
	if info.GetId() == "" {
		return nil, status.Error(codes.InvalidArgument, "node id required")
	}
	var nics []registry.NIC
	if len(info.GetNics()) > 0 {
		nics = make([]registry.NIC, 0, len(info.GetNics()))
		for _, nic := range info.GetNics() {
			nics = append(nics, registry.NICFromMbps(nic.GetName(), nic.GetSpeedMbps()))
		}
	}
	n, err := s.d.Registry.Register(ctx, registry.Node{
		ID:    info.GetId(),
		Role:  registry.Role(info.GetRole()),
		Host:  info.GetHost(),
		Cores: info.GetCores(),
		MemGB: info.GetMemGb(),
		NICs:  nics, // 空 = 未上报，权重按 25G 基准兜底（向后兼容旧版 Broker）
		// 版本号来自心跳 metrics_json.version（NodeInfo 契约无版本字段）
	})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "register node %s: %v", info.GetId(), err)
	}
	cfgJSON, err := s.d.Config.RoleConfigJSON(ctx, string(n.Role), n.ID)
	if err != nil {
		log.Printf(`{"level":"warn","module":"master.rpc","msg":"role config","node":%q,"err":%q}`,
			n.ID, err.Error())
		cfgJSON = `{"scopes":{}}`
	}
	return &lucidnetv1.NodeAck{Ok: true, ConfigJson: cfgJSON}, nil
}

// Heartbeat 双向流：指标上行（NodeStat）/ 命令下行（MasterCmd：reload|drain|
// deploy_command，docs/dd/08 §3.1 复用）。
func (s *Service) Heartbeat(stream lucidnetv1.Master_HeartbeatServer) error {
	// 首条 NodeStat 确定节点身份；未注册节点拒绝
	first, err := stream.Recv()
	if err != nil {
		return status.Errorf(codes.InvalidArgument, "recv first heartbeat: %v", err)
	}
	nodeID := first.GetNodeId()
	if nodeID == "" {
		return status.Error(codes.InvalidArgument, "node id required")
	}
	if _, err := s.d.Registry.Get(stream.Context(), nodeID); err != nil {
		if err == registry.ErrNotFound {
			return status.Errorf(codes.NotFound, "node %s not registered", nodeID)
		}
		return status.Errorf(codes.Internal, "get node %s: %v", nodeID, err)
	}

	cmds := make(chan *lucidnetv1.MasterCmd, 16)
	errCh := make(chan error, 2)

	// 下行：命令队列 → 流
	go func() {
		defer close(cmds)
		for {
			c, err := s.d.Hub.Pop(stream.Context(), nodeID)
			if err != nil {
				return
			}
			select {
			case cmds <- &lucidnetv1.MasterCmd{Type: c.Type, PayloadJson: c.PayloadJSON}:
			case <-stream.Context().Done():
				return
			}
		}
	}()

	// 上行接收
	go func() {
		for {
			stat, err := stream.Recv()
			if err != nil {
				errCh <- err
				return
			}
			if stat.GetNodeId() != "" && stat.GetNodeId() != nodeID {
				errCh <- status.Errorf(codes.InvalidArgument,
					"heartbeat node id changed %q -> %q", nodeID, stat.GetNodeId())
				return
			}
			if err := s.handleStat(stream.Context(), stat); err != nil {
				log.Printf(`{"level":"warn","module":"master.rpc","msg":"heartbeat stat","node":%q,"err":%q}`,
					nodeID, err.Error())
			}
		}
	}()

	for {
		select {
		case <-stream.Context().Done():
			return nil
		case err := <-errCh:
			if err != nil && err != io.EOF {
				return err
			}
			return nil
		case cmd := <-cmds:
			if err := stream.Send(cmd); err != nil {
				return status.Errorf(codes.Internal, "send cmd: %v", err)
			}
		}
	}
}

func (s *Service) handleStat(ctx context.Context, stat *lucidnetv1.NodeStat) error {
	nodeID := stat.GetNodeId()
	var ts time.Time
	if stat.GetTsMs() > 0 {
		ts = time.UnixMilli(stat.GetTsMs())
	}
	if err := s.d.Registry.Heartbeat(ctx, nodeID, ts, ""); err != nil {
		return fmt.Errorf("record hb: %w", err)
	}
	metrics, err := registry.ParseMetricsJSON([]byte(stat.GetMetricsJson()))
	if err != nil {
		return fmt.Errorf("parse metrics: %w", err)
	}
	if err := s.d.Registry.ObserveExporters(ctx, nodeID, metrics.Exporters); err != nil {
		return fmt.Errorf("observe exporters: %w", err)
	}
	if len(metrics.NICs) > 0 { // 网卡变化上报：更新档案并触发权重重算（可选路径）
		if err := s.d.Registry.UpdateNICs(ctx, nodeID, metrics.NICs); err != nil {
			return fmt.Errorf("update nics: %w", err)
		}
	}
	if ack := metrics.Ack; ack != nil {
		if err := s.d.Config.Ack(ctx, nodeID, ack.Scope, ack.Version, ack.OK, ack.ErrMsg); err != nil {
			return fmt.Errorf("record ack: %w", err)
		}
	}
	return nil
}

// PublishConfig 内部发布入口（Console 触发的变更；docs/dd/07 §1）。
func (s *Service) PublishConfig(ctx context.Context, pub *lucidnetv1.ConfigPublish) (*lucidnetv1.ConfigVersion, error) {
	if !s.d.Leader() {
		return nil, status.Errorf(codes.Unavailable, "not leader: cluster config is read-only")
	}
	version, err := s.d.Config.Publish(ctx, pub.GetScope(), pub.GetData(), "grpc:internal")
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "publish config %s: %v", pub.GetScope(), err)
	}
	return &lucidnetv1.ConfigVersion{Version: version}, nil
}

// WatchAssign 分配表订阅流：当前表 + 增量推送（docs/dd/07 §1）。
func (s *Service) WatchAssign(_ *lucidnetv1.WatchAssignRequest, stream lucidnetv1.Master_WatchAssignServer) error {
	ch, cancel := s.d.Assigner.Subscribe()
	defer cancel()
	ctx := stream.Context()
	for {
		select {
		case <-ctx.Done():
			return nil
		case t := <-ch:
			out := &lucidnetv1.AssignTable{Version: t.Version}
			for _, e := range t.Entries {
				out.Entries = append(out.Entries, &lucidnetv1.AssignEntry{
					Exporter:  e.Exporter,
					Collector: e.Collector,
				})
			}
			if err := stream.Send(out); err != nil {
				return status.Errorf(codes.Internal, "send assign table: %v", err)
			}
		}
	}
}
