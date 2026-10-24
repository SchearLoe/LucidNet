package master

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	clientv3 "go.etcd.io/etcd/client/v3"
	"google.golang.org/grpc"

	"github.com/SchearLoe/lucidnet/master/internal/assign"
	"github.com/SchearLoe/lucidnet/master/internal/audit"
	"github.com/SchearLoe/lucidnet/master/internal/auth"
	"github.com/SchearLoe/lucidnet/master/internal/config"
	"github.com/SchearLoe/lucidnet/master/internal/coord"
	lucidnetv1 "github.com/SchearLoe/lucidnet/master/internal/masterpb"
	"github.com/SchearLoe/lucidnet/master/internal/rbac"
	"github.com/SchearLoe/lucidnet/master/internal/registry"
	"github.com/SchearLoe/lucidnet/master/internal/restapi"
	"github.com/SchearLoe/lucidnet/master/internal/rpc"
	"github.com/SchearLoe/lucidnet/shared"
)

// Server —— lucid-master 装配与运行（docs/dd/07：节点管理/配置分发/负载分配/RBAC）。
type Server struct {
	opts Options

	reg     *registry.Registry
	cfg     *config.Store
	asg     *assign.Assigner
	aud     audit.Store
	users   rbac.Store
	hub     *rpc.Hub
	leader  *coord.LeaderGate
	hbc     *coord.HBConsumer
	grpcSrv *grpc.Server
	httpSrv *http.Server
	jwt     *auth.Signer
	etcdCLI *clientv3.Client
	pool    *pgxpool.Pool
}

// New 装配（不启动；Run 启动）。
func New(opts Options) (*Server, error) {
	if opts.GrpcAddr == "" {
		opts.GrpcAddr = shared.AddrMasterGRPC // ":9140"（docs/09 §4 端口契约）
	}
	s := &Server{opts: opts}
	if err := s.buildStores(); err != nil {
		return nil, err
	}
	if err := s.buildCore(); err != nil {
		return nil, err
	}
	return s, nil
}

// buildStores —— PG/内存台账装配（nodes/exporters/versions/audit/rbac）。
func (s *Server) buildStores() error {
	if s.opts.PGDSN == "" {
		log.Printf(`{"level":"warn","module":"master","msg":"LUCID_MASTER_PG_DSN empty: in-memory stores (dev mode)"}`)
		s.aud = audit.NewMemStore(0)
		s.users = rbac.NewMemStore()
		return nil
	}
	cfg, err := pgxpool.ParseConfig(s.opts.PGDSN)
	if err != nil {
		return fmt.Errorf("parse pg dsn: %w", err)
	}
	// 引导迁移需要多语句执行：simple protocol
	cfg.ConnConfig.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		return fmt.Errorf("connect pg: %w", err)
	}
	s.pool = pool
	if err := s.migrate(); err != nil {
		return fmt.Errorf("apply migrations: %w", err)
	}
	s.aud = audit.NewPGStore(pool)
	s.users = rbac.NewPGStore(pool)
	return nil
}

// migrate 应用内嵌迁移（幂等；仓库级 migrations/ 收敛后外迁，见模块 README）。
func (s *Server) migrate() error {
	entries, err := fsGlob()
	if err != nil {
		return err
	}
	for _, name := range entries {
		sql, err := migrationFS.ReadFile(name)
		if err != nil {
			return fmt.Errorf("read %s: %w", name, err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		_, err = s.pool.Exec(ctx, string(sql))
		cancel()
		if err != nil {
			return fmt.Errorf("exec %s: %w", name, err)
		}
		log.Printf(`{"level":"info","module":"master","msg":"migration applied","file":%q}`, name)
	}
	return nil
}

// buildCore —— 命令中枢/注册/分配/选主/配置/gRPC/REST/Kafka 副本通道装配。
func (s *Server) buildCore() error {
	s.hub = rpc.NewHub()
	now := time.Now

	// —— etcd（可选；配置/分配表发布 + 节点 lease 镜像 + 选主，docs/09 §5 / hld/07 §3）——
	var cfgPub config.Publisher = config.NopPublisher{}
	var asgPub assign.Publisher = assign.NopPublisher{}
	var mirror registry.NodeMirror = registry.NopMirror{}
	var initialAssignVersion uint64
	if len(s.opts.EtcdEndpoints) > 0 {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		cli, err := coord.EtcdClient(ctx, s.opts.EtcdEndpoints)
		cancel()
		if err != nil {
			// Master 是配置权威，etcd 不可用时拒绝降级启动（避免双权威）
			return fmt.Errorf("connect etcd %v: %w", s.opts.EtcdEndpoints, err)
		}
		s.etcdCLI = cli
		cfgPub = coord.NewConfigPublisher(cli)
		asgPub = coord.NewAssignPublisher(cli)
		mirror = coord.NewNodeMirror(cli, s.opts.NodeTTL)
		if v, err := coord.LatestAssignVersion(context.Background(), cli); err == nil {
			initialAssignVersion = v
		}
	} else {
		log.Printf(`{"level":"warn","module":"master","msg":"LUCID_MASTER_ETCD_ENDPOINTS empty: etcd publishing disabled (dev mode)"}`)
	}

	// —— 分配器（输入函数在 registry 建好后挂接）——
	s.asg = assign.New(assign.Options{
		Debounce:    s.opts.AssignDebounce,
		OverloadFPS: s.opts.OverloadFPS,
		Now:         now,
	})
	s.asg.Publisher = asgPub
	s.asg.InitialVersion = initialAssignVersion

	// —— 节点注册/心跳/故障判定 ——
	s.reg = registry.NewRegistry(registryStore(s), registry.Options{
		Mirror: mirror,
		Now:    now,
		OnEvent: func(ev registry.NodeEvent) {
			_, _ = s.aud.Append(context.Background(), audit.Entry{
				Ts: ev.At, User: "system", Action: "node." + string(ev.Type),
				Resource: "node:" + ev.Node.ID, Category: "system",
				DetailMsg: fmt.Sprintf("role=%s state=%s degraded=%t",
					ev.Node.Role, ev.Node.State, ev.Node.Degraded),
			})
		},
		OnChange: s.asg.Trigger, // 节点上下线/权重变化 → 分配表重算（防抖合并）
	})
	s.asg.Collectors = func(ctx context.Context) ([]assign.Collector, error) {
		nodes, err := s.reg.AssignCandidates(ctx)
		if err != nil {
			return nil, err
		}
		out := make([]assign.Collector, 0, len(nodes))
		for _, n := range nodes {
			out = append(out, assign.Collector{ID: n.ID, Weight: n.Weight()})
		}
		return out, nil
	}
	s.asg.Exporters = func(ctx context.Context) ([]assign.Exporter, error) {
		list, err := s.reg.ActiveExporters(ctx, s.opts.ExporterWindow)
		if err != nil {
			return nil, err
		}
		out := make([]assign.Exporter, 0, len(list))
		for _, e := range list {
			out = append(out, assign.Exporter{IP: e.IP, RateFPS: e.RateFPS, PinnedTo: e.PinnedTo})
		}
		return out, nil
	}

	// —— 选主（etcd /lucid/leader；开发模式恒 leader）——
	alwaysLeader := s.etcdCLI == nil
	if s.etcdCLI != nil {
		s.leader = coord.NewLeaderGate(s.etcdCLI, hostnameOrLocal(), int(s.opts.LeaderTTL.Seconds()))
	}
	isLeader := func() bool {
		if s.leader == nil {
			return alwaysLeader
		}
		return s.leader.IsLeader()
	}

	// —— 配置管理（校验 → PG 权威 → etcd → ACK，docs/dd/07 §5）——
	s.cfg = config.NewStore(configVersionsStore(s), config.Options{
		Publisher: cfgPub,
		Targets:   &scopeTargets{reg: s.reg, leader: isLeader},
		CmdSink:   &reloadSink{hub: s.hub},
		Now:       now,
	})

	// —— JWT（HS256，docs/dd/07 §4）——
	secret := s.opts.JWTSecret
	if secret == "" {
		secret = "lucidnet-dev-jwt-secret"
		log.Printf(`{"level":"warn","module":"master","msg":"LUCID_MASTER_JWT_SECRET empty: using insecure dev secret"}`)
	}
	s.jwt = auth.NewSigner(secret, now)

	// —— gRPC（docs/09 §4：9140）——
	svc := rpc.NewService(rpc.Deps{
		Registry: s.reg, Config: s.cfg, Assigner: s.asg,
		Hub: s.hub, Leader: isLeader, Now: now,
	})
	s.grpcSrv = grpc.NewServer()
	lucidnetv1.RegisterMasterServer(s.grpcSrv, svc)

	// —— REST（docs/09 §6；端口基线 9141，dd/08 §3.1）——
	rest := restapi.NewServer(restapi.Deps{
		Signer: s.jwt, Users: s.users, Audit: s.aud,
		Config: s.cfg, Registry: s.reg, Assigner: s.asg,
		Hub: &hubAdapter{hub: s.hub}, Leader: isLeader, Now: now,
	})
	s.httpSrv = &http.Server{
		Addr:              s.opts.HTTPAddr,
		Handler:           rest.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}

	// —— Kafka cluster.heartbeat 副本通道（可选，docs/00 §3）——
	s.hbc = coord.NewHBConsumer(s.opts.KafkaBrokers, s.reg,
		func(ctx context.Context, nodeID string, ack registry.CmdAck) {
			_ = s.cfg.Ack(ctx, nodeID, ack.Scope, ack.Version, ack.OK, ack.ErrMsg)
		})
	return nil
}

// registryStore / configVersionsStore —— 按存储模式选择实现。
func registryStore(s *Server) registry.Store {
	if s.pool != nil {
		return registry.NewPGStore(s.pool)
	}
	return registry.NewMemStore()
}

func configVersionsStore(s *Server) config.VersionsStore {
	if s.pool != nil {
		return config.NewPGVersions(s.pool)
	}
	return config.NewMemVersions()
}

// scopeTargets —— config.TargetResolver：作用域 → 在线目标节点（ACK 统计口径）。
type scopeTargets struct {
	reg    *registry.Registry
	leader func() bool
}

// ResolveTargets 实现 config.TargetResolver（非 leader 拒绝 → 集群只读保护，dd/07 §7）。
func (t *scopeTargets) ResolveTargets(ctx context.Context, scope string) ([]string, error) {
	if t.leader != nil && !t.leader() {
		return nil, config.ErrReadOnly
	}
	roles := config.ScopeTargets(scope)
	if len(roles) == 0 {
		return nil, nil
	}
	nodes, err := t.reg.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("list nodes for targets: %w", err)
	}
	roleSet := map[string]bool{}
	for _, r := range roles {
		roleSet[r] = true
	}
	var out []string
	for _, n := range nodes {
		if roleSet[string(n.Role)] && n.State == registry.StateOnline {
			out = append(out, n.ID)
		}
	}
	return out, nil
}

// reloadSink —— config.CmdSink：reload 命令入 Heartbeat 下行队列（数据本体走 etcd
// watch，命令仅触发"请应用新版本"与 ACK 载体，docs/09 §9-⑤）。
type reloadSink struct{ hub *rpc.Hub }

// SendReload 实现 config.CmdSink。
func (r *reloadSink) SendReload(_ context.Context, nodeID, cmdID, scope string, version uint64) error {
	payload, err := json.Marshal(map[string]any{"cmd_id": cmdID, "scope": scope, "version": version})
	if err != nil {
		return fmt.Errorf("marshal reload payload: %w", err)
	}
	return r.hub.Push(nodeID, rpc.Cmd{
		ID: cmdID, Type: rpc.CmdTypeReload, PayloadJSON: string(payload), CreatedAt: time.Now(),
	})
}

// hubAdapter —— restapi.CmdHub 适配（避免 restapi 依赖 rpc 包）。
type hubAdapter struct{ hub *rpc.Hub }

// Push 实现 restapi.CmdHub。
func (h *hubAdapter) Push(nodeID string, c restapi.Cmd) error {
	return h.hub.Push(nodeID, rpc.Cmd{
		ID: c.ID, Type: c.Type, PayloadJSON: c.PayloadJSON, CreatedAt: c.CreatedAt,
	})
}

// seedBootstrap 预置角色与平台管理员（docs/dd/07 §4）。
func (s *Server) seedBootstrap(ctx context.Context) error {
	pass := s.opts.AdminPassword
	if pass == "" {
		pass = "lucid-admin"
		log.Printf(`{"level":"warn","module":"master","msg":"LUCID_MASTER_ADMIN_PASSWORD empty: default admin password seeded (CHANGE IT)"}`)
	}
	hash, err := rbac.HashPassword(pass)
	if err != nil {
		return fmt.Errorf("hash admin password: %w", err)
	}
	return s.users.SeedDefaults(ctx, s.opts.AdminUser, hash)
}

// Run 启动全部子系统并阻塞直至 ctx 取消。
func (s *Server) Run(ctx context.Context) error {
	if err := s.seedBootstrap(ctx); err != nil {
		return fmt.Errorf("seed bootstrap: %w", err)
	}
	// 后台循环：故障扫描 / 配置补偿 / 分配防抖 / 选主 / Kafka 副本心跳
	go s.reg.ScanLoop(ctx)
	go s.cfg.Run(ctx)
	go s.asg.Run(ctx)
	if s.leader != nil {
		go s.leader.Run(ctx)
	}
	if s.hbc != nil {
		go s.hbc.Run(ctx)
	}
	// 启动即算一版分配表（无 collector/exporter 时为空表）
	if err := s.asg.ComputeOnce(ctx); err != nil {
		log.Printf(`{"level":"warn","module":"master","msg":"initial assign compute","err":%q}`, err.Error())
	}

	// gRPC 监听
	grpcLn, err := net.Listen("tcp", s.opts.GrpcAddr)
	if err != nil {
		return fmt.Errorf("listen grpc %s: %w", s.opts.GrpcAddr, err)
	}
	errCh := make(chan error, 2)
	go func() {
		if err := s.grpcSrv.Serve(grpcLn); err != nil {
			errCh <- err
		}
	}()
	log.Printf(`{"level":"info","module":"master","msg":"grpc serving","addr":%q}`, s.opts.GrpcAddr)

	// REST 监听
	go func() {
		if err := s.httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()
	log.Printf(`{"level":"info","module":"master","msg":"http serving","addr":%q}`, s.opts.HTTPAddr)

	select {
	case <-ctx.Done():
		s.shutdown()
		return nil
	case err := <-errCh:
		s.shutdown()
		return err
	}
}

// shutdown 优雅停机。
func (s *Server) shutdown() {
	if s.grpcSrv != nil {
		s.grpcSrv.GracefulStop()
	}
	if s.httpSrv != nil {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = s.httpSrv.Shutdown(shutdownCtx)
		cancel()
	}
	if s.hbc != nil {
		_ = s.hbc.Close()
	}
	if s.cfg != nil {
		_ = s.cfg.Close()
	}
	if s.reg != nil {
		_ = s.reg.Close()
	}
	if s.pool != nil {
		s.pool.Close()
	}
	if s.etcdCLI != nil {
		_ = s.etcdCLI.Close()
	}
}

func hostnameOrLocal() string {
	if h, err := os.Hostname(); err == nil && h != "" {
		return h
	}
	return "lucid-master"
}
