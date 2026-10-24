package master

import (
	"os"
	"strings"
	"time"
)

// Options —— lucid-master 装配项（环境变量 LUCID_MASTER_*，docs/11 §8）。
type Options struct {
	// GrpcAddr —— Master gRPC 监听（docs/09 §4：9140）
	GrpcAddr string
	// HTTPAddr —— REST 管理面监听（dd/08 §3.1 bootstrap 引用 9141）
	HTTPAddr string
	// EtcdEndpoints —— 空 = 开发模式（无 etcd：内存发布、永远 leader）
	EtcdEndpoints []string
	// PGDSN —— PostgreSQL 连接串；空 = 内存台账（开发模式）
	PGDSN string
	// KafkaBrokers —— cluster.heartbeat 副本通道；空 = 不启用（gRPC 心跳为主，dd/07 §1）
	KafkaBrokers []string
	// JWTSecret —— HS256 共享密钥（Master 与网关，docs/dd/07 §4）
	JWTSecret string
	// JWTRS256KeyPEM —— RS256 私钥 PEM 内容（LUCID_MASTER_JWT_RS256_PRIVATE_KEY；
	// 与 JWTRS256KeyFile 二选一。配置后 access/refresh 改用 RS256 签发，
	// 公钥经 GET /api/v1/auth/jwks 暴露供 LucidBGP 验签，docs/dd/07 §4）
	JWTRS256KeyPEM string
	// JWTRS256KeyFile —— RS256 私钥 PEM 文件路径（LUCID_MASTER_JWT_RS256_KEY_FILE）
	JWTRS256KeyFile string
	// AdminUser / AdminPassword —— 首次引导的平台管理员（docs/dd/07 §4 预置角色）
	AdminUser     string
	AdminPassword string
	// LeaderTTL —— etcd 选主会话 TTL（docs/dd/07 §7：备 15s 接管）
	LeaderTTL time.Duration
	// AssignDebounce —— 分配表变更防抖（docs/dd/07 §3：30s）
	AssignDebounce time.Duration
	// ExporterWindow —— exporter 活跃观测窗口
	ExporterWindow time.Duration
	// OverloadFPS —— 超载 exporter 阈值（docs/dd/07 §3：5w fps）
	OverloadFPS float64
	// NodeTTL —— etcd 节点 lease 存活期（≥3×心跳 10s）
	NodeTTL time.Duration
}

// Default 默认值（端口基线 docs/09 §4 / docs/dd/08 §2.3）。
func Default() Options {
	return Options{
		GrpcAddr:       ":9140",
		HTTPAddr:       ":9141",
		LeaderTTL:      15 * time.Second,
		AssignDebounce: 30 * time.Second,
		ExporterWindow: 5 * time.Minute,
		OverloadFPS:    50000,
		NodeTTL:        30 * time.Second,
		AdminUser:      "admin",
		AdminPassword:  "", // 空 = 未设置（首次引导必须显式提供）
	}
}

// FromEnv 从环境变量装配（docs/11 §8 命名规范）。
func FromEnv() Options {
	o := Default()
	if v := os.Getenv("LUCID_MASTER_GRPC_ADDR"); v != "" {
		o.GrpcAddr = v
	}
	if v := os.Getenv("LUCID_MASTER_HTTP_ADDR"); v != "" {
		o.HTTPAddr = v
	}
	if v := os.Getenv("LUCID_MASTER_ETCD_ENDPOINTS"); v != "" {
		o.EtcdEndpoints = strings.Split(v, ",")
	}
	if v := os.Getenv("LUCID_MASTER_PG_DSN"); v != "" {
		o.PGDSN = v
	}
	if v := os.Getenv("LUCID_MASTER_KAFKA_BROKERS"); v != "" {
		o.KafkaBrokers = strings.Split(v, ",")
	}
	if v := os.Getenv("LUCID_MASTER_JWT_SECRET"); v != "" {
		o.JWTSecret = v
	}
	if v := os.Getenv("LUCID_MASTER_JWT_RS256_PRIVATE_KEY"); v != "" {
		o.JWTRS256KeyPEM = v
	}
	if v := os.Getenv("LUCID_MASTER_JWT_RS256_KEY_FILE"); v != "" {
		o.JWTRS256KeyFile = v
	}
	if v := os.Getenv("LUCID_MASTER_ADMIN_USER"); v != "" {
		o.AdminUser = v
	}
	if v := os.Getenv("LUCID_MASTER_ADMIN_PASSWORD"); v != "" {
		o.AdminPassword = v
	}
	return o
}
