// Package config —— lucid-gateway 启动配置（docs/11 §8：环境变量 LUCID_<组件>_<键>）。
package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config —— 网关全部可配置项；零值不可直接使用，须经 Load（含默认值回填）。
type Config struct {
	// HTTP 监听地址（lucid-gateway 单点接入 /api/v1/*，docs/09 §6）。
	HTTPAddr string
	// JWT HS256 共享密钥（Master 与网关共享，docs/dd/07 §安全：claims={uid,tenant,roles,exp}）。
	JWTSecret string
	// AuthStrict 严格模式：claims 无 perms 时拒绝授权检查（false 仅限联调）。
	AuthStrict bool
	// Kafka brokers（消费组固定 gateway.ws，docs/09 §2 组名即接口）。
	KafkaBrokers []string
	// Kafka 会话超时等派生参数。
	KafkaDialTimeout time.Duration
	// Storage QueryService/ExportService 基址（R6 转发，docs/09 §6）。
	StorageURL string
	// LucidBGP 基址（R9 一键处置 /api/bgp/*，docs/dd/05 §5）。
	BGPURL string
	// Redis 地址（实时 rt:* TopN 轮询，M1 未接线仅校验格式，见 TODO）。
	RedisAddr string
	// 明细查询令牌桶：每用户 QPS（docs/dd/05 §6：10 QPS/用户）。
	FlowsQueryQPS float64
	FlowsQueryBurst int
	// 实时缓存容量（attacks 注册表 / alarms 环形缓冲条数）。
	RecentAttacksCap int
	RecentAlarmsCap  int
}

// Load 从环境变量读取配置并回填默认值。
func Load() (Config, error) {
	c := Config{
		HTTPAddr:         env("LUCID_CONSOLE_HTTP_ADDR", ":8080"),
		JWTSecret:        os.Getenv("LUCID_CONSOLE_JWT_SECRET"),
		AuthStrict:       envBool("LUCID_CONSOLE_AUTH_STRICT", true),
		KafkaBrokers:     envList("LUCID_CONSOLE_KAFKA_BROKERS", nil),
		KafkaDialTimeout: 5 * time.Second,
		StorageURL:       env("LUCID_CONSOLE_STORAGE_URL", "http://127.0.0.1:8082"),
		BGPURL:           env("LUCID_CONSOLE_BGP_URL", "http://127.0.0.1:8083"),
		RedisAddr:        os.Getenv("LUCID_CONSOLE_REDIS_ADDR"),
		FlowsQueryQPS:    10,
		FlowsQueryBurst:  20,
		RecentAttacksCap: 1000,
		RecentAlarmsCap:  10000,
	}
	if v := os.Getenv("LUCID_CONSOLE_FLOWS_QUERY_QPS"); v != "" {
		qps, err := strconv.ParseFloat(v, 64)
		if err != nil || qps <= 0 {
			return c, fmt.Errorf("parse LUCID_CONSOLE_FLOWS_QUERY_QPS %q: %w", v, err)
		}
		c.FlowsQueryQPS = qps
	}
	if c.JWTSecret == "" {
		return c, fmt.Errorf("config: LUCID_CONSOLE_JWT_SECRET required (HS256 shared with Master, docs/dd/07)")
	}
	return c, nil
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envList(key string, def []string) []string {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	var out []string
	for _, part := range strings.Split(v, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}

func envBool(key string, def bool) bool {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return def
	}
	return b
}
