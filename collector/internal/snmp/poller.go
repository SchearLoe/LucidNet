// Package snmp —— SNMP 采集与接口角色识别（dd/02 §5；R4）。
//
// 边界（hld/02 §2）：poller 轮询（30/60/300s 周期）→ VM 指标 + PG 资产 +
// snmp.ifcounters 审计流；LLDP/OSPF 证据收集 → 角色识别引擎 → PG interfaces.role，
// 快照经 etcd 推送 Collector 富化（enrich.IfRoleSnapshot）与 Analytics 过滤。
package snmp

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// 轮询周期与并发预算（dd/02 §5.1）。
const (
	DefaultIfPollInterval     = 30 * time.Second  // 接口计数器（可按设备调 60s）
	DefaultHealthPollInterval = 60 * time.Second  // 设备健康 CPU/内存/温度
	DefaultDOMPollInterval    = 300 * time.Second // 光功率
	DefaultWorkers            = 40                // 2,000 设备预算：单轮 30s 内完成
	DefaultRoundTick          = time.Second       // 到期扫描粒度
)

// ifXTable/ifTable 计数器 OID（dd/02 §5.1 接口计数器集；TODO(gosnmp) walk 用）。
const (
	oidIfHCInOctets     = "1.3.6.1.2.1.31.1.1.1.6"
	oidIfHCOutOctets    = "1.3.6.1.2.1.31.1.1.1.10"
	oidIfHCInUcastPkts  = "1.3.6.1.2.1.31.1.1.1.7"
	oidIfHCOutUcastPkts = "1.3.6.1.2.1.31.1.1.1.11"
	oidIfInErrors       = "1.3.6.1.2.1.2.2.1.14"
	oidIfOutDiscards    = "1.3.6.1.2.1.2.2.1.19"
)

// ErrSNMPNotImplemented —— gosnmp 交互未接通（walking skeleton 桩）。
var ErrSNMPNotImplemented = errors.New("snmp poller not implemented (gosnmp pending, dd/02 §5.1)")

// DeviceTarget —— 轮询目标（PG devices/exporters 镜像子集）。
type DeviceTarget struct {
	DeviceID uint32
	Host     string // IP/主机名
	// TODO(gosnmp)：v2c community / v3 认证参数（User/AuthPassword/PrivPassword，dd/02 §5.1）。
	Community      string
	IfPollInterval time.Duration // 零值 = DefaultIfPollInterval
	HealthInterval time.Duration // 零值 = DefaultHealthPollInterval
	DOMInterval    time.Duration // 零值 = DefaultDOMPollInterval
}

// ifInterval —— 归一化周期。
func (d DeviceTarget) ifInterval() time.Duration {
	if d.IfPollInterval <= 0 {
		return DefaultIfPollInterval
	}
	return d.IfPollInterval
}

// IfCounters —— 单接口计数器快照（审计流 snmp.ifcounters 消息体，09 §2）。
type IfCounters struct {
	DeviceID     uint32
	IfIndex      uint32
	InOctets     uint64 // ifHCInOctets
	OutOctets    uint64 // ifHCOutOctets
	InUcastPkts  uint64
	OutUcastPkts uint64
	InErrors     uint32
	OutDiscards  uint32
	TS           time.Time
}

// Poller —— SNMP 轮询器（gosnmp 封装；单设备单轮语义，调度见 Scheduler）。
type Poller interface {
	// PollIfCounters —— walk ifXTable 计数器集（dd/02 §5.1，30s 周期）。
	PollIfCounters(ctx context.Context, d DeviceTarget) ([]IfCounters, error)
	// PollDeviceHealth —— CPU/内存/温度（60s 周期）；结果打 VM 指标（桩未实现）。
	PollDeviceHealth(ctx context.Context, d DeviceTarget) error
	// PollDOM —— 光功率（300s 周期）；结果打 VM 指标（桩未实现）。
	PollDOM(ctx context.Context, d DeviceTarget) error
}

// GoSNMPPoller —— gosnmp 轮询器桩。
//
// TODO(gosnmp)（dd/02 §5.1）：
//  1. gosnmp.New 按设备建会话（v2c Community / v3 USM 认证，连接复用池）；
//  2. PollIfCounters：BulkWalk oidIfHC* 批量取数（P50 8ms/walk 批预算）→ []IfCounters；
//  3. PollDeviceHealth：CPU/内存/温度厂商 OID 表（不同厂商差异，按 device 猜测）；
//  4. PollDOM：光模块 DOM OID；
//  5. 指标：lucid_collector_snmp_poll_lag{device}（轮询滞后，docs/11 §9 标签白名单 device）。
type GoSNMPPoller struct{}

// NewGoSNMPPoller —— 构造桩。
func NewGoSNMPPoller() *GoSNMPPoller { return &GoSNMPPoller{} }

// PollIfCounters —— TODO(gosnmp)；桩恒 ErrSNMPNotImplemented。
func (p *GoSNMPPoller) PollIfCounters(ctx context.Context, d DeviceTarget) ([]IfCounters, error) {
	return nil, fmt.Errorf("poll if counters for device %s: %w", d.Host, ErrSNMPNotImplemented)
}

// PollDeviceHealth —— TODO(gosnmp)；桩恒 ErrSNMPNotImplemented。
func (p *GoSNMPPoller) PollDeviceHealth(ctx context.Context, d DeviceTarget) error {
	return fmt.Errorf("poll health for device %s: %w", d.Host, ErrSNMPNotImplemented)
}

// PollDOM —— TODO(gosnmp)；桩恒 ErrSNMPNotImplemented。
func (p *GoSNMPPoller) PollDOM(ctx context.Context, d DeviceTarget) error {
	return fmt.Errorf("poll dom for device %s: %w", d.Host, ErrSNMPNotImplemented)
}

// CountersSink —— 计数器去向（dd/02 §5.1：VictoriaMetrics `lucid_if{device,ifindex}` +
// Kafka `snmp.ifcounters` 审计流，key=device，09 §2）。
type CountersSink interface {
	PublishIfCounters(ctx context.Context, c IfCounters) error
}

// SinkFunc —— 函数适配器（测试/开发）。
type SinkFunc func(ctx context.Context, c IfCounters) error

// PublishIfCounters —— SinkFunc 实现。
func (f SinkFunc) PublishIfCounters(ctx context.Context, c IfCounters) error { return f(ctx, c) }
