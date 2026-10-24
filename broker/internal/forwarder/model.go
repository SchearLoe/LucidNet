// Package forwarder —— R1 转发规则引擎（dd/01 §3/§4）：
// 按源 IP（exporter）/分组匹配 → 多目的转发；透传复制 + 代理重编码（含再采样）+ Kafka 生产。
package forwarder

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
)

// Protocol —— 目的地协议（dd/01 §3.1/§4.2；kafka 为 Broker 扩展目的地，
// 产出 flows.raw 等 topic，key 规则严格按 docs/09 §2/00 §3）。
type Protocol string

const (
	ProtocolPassthrough Protocol = "passthrough"
	ProtocolNetFlow5    Protocol = "netflow5"
	ProtocolIPFIX       Protocol = "ipfix"
	ProtocolKafka       Protocol = "kafka"
)

// Valid 校验协议取值。
func (p Protocol) Valid() bool {
	switch p {
	case ProtocolPassthrough, ProtocolNetFlow5, ProtocolIPFIX, ProtocolKafka:
		return true
	}
	return false
}

// Proxy 报告是否为记录级（代理重编码/Kafka）目的地。
func (p Protocol) Proxy() bool {
	return p == ProtocolNetFlow5 || p == ProtocolIPFIX || p == ProtocolKafka
}

// ResampleMode —— 再采样算法（dd/01 §4.1）。
type ResampleMode string

const (
	ResampleDeterministic ResampleMode = "deterministic"
	ResampleRandom        ResampleMode = "random"
)

// Valid 校验算法取值。
func (m ResampleMode) Valid() bool {
	return m == ResampleDeterministic || m == ResampleRandom
}

// RulesSnapshot —— /lucid/forward/rules etcd 快照（docs/09 §5；结构 = JSON + 单调 version）。
type RulesSnapshot struct {
	Version        uint64              `json:"version"`
	Rules          []Rule              `json:"rules"`
	ExporterGroups map[string][]string `json:"exporter_groups"` // 组=exporter 集合（dd/01 §3.3）
}

// Rule —— 转发规则（dd/01 §3.1）。
type Rule struct {
	ID           int32         `json:"id"`
	Name         string        `json:"name"`
	Priority     int32         `json:"priority"` // 升序匹配，命中即复制（一条报文可喂多规则）
	Enabled      bool          `json:"enabled"`
	Match        Match         `json:"match"`
	Destinations []Destination `json:"destinations"`
	FlowFilter   *FlowFilter   `json:"flow_filter,omitempty"` // 代理模式可选内容过滤（dd/01 §3.2 #4）
}

// Match —— 匹配条件（AND：exporters 与 exporter_groups 取并集后精确匹配源 IP）。
type Match struct {
	Exporters      []string `json:"exporters"`
	ExporterGroups []string `json:"exporter_groups"`
}

// Destination —— 目的地。
type Destination struct {
	Addr     string    `json:"addr"` // host:port（kafka 目的地为空）
	Protocol Protocol  `json:"protocol"`
	Resample *Resample `json:"resample,omitempty"`
	Topic    string    `json:"topic,omitempty"` // kafka 目的地 topic（缺省 flows.raw）
}

// Resample —— 每目的地独立再采样（dd/01 §3.1/§4.1）。
type Resample struct {
	Mode ResampleMode `json:"mode"`
	Rate uint32       `json:"rate"` // 1/N 保留；1=不采样
}

// FlowFilter —— 代理模式内容过滤条件（dd/01 §3.2 #4：proto/src_prefix/dst_prefix/ports）。
type FlowFilter struct {
	Proto     uint32   `json:"proto,omitempty"`
	SrcPrefix string   `json:"src_prefix,omitempty"` // CIDR
	DstPrefix string   `json:"dst_prefix,omitempty"` // CIDR
	Ports     []uint32 `json:"ports,omitempty"`      // src 或 dst 端口命中即通过
}

// MaxExportersPerRule —— 单规则展开后 exporter 上限（dd/01 §3.2 #2：10,000）。
const MaxExportersPerRule = 10000

// 校验错误哨兵（配置校验阶段直接拒绝，dd/01 §3.2 #3）。
var (
	ErrPassthroughResample = errors.New("passthrough destination does not support resample (dd/01 §3.2)")
	ErrNoDestinations      = errors.New("rule has no destinations")
	ErrUnknownProtocol     = errors.New("unknown destination protocol")
	ErrUnknownResampleMode = errors.New("unknown resample mode")
	ErrBadResampleRate     = errors.New("resample rate must be >= 1")
	ErrBadDestination      = errors.New("destination addr must be host:port")
	ErrTooManyExporters    = errors.New("rule exporter count exceeds limit after group expansion")
	ErrBadFilterPrefix     = errors.New("flow_filter prefix must be valid CIDR")
	ErrRuleDisabled        = errors.New("rule disabled")
)

// Validate —— 快照级校验：非法规则整条拒绝（返回带规则 id 的错误），快照内允许部分合法规则生效。
func (s *RulesSnapshot) Validate() (valid []Rule, errs []error) {
	for i := range s.Rules {
		r := &s.Rules[i]
		if err := r.Validate(s.ExporterGroups); err != nil {
			if errors.Is(err, ErrRuleDisabled) {
				continue // 关闭规则静默跳过
			}
			errs = append(errs, fmt.Errorf("rule %d (%s): %w", r.ID, r.Name, err))
			continue
		}
		valid = append(valid, *r)
	}
	return valid, errs
}

// Validate —— 单规则校验（dd/01 §3.2；passthrough×resample 拒绝）。
func (r *Rule) Validate(groups map[string][]string) error {
	if !r.Enabled {
		return ErrRuleDisabled
	}
	if len(r.Destinations) == 0 {
		return ErrNoDestinations
	}
	for i := range r.Destinations {
		d := &r.Destinations[i]
		if !d.Protocol.Valid() {
			return fmt.Errorf("destination %d: %q: %w", i, d.Protocol, ErrUnknownProtocol)
		}
		if d.Protocol == ProtocolKafka {
			continue // kafka 目的地无 UDP 地址
		}
		if _, _, err := net.SplitHostPort(strings.TrimSpace(d.Addr)); err != nil {
			return fmt.Errorf("destination %d (%s): %w: %v", i, d.Protocol, ErrBadDestination, err)
		}
		if d.Resample != nil {
			if d.Protocol == ProtocolPassthrough {
				return fmt.Errorf("destination %d: %w", i, ErrPassthroughResample)
			}
			if !d.Resample.Mode.Valid() {
				return fmt.Errorf("destination %d: %q: %w", i, d.Resample.Mode, ErrUnknownResampleMode)
			}
			if d.Resample.Rate < 1 {
				return fmt.Errorf("destination %d: %w", i, ErrBadResampleRate)
			}
		}
	}
	if r.FlowFilter != nil {
		for _, p := range []string{r.FlowFilter.SrcPrefix, r.FlowFilter.DstPrefix} {
			if p == "" {
				continue
			}
			if _, err := netip.ParsePrefix(p); err != nil {
				return fmt.Errorf("%w: %q: %v", ErrBadFilterPrefix, p, err)
			}
		}
	}
	if n := r.expandedExporterCount(groups); n > MaxExportersPerRule {
		return fmt.Errorf("%d exporters after expansion: %w", n, ErrTooManyExporters)
	}
	return nil
}

// expandedExporterCount —— 展开 groups 后的 exporter 去重计数（dd/01 §3.2 #2）。
func (r *Rule) expandedExporterCount(groups map[string][]string) int {
	seen := make(map[string]struct{}, len(r.Match.Exporters))
	for _, e := range r.Match.Exporters {
		if e = strings.TrimSpace(e); e != "" {
			seen[e] = struct{}{}
		}
	}
	for _, g := range r.Match.ExporterGroups {
		for _, e := range groups[g] {
			if e = strings.TrimSpace(e); e != "" {
				seen[e] = struct{}{}
			}
		}
	}
	return len(seen)
}
