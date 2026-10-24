// Package decoder —— 流解码：NetFlow v5 完整实现；v9/IPFIX/sFlow 为 GoFlow2 fork 接入桩（dd/02 §1）。
// 输出 shared.FlowRecord，字段语义唯一权威 = docs/09 §3。
package decoder

import (
	"net/netip"

	"github.com/SchearLoe/lucidnet/shared"
)

// 数据报首字段版本号（线上协议）。
const (
	VersionNetFlowV5 uint16 = 5
	VersionNetFlowV9 uint16 = 9
	VersionIPFIX     uint16 = 10
	// sFlow v5 数据报首 4B = 5（uint32），与 NetFlow v5 首 2B 数值冲突，
	// 按监听端口分流（NetFlow 2055/9995/9996，sFlow 6343，hld/02 §4）。
	VersionSFlow uint32 = 5
)

// DecodeResult —— 一次数据报解码产出。
type DecodeResult struct {
	Records        []shared.FlowRecord
	TemplateEvents []TemplateEvent // v5 恒空；v9/IPFIX 模板增删（dd/02 §1 #1，须持久化到 WAL）
}

// Decoder —— 单个 UDP 数据报 → FlowRecord 列表（+模板事件）。
type Decoder interface {
	// Decode 解析来自 exporter 的一个数据报；不可解析时返回错误（调用方计数并丢弃，
	// UDP 语义：无重传，dd/02 §4）。
	Decode(datagram []byte, exporter netip.Addr) (DecodeResult, error)
}

// options —— 解码器公共配置（Option 模式，docs/11 §3）。
type options struct {
	defaultSampleRate uint32
}

func defaultOptions() options { return options{defaultSampleRate: 1} }

// Option —— 解码器选项。
type Option func(*options)

// WithDefaultSampleRate —— v5 头部无采样信息时使用的缺省采样率倒数
// （per-exporter 采样登记表缺省值，dd/02 §1 定制点 #3；1=全采）。
func WithDefaultSampleRate(rate uint32) Option {
	return func(o *options) {
		if rate > 0 {
			o.defaultSampleRate = rate
		}
	}
}
