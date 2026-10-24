package decoder

import (
	"errors"
	"fmt"
	"net/netip"
	"time"
)

// ErrDecoderNotImplemented —— v9/IPFIX/sFlow 解码走 GoFlow2 fork（dd/02 §1），骨架阶段未接通。
var ErrDecoderNotImplemented = errors.New("v9/ipfix/sflow decoder not implemented (goflow2 fork pending, dd/02 §1)")

// GoFlow2 fork 定制点落点索引（dd/02 §1 表格逐项对应）：
//
//	#1 模板缓存持久化 → template.go（TemplateCache/TemplateWAL 接口 + 内存实现）
//	                     + wal_kafka.go（Kafka flow.templates compact + 本地 WAL + 启动重放）
//	#2 华为私有 IE     → huawei.go（enterprise 2011 映射表；未识别 IE 计数
//	                     flow_unknown_ie{exporter} 并保留原始 TLV 透传 evidence）
//	#3 采样字段归一     → TODO(normalizeSample)（本文件）：v9 OPTIONSCOPE_SAMPLER + IE 305/306；
//	                     sFlow sampleProbability；统一折算 FlowRecord.SampleRate
//	#4 IPv6（R3）      → TODO(ipv6)（本文件）：v9/IPFIX IE 27/28 → FlowRecord 16B + ip_version=6；
//	                     sFlow v6 报文头解析
//	#5 观测域          → template.go TemplateKey{Exporter, ObsDomainID, TemplateID}（已实现），
//	                     模板/采样状态均按此隔离
//
// 模板丢失防护（dd/02 §1）：60s 内收到 data record 但无对应模板 → 缓冲最近 30s 报文
// （环形 1GB replayBuffer），模板到达后回放；持续缺失则丢弃 + 告警
// flow_template_missing{exporter}（严重级）。

// V9Decoder —— NetFlow v9 解码器（GoFlow2 fork 接入点）。
type V9Decoder struct {
	cache TemplateCache
	wal   TemplateWAL
	opts  options
}

// NewV9 —— 构造（cache/wal 为空时用内存实现）。
func NewV9(cache TemplateCache, wal TemplateWAL, opts ...Option) *V9Decoder {
	o := defaultOptions()
	for _, f := range opts {
		f(&o)
	}
	if cache == nil {
		cache = NewMemTemplateCache()
	}
	if wal == nil {
		wal = NewMemTemplateWAL()
	}
	return &V9Decoder{cache: cache, wal: wal, opts: o}
}

// Decode TODO(fork GoFlow2)：
//  1. 头部解析（version=9, count, sys_uptime, unix_secs —— boot 换算同 netflow_v5.go flowTimeMs）；
//  2. flowset 遍历：模板集(id=0)/选项模板集(id=1)/数据集；
//  3. 模板增删 → cache.Put/Delete + wal.Append（定制点 #1）；
//  4. 数据记录 → IE 展开 → FlowRecord（huawei.go 私有 IE（#2）、TODO(normalizeSample)（#3）、
//     TODO(ipv6)（#4））；缓存 key 按观测域隔离（#5）；
//  5. 60s 内无模板的 data → replayBuffer 缓冲，模板到达后回放。
func (d *V9Decoder) Decode(datagram []byte, exporter netip.Addr) (DecodeResult, error) {
	return DecodeResult{}, fmt.Errorf("decode netflow v9 from %s: %w", exporter, ErrDecoderNotImplemented)
}

// IPFIXDecoder —— IPFIX 解码器（version=10；模板活跃期重验证默认 24h，dd/02 §1 #1）。
type IPFIXDecoder struct {
	v9 V9Decoder
}

// NewIPFIX —— 构造（复用 v9 模板管理，ExpiresAt 按活跃期配置）。
func NewIPFIX(cache TemplateCache, wal TemplateWAL, opts ...Option) *IPFIXDecoder {
	return &IPFIXDecoder{v9: *NewV9(cache, wal, opts...)}
}

// Decode TODO(fork GoFlow2)：IE 布局与 v9 差异（企业号私有 IE、infrastructureEngineType 等）。
func (d *IPFIXDecoder) Decode(datagram []byte, exporter netip.Addr) (DecodeResult, error) {
	return DecodeResult{}, fmt.Errorf("decode ipfix from %s: %w", exporter, ErrDecoderNotImplemented)
}

// SFlowDecoder —— sFlow v5 解码器（监听端口 6343；版本字段与 NetFlow v5 冲突，按端口分流，hld/02 §4）。
type SFlowDecoder struct {
	opts options
}

// NewSFlow —— 构造。
func NewSFlow(opts ...Option) *SFlowDecoder {
	o := defaultOptions()
	for _, f := range opts {
		f(&o)
	}
	return &SFlowDecoder{opts: o}
}

// Decode TODO(fork GoFlow2)：sFlow v5 报文头 + flow sample 展开；sampleProbability → 采样归一（#3）。
func (d *SFlowDecoder) Decode(datagram []byte, exporter netip.Addr) (DecodeResult, error) {
	return DecodeResult{}, fmt.Errorf("decode sflow from %s: %w", exporter, ErrDecoderNotImplemented)
}

// replayBuffer —— 模板丢失防护环形缓冲（最近 30s 报文，容量上限默认 1GB；dd/02 §1）。
type replayBuffer struct {
	maxBytes int64
}

// ErrReplayNotImplemented —— 环形缓冲回放未实现（fork 时接通）。
var ErrReplayNotImplemented = errors.New("template-missing replay buffer not implemented (dd/02 §1)")

func newReplayBuffer(maxBytes int64) *replayBuffer { return &replayBuffer{maxBytes: maxBytes} }

// Push —— 无模板 data record 数据报入环形缓冲（超容量/超 30s 淘汰最旧）。
func (b *replayBuffer) Push(datagram []byte, exporter netip.Addr, ts time.Time) error {
	// TODO(fork)：环形链表 + 字节水位淘汰；计数 flow_template_missing{exporter}
	return ErrReplayNotImplemented
}

// Replay —— 模板到达后回放该观测域缓冲的数据报。
func (b *replayBuffer) Replay(exporter netip.Addr, obsDomainID uint32) ([][]byte, error) {
	return nil, ErrReplayNotImplemented
}
