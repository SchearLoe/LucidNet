package forwarder

import (
	"net/netip"

	"github.com/SchearLoe/lucidnet/shared"
)

// Filter —— 编译后的代理模式内容过滤（dd/01 §3.2 #4：proto/src_prefix/dst_prefix/ports）。
// 不匹配记录被丢弃后再编码——覆盖"按流记录内部源 IP 分流"扩展场景。
type Filter struct {
	proto     uint32
	srcPrefix netip.Prefix
	dstPrefix netip.Prefix
	hasSrc    bool
	hasDst    bool
	ports     map[uint32]struct{}
}

// CompileFilter —— 编译配置过滤条件（前缀已在 Validate 校验，此处容错跳过非法值）。
func CompileFilter(f *FlowFilter) *Filter {
	if f == nil {
		return nil
	}
	out := &Filter{proto: f.Proto}
	if p, err := netip.ParsePrefix(f.SrcPrefix); err == nil {
		out.srcPrefix = p.Masked()
		out.hasSrc = true
	}
	if p, err := netip.ParsePrefix(f.DstPrefix); err == nil {
		out.dstPrefix = p.Masked()
		out.hasDst = true
	}
	if len(f.Ports) > 0 {
		out.ports = make(map[uint32]struct{}, len(f.Ports))
		for _, p := range f.Ports {
			out.ports[p] = struct{}{}
		}
	}
	return out
}

// Match —— 全部已配置条件 AND 命中才保留。
func (f *Filter) Match(rec *shared.FlowRecord) bool {
	if f == nil {
		return true
	}
	if f.proto != 0 && rec.Proto != f.proto {
		return false
	}
	if f.hasSrc && !prefixContains(f.srcPrefix, rec.SrcIP, rec.IPVersion) {
		return false
	}
	if f.hasDst && !prefixContains(f.dstPrefix, rec.DstIP, rec.IPVersion) {
		return false
	}
	if len(f.ports) > 0 {
		if _, ok := f.ports[rec.SrcPort]; ok {
			return true
		}
		if _, ok := f.ports[rec.DstPort]; ok {
			return true
		}
		return false
	}
	return true
}

// prefixContains —— 16B 地址（v4 ::ffff: 映射）落入前缀判断（docs/00 §1 统一地址表示）。
func prefixContains(p netip.Prefix, ip [16]byte, ipVersion uint32) bool {
	addr, ok := netip.AddrFromSlice(ip[:])
	if !ok {
		return false
	}
	if ipVersion == 4 && addr.Is4In6() {
		addr = netip.AddrFrom4(addr.As4()) // 展开为纯 v4 再比对
	}
	return p.Contains(addr.Unmap())
}
