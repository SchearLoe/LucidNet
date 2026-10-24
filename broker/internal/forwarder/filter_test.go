package forwarder

import (
	"testing"

	"github.com/SchearLoe/lucidnet/shared"
)

func ip4(a, b, c, d byte) [16]byte {
	var out [16]byte
	out[10], out[11] = 0xff, 0xff
	out[12], out[13], out[14], out[15] = a, b, c, d
	return out
}

func TestFilterPrefixV4Mapped(t *testing.T) {
	f := CompileFilter(&FlowFilter{SrcPrefix: "10.0.0.0/8"})
	if f == nil {
		t.Fatal("nil filter")
	}
	rec := shared.FlowRecord{SrcIP: ip4(10, 1, 2, 3), DstIP: ip4(8, 8, 8, 8), IPVersion: 4}
	if !f.Match(&rec) {
		t.Fatal("10.x must match 10/8")
	}
	other := shared.FlowRecord{SrcIP: ip4(11, 0, 0, 1), DstIP: ip4(8, 8, 8, 8), IPVersion: 4}
	if f.Match(&other) {
		t.Fatal("11.x must not match 10/8")
	}
}

func TestFilterProtoAndPorts(t *testing.T) {
	f := CompileFilter(&FlowFilter{Proto: 6, Ports: []uint32{80, 443}})
	rec := shared.FlowRecord{SrcIP: ip4(1, 1, 1, 1), DstIP: ip4(2, 2, 2, 2), Proto: 17, DstPort: 53, IPVersion: 4}
	if f.Match(&rec) {
		t.Fatal("proto 17 must not match proto=6 filter")
	}
	rec.Proto = 6
	if f.Match(&rec) {
		t.Fatal("tcp/53 must not pass ports {80,443}")
	}
	rec.DstPort = 443
	if !f.Match(&rec) {
		t.Fatal("tcp/443 must pass")
	}
	// src 端口命中亦可
	f2 := CompileFilter(&FlowFilter{Ports: []uint32{8080}})
	rec2 := shared.FlowRecord{SrcPort: 8080, DstPort: 9999}
	if !f2.Match(&rec2) {
		t.Fatal("src port hit must pass")
	}
}

func TestFilterNil(t *testing.T) {
	var f *Filter
	rec := shared.FlowRecord{}
	if !f.Match(&rec) {
		t.Fatal("nil filter matches all")
	}
}
