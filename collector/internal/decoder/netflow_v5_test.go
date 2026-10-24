package decoder

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"reflect"
	"testing"

	"github.com/SchearLoe/lucidnet/shared"
)

// —— 手工构造 v5 字节 fixture ——

type v5HeaderFixture struct {
	Count        uint16
	SysUptime    uint32
	UnixSecs     uint32
	UnixNsecs    uint32
	FlowSequence uint32
	EngineType   uint8
	EngineID     uint8
	Sampling     uint16 // bit15-14 mode / bit13-0 interval
}

func (h v5HeaderFixture) marshal() []byte {
	b := make([]byte, v5HeaderLen)
	binary.BigEndian.PutUint16(b[0:2], VersionNetFlowV5)
	binary.BigEndian.PutUint16(b[2:4], h.Count)
	binary.BigEndian.PutUint32(b[4:8], h.SysUptime)
	binary.BigEndian.PutUint32(b[8:12], h.UnixSecs)
	binary.BigEndian.PutUint32(b[12:16], h.UnixNsecs)
	binary.BigEndian.PutUint32(b[16:20], h.FlowSequence)
	b[20] = h.EngineType
	b[21] = h.EngineID
	binary.BigEndian.PutUint16(b[22:24], h.Sampling)
	return b
}

type v5RecFixture struct {
	SrcAddr, DstAddr, NextHop uint32
	Input, Output             uint16
	Packets, Octets           uint32
	First, Last               uint32
	SrcPort, DstPort          uint16
	TCPFlags, Proto, TOS      uint8
	SrcAS, DstAS              uint16
	SrcMask, DstMask          uint8
}

func (r v5RecFixture) marshal() []byte {
	b := make([]byte, v5RecordLen)
	binary.BigEndian.PutUint32(b[0:4], r.SrcAddr)
	binary.BigEndian.PutUint32(b[4:8], r.DstAddr)
	binary.BigEndian.PutUint32(b[8:12], r.NextHop)
	binary.BigEndian.PutUint16(b[12:14], r.Input)
	binary.BigEndian.PutUint16(b[14:16], r.Output)
	binary.BigEndian.PutUint32(b[16:20], r.Packets)
	binary.BigEndian.PutUint32(b[20:24], r.Octets)
	binary.BigEndian.PutUint32(b[24:28], r.First)
	binary.BigEndian.PutUint32(b[28:32], r.Last)
	binary.BigEndian.PutUint16(b[32:34], r.SrcPort)
	binary.BigEndian.PutUint16(b[34:36], r.DstPort)
	// b[36] pad1
	b[37] = r.TCPFlags
	b[38] = r.Proto
	b[39] = r.TOS
	binary.BigEndian.PutUint16(b[40:42], r.SrcAS)
	binary.BigEndian.PutUint16(b[42:44], r.DstAS)
	b[44] = r.SrcMask
	b[45] = r.DstMask
	// b[46:48] pad2
	return b
}

func v4u(ip string) uint32 {
	a := netip.MustParseAddr(ip).As4()
	return binary.BigEndian.Uint32(a[:])
}

var testExporter = netip.MustParseAddr("10.255.0.1")

func TestDecodeV5FullFieldMapping(t *testing.T) {
	hdr := v5HeaderFixture{
		Count: 1, SysUptime: 100_000, UnixSecs: 1_700_000_000, UnixNsecs: 500_000_000,
		FlowSequence: 42, EngineType: 1, EngineID: 2, Sampling: 0,
	}
	rec := v5RecFixture{
		SrcAddr: v4u("192.0.2.23"), DstAddr: v4u("198.51.100.9"), NextHop: v4u("203.0.113.1"),
		Input: 5, Output: 9, Packets: 1000, Octets: 150_000,
		First: 50_000, Last: 90_000,
		SrcPort: 1024, DstPort: 443, TCPFlags: 0x12, Proto: 6, TOS: 0x2e,
		SrcAS: 65001, DstAS: 65002, SrcMask: 24, DstMask: 20,
	}
	d := NewV5()
	res, err := d.Decode(append(hdr.marshal(), rec.marshal()...), testExporter)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(res.Records) != 1 {
		t.Fatalf("records = %d, want 1", len(res.Records))
	}
	if len(res.TemplateEvents) != 0 {
		t.Errorf("v5 template events = %d, want 0（v5 无模板机制）", len(res.TemplateEvents))
	}
	want := shared.FlowRecord{
		// boot = 1700000000500 - 100000 = 1699999900500；start = boot+50000；end = boot+90000
		TimeStartMs: 1_699_999_950_500,
		TimeEndMs:   1_699_999_990_500,
		Exporter:    "10.255.0.1",
		InIf:        5, OutIf: 9,
		SrcIP:      v4Mapped16(v4u("192.0.2.23")),
		DstIP:      v4Mapped16(v4u("198.51.100.9")),
		BGPNextHop: v4Mapped16(v4u("203.0.113.1")),
		SrcPort:    1024, DstPort: 443, Proto: 6,
		IPVersion: 4, // v5 仅 IPv4，恒定（dd/02 §1 定制点 #4）
		Packets:   1000, Bytes: 150_000,
		TCPFlags: 0x12, TOS: 0x2e,
		SampleRate: 1,
		SrcAS:      65001, DstAS: 65002,
	}
	if !reflect.DeepEqual(res.Records[0], want) {
		t.Errorf("record mismatch:\n got %+v\nwant %+v", res.Records[0], want)
	}
}

func TestDecodeV5MultiRecordAndTrailingBytes(t *testing.T) {
	r1 := v5RecFixture{SrcAddr: v4u("192.0.2.1"), DstAddr: v4u("198.51.100.1"), Proto: 17, Packets: 1}
	r2 := v5RecFixture{SrcAddr: v4u("192.0.2.2"), DstAddr: v4u("198.51.100.2"), Proto: 6, Packets: 2}
	hdr := v5HeaderFixture{Count: 2, SysUptime: 1000, UnixSecs: 2_000_000_000}
	dg := hdr.marshal()
	dg = append(dg, r1.marshal()...)
	dg = append(dg, r2.marshal()...)
	dg = append(dg, 0xde, 0xad, 0x00) // 尾随字节忽略
	res, err := NewV5().Decode(dg, testExporter)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(res.Records) != 2 {
		t.Fatalf("records = %d, want 2", len(res.Records))
	}
	if res.Records[0].Proto != 17 || res.Records[1].Proto != 6 {
		t.Errorf("proto = %d/%d, want 17/6", res.Records[0].Proto, res.Records[1].Proto)
	}
	if res.Records[0].TimeStartMs != 1_999_999_999_000 {
		t.Errorf("start = %d, want %d（boot+first, first=0）", res.Records[0].TimeStartMs, 1_999_999_999_000)
	}
}

func TestDecodeV5UptimeWrap(t *testing.T) {
	// 32bit sysuptime ≈49.7 天回绕：first 落在回绕前（first > 头部 sys_uptime）→ 回退 2^32 ms
	hdr := v5HeaderFixture{Count: 1, SysUptime: 1000, UnixSecs: 2_000_000_000}
	rec := v5RecFixture{First: 4_294_966_296 /* 2^32-1000 */, Last: 500}
	res, err := NewV5().Decode(append(hdr.marshal(), rec.marshal()...), testExporter)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	got := res.Records[0]
	// boot = 2000000000000-1000；start = boot + (2^32-1000) - 2^32 = wall-2000
	if want := int64(1_999_999_998_000); got.TimeStartMs != want {
		t.Errorf("wrapped start = %d, want %d", got.TimeStartMs, want)
	}
	if want := int64(1_999_999_999_500); got.TimeEndMs != want {
		t.Errorf("normal end = %d, want %d", got.TimeEndMs, want)
	}
}

func TestDecodeV5SampleRate(t *testing.T) {
	tests := []struct {
		name     string
		sampling uint16
		opts     []Option
		want     uint32
	}{
		{"header mode 1 interval 100", 1<<14 | 100, nil, 100},
		{"header zero falls back to registry default", 0, []Option{WithDefaultSampleRate(10)}, 10},
		{"header mode without interval falls back", 1 << 14, []Option{WithDefaultSampleRate(10)}, 10},
		{"default 1", 0, nil, 1},
	}
	for _, tc := range tests {
		hdr := v5HeaderFixture{Count: 1, SysUptime: 1, UnixSecs: 1, Sampling: tc.sampling}
		res, err := NewV5(tc.opts...).Decode(append(hdr.marshal(), v5RecFixture{}.marshal()...), testExporter)
		if err != nil {
			t.Fatalf("%s: decode: %v", tc.name, err)
		}
		if got := res.Records[0].SampleRate; got != tc.want {
			t.Errorf("%s: sample_rate = %d, want %d", tc.name, got, tc.want)
		}
	}
}

func TestDecodeV5Errors(t *testing.T) {
	hdr := v5HeaderFixture{Count: 2, SysUptime: 1, UnixSecs: 1}
	oneRec := append(hdr.marshal(), v5RecFixture{}.marshal()...)

	tests := []struct {
		name string
		data []byte
		want error
	}{
		{"short header", make([]byte, 10), ErrDatagramTooShort},
		{"truncated records", oneRec, ErrRecordTruncated}, // count=2 只带 1 条
	}
	for _, tc := range tests {
		if _, err := NewV5().Decode(tc.data, testExporter); !errors.Is(err, tc.want) {
			t.Errorf("%s: err = %v, want %v", tc.name, err, tc.want)
		}
	}

	// v9 数据报：版本不符（v9/IPFIX 由 goflow2 fork 解码器负责，dd/02 §1）
	v9 := make([]byte, v5HeaderLen)
	binary.BigEndian.PutUint16(v9[0:2], VersionNetFlowV9)
	if _, err := NewV5().Decode(v9, testExporter); !errors.Is(err, ErrVersionMismatch) {
		t.Errorf("v9 datagram: err = %v, want ErrVersionMismatch", err)
	}

	// exporter 地址非法
	if _, err := NewV5().Decode(hdr.marshal(), netip.Addr{}); err == nil {
		t.Error("invalid exporter: want error, got nil")
	}
}
