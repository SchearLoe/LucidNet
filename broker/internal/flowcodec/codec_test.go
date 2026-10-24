package flowcodec

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"
	"time"

	"github.com/SchearLoe/lucidnet/shared"
)

func TestFlowRecordMarshalRoundtrip(t *testing.T) {
	rec := shared.FlowRecord{
		TimeStartMs: 1729700000123,
		TimeEndMs:   1729700002123,
		Exporter:    "10.1.1.1",
		InIf:        12,
		OutIf:       15,
		SrcIP:       v4Mapped(0x01020304),
		DstIP:       v4Mapped(0x05060708),
		SrcPort:     44321,
		DstPort:     443,
		Proto:       6,
		IPVersion:   4,
		Packets:     120,
		Bytes:       86400,
		TCPFlags:    0x12,
		TOS:         0,
		SampleRate:  10,
		SrcAS:       4134,
		DstAS:       9808,
		ZoneID:      101,
		IfRole:      3,
		ZoneSide:    1,
	}
	b := MarshalFlowRecord(&rec)
	got, err := UnmarshalFlowRecord(b)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got != rec {
		t.Errorf("roundtrip mismatch:\n got %+v\nwant %+v", got, rec)
	}
}

func TestFlowRecordFieldNumbers(t *testing.T) {
	// exporter=3 / zone_id=26 / zone_side=28 字段号锁定（proto/lucidnet/v1/flowrecord.proto）
	rec := shared.FlowRecord{Exporter: "1.2.3.4", ZoneID: 7, ZoneSide: 2}
	b := MarshalFlowRecord(&rec)
	if b[0] != 3<<3|2 {
		t.Errorf("exporter tag = %#x", b[0])
	}
	found := walkFields(b)
	if wt, ok := found[26]; !ok || wt != 0 {
		t.Errorf("zone_id field 26 missing/wrong: %v", found)
	}
	if wt, ok := found[28]; !ok || wt != 0 {
		t.Errorf("zone_side field 28 missing/wrong: %v", found)
	}
	if wt, ok := found[3]; !ok || wt != 2 {
		t.Errorf("exporter field 3 missing/wrong: %v", found)
	}
}

// walkFields —— 测试用最小 proto3 字段遍历（正确处理多字节 varint tag/value）。
func walkFields(b []byte) map[int]int {
	out := map[int]int{}
	i := 0
	for i < len(b) {
		tag, next := protoVarint(b, i)
		i = next
		field, wt := int(tag>>3), int(tag&7)
		out[field] = wt
		switch wt {
		case 0:
			_, i = protoVarint(b, i)
		case 2:
			l, n := protoVarint(b, i)
			i = n + int(l)
		case 1:
			i += 8
		case 5:
			i += 4
		default:
			return out
		}
	}
	return out
}

func protoVarint(b []byte, i int) (uint64, int) {
	var v uint64
	var shift uint
	for i < len(b) {
		v |= uint64(b[i]&0x7f) << shift
		i++
		if b[i-1]&0x80 == 0 {
			break
		}
		shift += 7
	}
	return v, i
}

func TestDecodeEncodeV5(t *testing.T) {
	dg := buildV5Datagram(t, 2, map[int]struct {
		src, dst uint32
		sport    uint16
	}{
		0: {src: 0x01020304, dst: 0x05060708, sport: 1000},
		1: {src: 0x0A0B0C0D, dst: 0x0E0F1011, sport: 2000},
	})
	exp := netip.MustParseAddr("10.1.1.1")
	recs, h, err := DecodeV5(dg, exp)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if h.Version != 5 || h.Count != 2 || len(recs) != 2 {
		t.Fatalf("header: %+v records=%d", h, len(recs))
	}
	if recs[0].Exporter != "10.1.1.1" || recs[0].IPVersion != 4 || recs[0].SampleRate != 1 {
		t.Errorf("rec0 = %+v", recs[0])
	}
	if got := binary.BigEndian.Uint32(recs[1].SrcIP[12:16]); got != 0x01020305 { // src = 0x01020304+i
		t.Errorf("rec1 src = %#x", got)
	}

	// 重编码：会话内 flush → 头部 count/seq 语义（包内序号 = 本包首流序号，发包后累加）
	enc := NewV5Encoder(time.Unix(1700000000, 0))
	for _, r := range recs {
		if enc.Append(r) {
			t.Fatal("unexpected full flush at 2 records")
		}
	}
	out := enc.Flush(time.Unix(1700000001, 0))
	if out == nil {
		t.Fatal("flush empty")
	}
	if binary.BigEndian.Uint16(out[0:2]) != 5 || binary.BigEndian.Uint16(out[2:4]) != 2 {
		t.Errorf("out header version/count = %d/%d", binary.BigEndian.Uint16(out[0:2]), binary.BigEndian.Uint16(out[2:4]))
	}
	if binary.BigEndian.Uint32(out[16:20]) != 0 {
		t.Errorf("first flow sequence = %d", binary.BigEndian.Uint32(out[16:20]))
	}
	// 第二包序号接续（目的地独立维护，dd/01 §4.2）
	enc.Append(recs[0])
	out2 := enc.Flush(time.Unix(1700000002, 0))
	if binary.BigEndian.Uint32(out2[16:20]) != 2 {
		t.Errorf("second flow sequence = %d", binary.BigEndian.Uint32(out2[16:20]))
	}
	if binary.BigEndian.Uint32(out[4:8]) != 1000 { // sysuptime = flush - boot
		t.Errorf("sysuptime = %d", binary.BigEndian.Uint32(out[4:8]))
	}
	// 记录字段回读：第 0 条 src/dst/proto
	if got := binary.BigEndian.Uint32(out[24:28]); got != 0x01020304 {
		t.Errorf("out rec0 src = %#x", got)
	}
	if out[24+38] != 6 { // proto
		t.Errorf("out rec0 proto = %d", out[24+38])
	}
	// 二次解码自洽
	recs2, _, err := DecodeV5(out, exp)
	if err != nil || len(recs2) != 2 {
		t.Fatalf("re-decode: %v n=%d", err, len(recs2))
	}
	if recs2[1].SrcPort != recs[1].SrcPort {
		t.Errorf("re-decode sport mismatch: %d vs %d", recs2[1].SrcPort, recs[1].SrcPort)
	}
}

func TestV5EncoderBatchLimit(t *testing.T) {
	enc := NewV5Encoder(time.Now())
	exp := netip.MustParseAddr("10.0.0.9")
	recs, _, _ := DecodeV5(buildV5Datagram(t, 1, nil), exp)
	rec := recs[0]
	full := false
	for i := 0; i < V5MaxRecords; i++ {
		full = enc.Append(rec)
	}
	if !full || enc.Pending() != V5MaxRecords {
		t.Fatalf("pending=%d full=%v", enc.Pending(), full)
	}
	out := enc.Flush(time.Now())
	if len(out) != V5HeaderLen+V5MaxRecords*V5RecordLen {
		t.Errorf("packet size = %d", len(out))
	}
}

func TestDecodeV5Errors(t *testing.T) {
	exp := netip.MustParseAddr("10.0.0.1")
	if _, _, err := DecodeV5([]byte{0, 5, 0}, exp); err == nil {
		t.Error("short datagram should fail")
	}
	bad := make([]byte, V5HeaderLen)
	binary.BigEndian.PutUint16(bad[0:2], 9)
	if _, _, err := DecodeV5(bad, exp); err == nil {
		t.Error("version 9 should fail in v5 decoder")
	}
	trunc := buildV5Datagram(t, 3, nil)[:V5HeaderLen+2*V5RecordLen]
	if _, _, err := DecodeV5(trunc, exp); err == nil {
		t.Error("truncated records should fail")
	}
}

// buildV5Datagram —— 构造测试用 v5 数据报。
func buildV5Datagram(t *testing.T, count int, _ map[int]struct {
	src, dst uint32
	sport    uint16
}) []byte {
	t.Helper()
	dg := make([]byte, V5HeaderLen+count*V5RecordLen)
	binary.BigEndian.PutUint16(dg[0:2], 5)
	binary.BigEndian.PutUint16(dg[2:4], uint16(count))
	binary.BigEndian.PutUint32(dg[4:8], 5000) // sysuptime
	binary.BigEndian.PutUint32(dg[8:12], 1700000000)
	for i := 0; i < count; i++ {
		off := V5HeaderLen + i*V5RecordLen
		binary.BigEndian.PutUint32(dg[off:off+4], uint32(0x01020304+i))
		binary.BigEndian.PutUint32(dg[off+4:off+8], 0x05060708)
		binary.BigEndian.PutUint16(dg[off+32:off+34], uint16(1000+i))
		binary.BigEndian.PutUint16(dg[off+34:off+36], 80)
		dg[off+38] = 6 // proto tcp
	}
	return dg
}

func TestIPFIXSession(t *testing.T) {
	enc := NewIPFIXEncoder(42001, 600*time.Second)
	now := time.Unix(1700000000, 0)
	rec := shared.FlowRecord{
		Exporter:    "10.1.1.1",
		SrcIP:       v4Mapped(0x01020304),
		DstIP:       v4Mapped(0x05060708),
		SrcPort:     5353,
		DstPort:     53,
		Proto:       17,
		IPVersion:   4,
		Packets:     3,
		Bytes:       900,
		TimeStartMs: now.UnixMilli(),
		TimeEndMs:   now.Add(time.Second).UnixMilli(),
		SampleRate:  10,
	}
	if enc.Append(rec) {
		t.Fatal("unexpected flush at 1 record")
	}
	msg := enc.Flush(now, IPFIXAlgoDeterministic, 10)
	if msg == nil {
		t.Fatal("first flush must carry templates + data")
	}
	if binary.BigEndian.Uint16(msg[0:2]) != 10 {
		t.Errorf("ipfix version = %d", binary.BigEndian.Uint16(msg[0:2]))
	}
	if binary.BigEndian.Uint16(msg[2:4]) != uint16(len(msg)) {
		t.Errorf("length field %d != actual %d", binary.BigEndian.Uint16(msg[2:4]), len(msg))
	}
	if binary.BigEndian.Uint32(msg[12:16]) != 42001 {
		t.Errorf("obs domain = %d", binary.BigEndian.Uint32(msg[12:16]))
	}
	// 模板集（Set ID=2 × v4/v6）+ Options 模板（Set ID=3）+ 数据集（Set ID=256）依次出现
	setIDs := walkSetIDs(msg[ipfixHeaderLen:])
	if len(setIDs) < 4 || setIDs[0] != ipfixTemplateSetID || setIDs[1] != ipfixTemplateSetID ||
		setIDs[2] != ipfixOptionsSetID || setIDs[3] != ipfixDataTemplateV4 {
		t.Errorf("set ids = %v", setIDs)
	}
	// 模板周期内不再重发
	if msg2 := enc.Flush(now.Add(time.Second), IPFIXAlgoDeterministic, 10); msg2 != nil {
		t.Error("no data + template fresh → nil message")
	}
	// 600s 到期：仅模板（v4+v6 options）
	if msg3 := enc.Flush(now.Add(601*time.Second), IPFIXAlgoDeterministic, 10); msg3 == nil {
		t.Error("template resend due")
	} else {
		ids := walkSetIDs(msg3[ipfixHeaderLen:])
		if len(ids) != 3 || ids[0] != ipfixTemplateSetID || ids[1] != ipfixTemplateSetID || ids[2] != ipfixOptionsSetID {
			t.Errorf("resend sets = %v", ids)
		}
	}
	// 序列号 = 累计数据记录数
	if binary.BigEndian.Uint32(msg[8:12]) != 1 {
		t.Errorf("sequence = %d", binary.BigEndian.Uint32(msg[8:12]))
	}
}

func TestIPFIXV6SeparateSet(t *testing.T) {
	enc := NewIPFIXEncoder(1, time.Hour)
	now := time.Now()
	v6 := shared.FlowRecord{IPVersion: 6, SrcIP: [16]byte{0x20, 0x01}, DstIP: [16]byte{0x20, 0x02}, Proto: 6}
	enc.Append(v6)
	enc.Append(shared.FlowRecord{IPVersion: 4, SrcIP: v4Mapped(1), DstIP: v4Mapped(2), Proto: 6})
	msg := enc.Flush(now, IPFIXAlgoRandom, 5)
	ids := walkSetIDs(msg[ipfixHeaderLen:])
	var hasV4, hasV6 bool
	for _, id := range ids {
		if id == ipfixDataTemplateV4 {
			hasV4 = true
		}
		if id == ipfixDataTemplateV6 {
			hasV6 = true
		}
	}
	if !hasV4 || !hasV6 {
		t.Errorf("expect both v4/v6 data sets, got %v", ids)
	}
}

// walkSetIDs —— 遍历消息体 Set 序列返回 Set ID。
func walkSetIDs(body []byte) []uint16 {
	var ids []uint16
	for len(body) >= 4 {
		id := binary.BigEndian.Uint16(body[0:2])
		l := int(binary.BigEndian.Uint16(body[2:4]))
		if l < 4 || l > len(body) {
			break
		}
		ids = append(ids, id)
		body = body[l:]
	}
	return ids
}

func TestV4MappedHelper(t *testing.T) {
	a := v4Mapped(0x0A000001)
	if a[10] != 0xff || a[11] != 0xff || !bytes.Equal(a[12:16], []byte{10, 0, 0, 1}) {
		t.Errorf("v4 mapped = %v", a)
	}
	addr, ok := V4MappedIPv4(a)
	if !ok || addr.String() != "10.0.0.1" {
		t.Errorf("V4MappedIPv4 = %v %v", addr, ok)
	}
}
