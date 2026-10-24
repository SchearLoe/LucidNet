package flowcodec

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"time"
)

// —— NetFlow v9 测试报文构造（模板集先行正常流 / 模板缺失 / 畸形包，任务一） ——

// v9TestTemplate —— 测试用数据模板：IN_BYTES(4)/IN_PKTS(4)/PROTO(1)/SRC_PORT(2)/
// SRC_ADDR(4)/DST_PORT(2)/DST_ADDR(4)/FIRST_SWITCHED(4)/LAST_SWITCHED(4) = 29B。
var v9TestTemplate = []struct {
	ie uint16
	ln uint16
}{
	{1, 4}, {2, 4}, {4, 1}, {7, 2}, {8, 4}, {11, 2}, {12, 4}, {22, 4}, {21, 4},
}

const (
	v9TestTemplateID = 1024
	v9TestRecordLen  = 29
)

func v9TestRecord(startMs, lastMs uint32) []byte {
	r := make([]byte, v9TestRecordLen)
	binary.BigEndian.PutUint32(r[0:4], 1500) // IN_BYTES
	binary.BigEndian.PutUint32(r[4:8], 3)    // IN_PKTS
	r[8] = 6                                 // PROTO tcp
	binary.BigEndian.PutUint16(r[9:11], 1000)
	binary.BigEndian.PutUint32(r[11:15], 0x0A000001)
	binary.BigEndian.PutUint16(r[15:17], 80)
	binary.BigEndian.PutUint32(r[17:21], 0x0A000002)
	binary.BigEndian.PutUint32(r[21:25], startMs)
	binary.BigEndian.PutUint32(r[25:29], lastMs)
	return r
}

func v9TemplateSet() []byte {
	s := make([]byte, 0, 8+len(v9TestTemplate)*4)
	s = binary.BigEndian.AppendUint16(s, 0) // template flowset id
	// set 长 = 4B set 头 + 4B 模板头（template_id+field_count）+ 4B×字段数
	s = binary.BigEndian.AppendUint16(s, uint16(8+len(v9TestTemplate)*4))
	s = binary.BigEndian.AppendUint16(s, v9TestTemplateID)
	s = binary.BigEndian.AppendUint16(s, uint16(len(v9TestTemplate)))
	for _, f := range v9TestTemplate {
		s = binary.BigEndian.AppendUint16(s, f.ie)
		s = binary.BigEndian.AppendUint16(s, f.ln)
	}
	return s
}

func v9DataSet(id uint16, records ...[]byte) []byte {
	n := 4
	for _, r := range records {
		n += len(r)
	}
	s := make([]byte, 0, n)
	s = binary.BigEndian.AppendUint16(s, id)
	s = binary.BigEndian.AppendUint16(s, uint16(n))
	for _, r := range records {
		s = append(s, r...)
	}
	return s
}

func v9Packet(sourceID uint32, sets ...[]byte) []byte {
	var body []byte
	for _, s := range sets {
		body = append(body, s...)
	}
	dg := make([]byte, V9HeaderLen+len(body))
	binary.BigEndian.PutUint16(dg[0:2], 9)
	binary.BigEndian.PutUint32(dg[4:8], 5000)        // sys uptime ms
	binary.BigEndian.PutUint32(dg[8:12], 1700000000) // unix secs
	binary.BigEndian.PutUint32(dg[16:20], sourceID)
	copy(dg[V9HeaderLen:], body)
	return dg
}

var v9Exp = netip.MustParseAddr("10.9.9.9")

// TestDecodeV9TemplateThenData —— 正常流：模板集先行（同包），数据集解出统一记录。
func TestDecodeV9TemplateThenData(t *testing.T) {
	tc := NewTemplateCache(0, 0, nil)
	dg := v9Packet(7, v9TemplateSet(), v9DataSet(v9TestTemplateID, v9TestRecord(1000, 2000)))
	recs, h, stats, err := DecodeV9(dg, v9Exp, tc)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if h.Version != 9 || h.SourceID != 7 || h.SysUptime != 5000 {
		t.Errorf("header = %+v", h)
	}
	if stats.Sum() != 0 || stats.LearnedTemplates != 1 {
		t.Errorf("stats = %+v", stats)
	}
	if len(recs) != 1 {
		t.Fatalf("records = %d", len(recs))
	}
	rec := recs[0]
	if rec.Exporter != "10.9.9.9" || rec.IPVersion != 4 {
		t.Errorf("rec0 = %+v", rec)
	}
	if rec.Bytes != 1500 || rec.Packets != 3 || rec.Proto != 6 || rec.SampleRate != 1 {
		t.Errorf("counters = %+v", rec)
	}
	if rec.SrcPort != 1000 || rec.DstPort != 80 {
		t.Errorf("ports = %d/%d", rec.SrcPort, rec.DstPort)
	}
	if got := binary.BigEndian.Uint32(rec.SrcIP[12:16]); got != 0x0A000001 {
		t.Errorf("src = %#x", got)
	}
	// 时间：boot = 1700000000000-5000；start = boot+1000, end = boot+2000
	if rec.TimeStartMs != 1699999996000 || rec.TimeEndMs != 1699999997000 {
		t.Errorf("times = %d/%d", rec.TimeStartMs, rec.TimeEndMs)
	}
	// 模板已学习：后续纯数据包直接解码
	recs2, _, stats2, err := DecodeV9(v9Packet(7, v9DataSet(v9TestTemplateID, v9TestRecord(3000, 4000))), v9Exp, tc)
	if err != nil || len(recs2) != 1 || stats2.Sum() != 0 || stats2.LearnedTemplates != 0 {
		t.Fatalf("second packet: n=%d stats=%+v err=%v", len(recs2), stats2, err)
	}
	if recs2[0].TimeStartMs != 1699999998000 {
		t.Errorf("second start = %d", recs2[0].TimeStartMs)
	}
	// 同 source_id 不同 exporter：模板作用域隔离 → 跳过
	other := netip.MustParseAddr("10.9.9.10")
	_, _, stats3, _ := DecodeV9(v9Packet(7, v9DataSet(v9TestTemplateID, v9TestRecord(1, 2))), other, tc)
	if stats3.SkippedDataSets != 1 {
		t.Errorf("template must be scoped per exporter: %+v", stats3)
	}
}

// TestDecodeV9DataBeforeTemplate —— 模板先于数据缺失：数据集跳过计数，学习后恢复。
func TestDecodeV9DataBeforeTemplate(t *testing.T) {
	tc := NewTemplateCache(0, 0, nil)
	recs, _, stats, err := DecodeV9(v9Packet(7, v9DataSet(v9TestTemplateID, v9TestRecord(1, 2))), v9Exp, tc)
	if err != nil {
		t.Fatalf("decode must not fail hard: %v", err)
	}
	if len(recs) != 0 || stats.SkippedDataSets != 1 {
		t.Fatalf("n=%d stats=%+v", len(recs), stats)
	}
	// 同包学习场景（数据在前、模板在后）：数据集跳过，模板学习成功
	dg := v9Packet(7, v9DataSet(v9TestTemplateID, v9TestRecord(1, 2)), v9TemplateSet())
	_, _, stats2, _ := DecodeV9(dg, v9Exp, tc)
	if stats2.SkippedDataSets != 1 || stats2.LearnedTemplates != 1 {
		t.Fatalf("same-packet late template: %+v", stats2)
	}
	// 下一包恢复解码
	recs3, _, stats3, _ := DecodeV9(v9Packet(7, v9DataSet(v9TestTemplateID, v9TestRecord(1, 2))), v9Exp, tc)
	if len(recs3) != 1 || stats3.Sum() != 0 {
		t.Fatalf("after learn: n=%d stats=%+v", len(recs3), stats3)
	}
}

// TestDecodeV9TemplateExpiry —— 模板超时老化：过期后数据集跳过，重学恢复。
func TestDecodeV9TemplateExpiry(t *testing.T) {
	now := time.Unix(1700000000, 0)
	tc := NewTemplateCache(time.Minute, 0, func() time.Time { return now })
	dg := v9Packet(7, v9TemplateSet(), v9DataSet(v9TestTemplateID, v9TestRecord(1, 2)))
	if _, _, stats, _ := DecodeV9(dg, v9Exp, tc); stats.Sum() != 0 {
		t.Fatalf("initial: %+v", stats)
	}
	now = now.Add(2 * time.Minute) // 超过 maxAge 未刷新
	_, _, stats, _ := DecodeV9(v9Packet(7, v9DataSet(v9TestTemplateID, v9TestRecord(1, 2))), v9Exp, tc)
	if stats.SkippedDataSets != 1 || tc.Len() != 0 {
		t.Fatalf("expired: stats=%+v len=%d", stats, tc.Len())
	}
	// 重学后恢复
	now = now.Add(time.Second)
	dg = v9Packet(7, v9TemplateSet(), v9DataSet(v9TestTemplateID, v9TestRecord(1, 2)))
	if _, _, stats, _ := DecodeV9(dg, v9Exp, tc); stats.Sum() != 0 {
		t.Fatalf("re-learn: %+v", stats)
	}
}

// TestDecodeV9OptionsSampling —— options 模板（v9 长度按字节）学习采样间隔，
// 数据记录未带采样 IE 时回退。
func TestDecodeV9OptionsSampling(t *testing.T) {
	tc := NewTemplateCache(0, 0, nil)
	// option template 1026：scope=(type 1 system, 4B)，option=(34 samplingInterval, 4B)
	// set 长 = 4B set 头 + 6B v9 options 模板头 + 4B×2 说明符
	opt := make([]byte, 0, 18)
	opt = binary.BigEndian.AppendUint16(opt, 1) // options flowset id
	opt = binary.BigEndian.AppendUint16(opt, 18)
	opt = binary.BigEndian.AppendUint16(opt, 1026)
	opt = binary.BigEndian.AppendUint16(opt, 4) // scope 字节长
	opt = binary.BigEndian.AppendUint16(opt, 4) // option 字节长
	opt = binary.BigEndian.AppendUint16(opt, 1) // scope type system
	opt = binary.BigEndian.AppendUint16(opt, 4)
	opt = binary.BigEndian.AppendUint16(opt, 34) // samplingInterval
	opt = binary.BigEndian.AppendUint16(opt, 4)
	optRec := make([]byte, 8)
	binary.BigEndian.PutUint32(optRec[4:8], 10) // interval 1:10

	dg := v9Packet(7, v9TemplateSet(), opt, v9DataSet(1026, optRec),
		v9DataSet(v9TestTemplateID, v9TestRecord(1000, 2000)))
	recs, _, stats, err := DecodeV9(dg, v9Exp, tc)
	if err != nil || stats.Sum() != 0 {
		t.Fatalf("decode: err=%v stats=%+v", err, stats)
	}
	if len(recs) != 1 {
		t.Fatalf("records = %d", len(recs))
	}
	if recs[0].SampleRate != 10 {
		t.Errorf("sample rate = %d (want 10 via options fallback)", recs[0].SampleRate)
	}
}

// TestDecodeV9EnterpriseField —— vendor PEN 字段仅消费不映射，不影响其余字段。
func TestDecodeV9EnterpriseField(t *testing.T) {
	tc := NewTemplateCache(0, 0, nil)
	// 字段说明符：(1,4) / (0x8064,8)+PEN / (12,4) → spec 字节 4+8+4=16
	s := make([]byte, 0, 8+16)
	s = binary.BigEndian.AppendUint16(s, 0)
	s = binary.BigEndian.AppendUint16(s, 8+16)
	s = binary.BigEndian.AppendUint16(s, 2048)
	s = binary.BigEndian.AppendUint16(s, 3)
	s = binary.BigEndian.AppendUint16(s, 1) // ie
	s = binary.BigEndian.AppendUint16(s, 4) // len
	s = binary.BigEndian.AppendUint16(s, 0x8000|100)
	s = binary.BigEndian.AppendUint16(s, 8)
	s = binary.BigEndian.AppendUint32(s, 999) // PEN
	s = binary.BigEndian.AppendUint16(s, 12)
	s = binary.BigEndian.AppendUint16(s, 4)
	rec := make([]byte, 16)
	binary.BigEndian.PutUint32(rec[0:4], 777)
	binary.BigEndian.PutUint32(rec[4:8], 0xDEADBEEF) // 私有数据（应被跳过）
	binary.BigEndian.PutUint32(rec[8:12], 0xCAFE0000)
	binary.BigEndian.PutUint32(rec[12:16], 0x0A000002)

	dg := v9Packet(7, s, v9DataSet(2048, rec))
	if _, _, stats, err := DecodeV9(dg, v9Exp, tc); err != nil || stats.Sum() != 0 {
		t.Fatalf("decode: err=%v stats=%+v", err, stats)
	}
	recs, _, _, _ := DecodeV9(v9Packet(7, v9DataSet(2048, rec)), v9Exp, tc)
	if len(recs) != 1 {
		t.Fatalf("records = %d", len(recs))
	}
	if recs[0].Bytes != 777 {
		t.Errorf("bytes = %d", recs[0].Bytes)
	}
	if got := binary.BigEndian.Uint32(recs[0].DstIP[12:16]); got != 0x0A000002 {
		t.Errorf("dst = %#x", got)
	}
}

// TestDecodeV9Malformed —— 畸形包：不 panic，逐 set 计数跳过。
func TestDecodeV9Malformed(t *testing.T) {
	tc := NewTemplateCache(0, 0, nil)
	if _, _, _, err := DecodeV9([]byte{0, 9, 0}, v9Exp, tc); err == nil {
		t.Error("short header must fail")
	}
	if _, _, _, err := DecodeV9(make([]byte, V9HeaderLen), netip.Addr{}, tc); err == nil {
		t.Error("invalid exporter must fail")
	}
	bad := make([]byte, V9HeaderLen)
	binary.BigEndian.PutUint16(bad[0:2], 10)
	if _, _, _, err := DecodeV9(bad, v9Exp, tc); err == nil {
		t.Error("version 10 must fail in v9 decoder")
	}
	// set 长度非法（0）
	if _, _, stats, _ := DecodeV9(v9Packet(7, []byte{0, 0, 0, 0}), v9Exp, tc); stats.BadSets != 1 {
		t.Errorf("zero set length: %+v", stats)
	}
	// set 长度越界
	over := make([]byte, 4)
	binary.BigEndian.PutUint16(over[2:4], 1000)
	if _, _, stats, _ := DecodeV9(v9Packet(7, over), v9Exp, tc); stats.BadSets != 1 {
		t.Errorf("overflow set length: %+v", stats)
	}
	// 模板记录截断（field_count=3 但只有 1 个字段说明符）
	truncT := make([]byte, 0, 12)
	truncT = binary.BigEndian.AppendUint16(truncT, 0)
	truncT = binary.BigEndian.AppendUint16(truncT, 12)
	truncT = binary.BigEndian.AppendUint16(truncT, 3072)
	truncT = binary.BigEndian.AppendUint16(truncT, 3)
	truncT = binary.BigEndian.AppendUint16(truncT, 1) // 只有 1/3 字段
	truncT = binary.BigEndian.AppendUint16(truncT, 4)
	if _, _, stats, _ := DecodeV9(v9Packet(7, truncT), v9Exp, tc); stats.BadSets != 1 {
		t.Errorf("truncated template: %+v", stats)
	}
	// 数据记录短于模板定长（脏尾 ≥4B → skipped）
	shortRec := make([]byte, 12)
	binary.BigEndian.PutUint32(shortRec[0:4], 99)
	dg := v9Packet(7, v9TemplateSet(), v9DataSet(v9TestTemplateID, shortRec))
	_, _, stats, _ := DecodeV9(dg, v9Exp, tc)
	if stats.SkippedDataSets != 1 {
		t.Errorf("short record: %+v", stats)
	}
	// set 尾 2B 对齐 padding：静默忽略
	padded := v9DataSet(v9TestTemplateID, v9TestRecord(1, 2))
	padded = append(padded, 0, 0)
	binary.BigEndian.PutUint16(padded[2:4], uint16(len(padded)))
	recs, _, stats, _ := DecodeV9(v9Packet(7, v9TemplateSet(), padded), v9Exp, tc)
	if len(recs) != 1 || stats.SkippedDataSets != 0 {
		t.Errorf("padding: n=%d stats=%+v", len(recs), stats)
	}
}

// TestDecodeV9RecordScale —— 单包多 set 多记录（顺序保持、产出计数正确）。
func TestDecodeV9RecordScale(t *testing.T) {
	tc := NewTemplateCache(0, 0, nil)
	recs1 := make([][]byte, 0, 50)
	for i := 0; i < 50; i++ {
		r := v9TestRecord(uint32(i)*10, uint32(i)*10+5)
		binary.BigEndian.PutUint16(r[9:11], uint16(2000+i))
		recs1 = append(recs1, r)
	}
	recs2 := make([][]byte, 0, 25)
	for i := 0; i < 25; i++ {
		r := v9TestRecord(uint32(i)*10, uint32(i)*10+5)
		binary.BigEndian.PutUint16(r[9:11], uint16(3000+i))
		recs2 = append(recs2, r)
	}
	dg := v9Packet(7, v9TemplateSet(), v9DataSet(v9TestTemplateID, recs1...), v9DataSet(v9TestTemplateID, recs2...))
	got, _, stats, err := DecodeV9(dg, v9Exp, tc)
	if err != nil || stats.Sum() != 0 {
		t.Fatalf("decode: err=%v stats=%+v", err, stats)
	}
	if len(got) != 75 {
		t.Fatalf("records = %d", len(got))
	}
	if got[0].SrcPort != 2000 || got[50].SrcPort != 3000 || got[74].SrcPort != 3024 {
		t.Errorf("order broken: %d/%d/%d", got[0].SrcPort, got[50].SrcPort, got[74].SrcPort)
	}
}

// TestDecodeV9NilCache —— nil 缓存安全（每包独立语义：无模板则跳过）。
func TestDecodeV9NilCache(t *testing.T) {
	recs, _, stats, err := DecodeV9(v9Packet(7, v9DataSet(v9TestTemplateID, v9TestRecord(1, 2))), v9Exp, nil)
	if err != nil || len(recs) != 0 || stats.SkippedDataSets != 1 {
		t.Errorf("n=%d stats=%+v err=%v", len(recs), stats, err)
	}
}

// TestDecodeV9V6Addresses —— IE 27/28 v6 地址。
func TestDecodeV9V6Addresses(t *testing.T) {
	tc := NewTemplateCache(0, 0, nil)
	fields := []struct {
		ie uint16
		ln uint16
	}{{1, 8}, {2, 8}, {4, 1}, {27, 16}, {28, 16}}
	tmpl := make([]byte, 0, 8+len(fields)*4)
	tmpl = binary.BigEndian.AppendUint16(tmpl, 0)
	tmpl = binary.BigEndian.AppendUint16(tmpl, uint16(8+len(fields)*4))
	tmpl = binary.BigEndian.AppendUint16(tmpl, 4096)
	tmpl = binary.BigEndian.AppendUint16(tmpl, uint16(len(fields)))
	for _, f := range fields {
		tmpl = binary.BigEndian.AppendUint16(tmpl, f.ie)
		tmpl = binary.BigEndian.AppendUint16(tmpl, f.ln)
	}
	rec := make([]byte, 8+8+1+32)
	binary.BigEndian.PutUint64(rec[0:8], 900)
	binary.BigEndian.PutUint64(rec[8:16], 7)
	rec[16] = 17
	src := [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	dst := [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}
	copy(rec[17:33], src[:])
	copy(rec[33:49], dst[:])

	dg := v9Packet(7, tmpl, v9DataSet(4096, rec))
	got, _, stats, err := DecodeV9(dg, v9Exp, tc)
	if err != nil || stats.Sum() != 0 || len(got) != 1 {
		t.Fatalf("decode: err=%v stats=%+v n=%d", err, stats, len(got))
	}
	r := got[0]
	if r.IPVersion != 6 || r.Packets != 7 || r.Bytes != 900 || r.Proto != 17 {
		t.Errorf("rec = %+v", r)
	}
	if r.SrcIP != src || r.DstIP != dst {
		t.Errorf("addrs = %v -> %v", r.SrcIP, r.DstIP)
	}
	// 统一记录语义：v6 记录可经 MarshalFlowRecord 顺利编码（与 Kafka 目的地同路径）
	if _, err := UnmarshalFlowRecord(MarshalFlowRecord(&r)); err != nil {
		t.Errorf("proto roundtrip: %v", err)
	}
}
