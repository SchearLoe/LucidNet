package flowcodec

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"time"

	"github.com/SchearLoe/lucidnet/shared"
)

// —— IPFIX 测试报文构造（任务一） ——

func ipfixPacket(obsDomain uint32, exportTime uint32, sets ...[]byte) []byte {
	var body []byte
	for _, s := range sets {
		body = append(body, s...)
	}
	dg := make([]byte, ipfixHeaderLen+len(body))
	binary.BigEndian.PutUint16(dg[0:2], ipfixVersion)
	binary.BigEndian.PutUint16(dg[2:4], uint16(len(dg)))
	binary.BigEndian.PutUint32(dg[4:8], exportTime)
	binary.BigEndian.PutUint32(dg[12:16], obsDomain)
	copy(dg[ipfixHeaderLen:], body)
	return dg
}

func ipfixTemplateSet(id uint16, fields []templateField) []byte {
	n := 8 + len(fields)*4
	s := make([]byte, 0, n)
	s = binary.BigEndian.AppendUint16(s, ipfixTemplateSetID)
	s = binary.BigEndian.AppendUint16(s, uint16(n))
	s = binary.BigEndian.AppendUint16(s, id)
	s = binary.BigEndian.AppendUint16(s, uint16(len(fields)))
	for _, f := range fields {
		s = binary.BigEndian.AppendUint16(s, f.ie)
		s = binary.BigEndian.AppendUint16(s, f.length)
	}
	return s
}

// 与 encode_ipfix.go v4 数据模板同构（roundtrip 用）。
var ipfixV4Fields = []templateField{
	{ieFlowStartMilliseconds, 8}, {ieFlowEndMilliseconds, 8},
	{ieSourceIPv4Address, 4}, {ieDestinationIPv4Address, 4},
	{ieSourceTransportPort, 2}, {ieDestinationTransportPort, 2},
	{ieProtocolIdentifier, 1},
	{iePacketDeltaCount, 8}, {ieOctetDeltaCount, 8},
	{ieTCPControlBits, 1}, {ieIPClassOfService, 1},
	{ieIngressInterface, 4}, {ieEgressInterface, 4},
	{ieBGPSourceASNumber, 4}, {ieBGPDestinationASNumber, 4},
}

func ipfixDataSet(id uint16, records ...[]byte) []byte {
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

var ipfixExp = netip.MustParseAddr("10.7.7.7")

// TestDecodeIPFIXBasic —— 模板集（set id 2）先行 + 绝对时间 IE。
func TestDecodeIPFIXBasic(t *testing.T) {
	tc := NewTemplateCache(0, 0, nil)
	rec := make([]byte, 0, 56)
	rec = binary.BigEndian.AppendUint64(rec, 1700000000000) // flowStartMilliseconds
	rec = binary.BigEndian.AppendUint64(rec, 1700000001500)
	rec = append(rec, 10, 0, 0, 1)
	rec = append(rec, 10, 0, 0, 2)
	rec = binary.BigEndian.AppendUint16(rec, 5000)
	rec = binary.BigEndian.AppendUint16(rec, 443)
	rec = append(rec, 6)
	rec = binary.BigEndian.AppendUint64(rec, 12)  // packets
	rec = binary.BigEndian.AppendUint64(rec, 980) // bytes
	rec = append(rec, 0x12)                       // tcp flags
	rec = append(rec, 0x08)                       // tos
	rec = binary.BigEndian.AppendUint32(rec, 3)   // in if
	rec = binary.BigEndian.AppendUint32(rec, 7)   // out if
	rec = binary.BigEndian.AppendUint32(rec, 4134)
	rec = binary.BigEndian.AppendUint32(rec, 9808)

	dg := ipfixPacket(42, 1700000002, ipfixTemplateSet(256, ipfixV4Fields), ipfixDataSet(256, rec))
	got, h, stats, err := DecodeIPFIX(dg, ipfixExp, tc)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if h.Version != 10 || h.ObsDomainID != 42 || h.Length != uint16(len(dg)) {
		t.Errorf("header = %+v", h)
	}
	if stats.Sum() != 0 || stats.LearnedTemplates != 1 || len(got) != 1 {
		t.Fatalf("stats=%+v n=%d", stats, len(got))
	}
	r := got[0]
	if r.TimeStartMs != 1700000000000 || r.TimeEndMs != 1700000001500 {
		t.Errorf("times = %d/%d", r.TimeStartMs, r.TimeEndMs)
	}
	if r.SrcPort != 5000 || r.DstPort != 443 || r.Proto != 6 || r.Packets != 12 || r.Bytes != 980 {
		t.Errorf("rec = %+v", r)
	}
	if r.TCPFlags != 0x12 || r.TOS != 8 || r.InIf != 3 || r.OutIf != 7 || r.SrcAS != 4134 || r.DstAS != 9808 {
		t.Errorf("rec = %+v", r)
	}
	if got2 := binary.BigEndian.Uint32(r.SrcIP[12:16]); got2 != 0x0A000001 {
		t.Errorf("src = %#x", got2)
	}
}

// TestDecodeIPFIXRoundtripWithEncoder —— 与自有 IPFIXEncoder 输出互逆：
// 编码器首包（模板×2+options+数据）与续包（纯数据）均可解码。
func TestDecodeIPFIXRoundtripWithEncoder(t *testing.T) {
	tc := NewTemplateCache(0, 0, nil)
	enc := NewIPFIXEncoder(42001, time.Hour)
	now := time.Unix(1700000000, 0)
	in := shared.FlowRecord{
		Exporter:    "10.7.7.7",
		SrcIP:       v4Mapped(0x01020304),
		DstIP:       v4Mapped(0x05060708),
		SrcPort:     5353,
		DstPort:     53,
		Proto:       17,
		IPVersion:   4,
		Packets:     3,
		Bytes:       900,
		TCPFlags:    0x10,
		TOS:         4,
		InIf:        2,
		OutIf:       9,
		SrcAS:       100,
		DstAS:       200,
		TimeStartMs: now.UnixMilli(),
		TimeEndMs:   now.Add(time.Second).UnixMilli(),
		SampleRate:  10,
	}
	enc.Append(in)
	msg := enc.Flush(now, IPFIXAlgoDeterministic, 10)
	if msg == nil {
		t.Fatal("first flush must carry templates")
	}
	got, _, stats, err := DecodeIPFIX(msg, ipfixExp, tc)
	if err != nil {
		t.Fatalf("decode first: %v", err)
	}
	if stats.Sum() != 0 || stats.LearnedTemplates != 3 {
		t.Fatalf("stats = %+v (want 3 templates: v4/v6/options)", stats)
	}
	if len(got) != 1 {
		t.Fatalf("records = %d", len(got))
	}
	out := got[0]
	// exporter 由解码侧注入（=数据报源 IP，与 in.Exporter 同值）；
	// 采样率经 options(305) 声明 → 解码回退补齐，二者应自然相等
	if out != in {
		t.Errorf("roundtrip mismatch:\n got %+v\nwant %+v", out, in)
	}
	// 续包（纯数据集）：模板已缓存，options 采样间隔继续兜底
	enc.Append(in)
	msg2 := enc.Flush(now.Add(time.Second), IPFIXAlgoDeterministic, 10)
	if msg2 == nil {
		t.Fatal("second flush")
	}
	got2, _, stats2, err := DecodeIPFIX(msg2, ipfixExp, tc)
	if err != nil || len(got2) != 1 || stats2.Sum() != 0 || stats2.LearnedTemplates != 0 {
		t.Fatalf("second: err=%v n=%d stats=%+v", err, len(got2), stats2)
	}
	if got2[0].Bytes != 900 || got2[0].SampleRate != 10 {
		t.Errorf("second rec = %+v", got2[0])
	}
}

// TestDecodeIPFIXVariableLength —— 变长字段（length=65535，短/长两种前缀）。
func TestDecodeIPFIXVariableLength(t *testing.T) {
	tc := NewTemplateCache(0, 0, nil)
	fields := []templateField{{ieOctetDeltaCount, 4}, {99, ieVarlen}, {ieDestinationTransportPort, 2}}
	rec := make([]byte, 0, 4+4+2+2)
	rec = binary.BigEndian.AppendUint32(rec, 500)
	rec = append(rec, 3, 'a', 'b', 'c') // 短前缀：len=3 + 值
	rec = binary.BigEndian.AppendUint16(rec, 8080)

	dg := ipfixPacket(1, 1700000000, ipfixTemplateSet(300, fields), ipfixDataSet(300, rec))
	got, _, stats, err := DecodeIPFIX(dg, ipfixExp, tc)
	if err != nil || stats.Sum() != 0 || len(got) != 1 {
		t.Fatalf("decode: err=%v stats=%+v n=%d", err, stats, len(got))
	}
	if got[0].Bytes != 500 || got[0].DstPort != 8080 {
		t.Errorf("rec = %+v", got[0])
	}

	// 长前缀：0xFF + 2B 大端长度（300B 值）
	big := make([]byte, 300)
	big[0] = 0xAB
	rec2 := make([]byte, 0, 4+3+300+2)
	rec2 = binary.BigEndian.AppendUint32(rec2, 1)
	rec2 = append(rec2, 0xFF)
	rec2 = binary.BigEndian.AppendUint16(rec2, 300)
	rec2 = append(rec2, big...)
	rec2 = binary.BigEndian.AppendUint16(rec2, 22)
	dg2 := ipfixPacket(1, 1700000000, ipfixDataSet(300, rec2))
	got2, _, stats2, err := DecodeIPFIX(dg2, ipfixExp, tc)
	if err != nil || stats2.Sum() != 0 || len(got2) != 1 {
		t.Fatalf("long varlen: err=%v stats=%+v n=%d", err, stats2, len(got2))
	}
	if got2[0].DstPort != 22 {
		t.Errorf("long varlen rec = %+v", got2[0])
	}
}

// TestDecodeIPFIXAnchorTimes —— systemInitTimeMilliseconds(160) 锚点 +
// flowStart/EndSysUpTime(22/21) 相对时间换算（跨报文两段式）。
func TestDecodeIPFIXAnchorTimes(t *testing.T) {
	tc := NewTemplateCache(0, 0, nil)
	// options 模板 258：scope=(10,4)，option=(160,8)；set 长 = 4B set 头 + 6B 模板头 + 4B + 4B
	optSet := make([]byte, 0, 18)
	optSet = binary.BigEndian.AppendUint16(optSet, ipfixOptionsSetID)
	optSet = binary.BigEndian.AppendUint16(optSet, 18)
	optSet = binary.BigEndian.AppendUint16(optSet, 258) // options template id
	optSet = binary.BigEndian.AppendUint16(optSet, 2)   // field count（含 scope，RFC 7011 §3.4.2）
	optSet = binary.BigEndian.AppendUint16(optSet, 1)   // scope field count
	optSet = binary.BigEndian.AppendUint16(optSet, 10)  // scope: ingressInterface
	optSet = binary.BigEndian.AppendUint16(optSet, 4)
	optSet = binary.BigEndian.AppendUint16(optSet, 160)
	optSet = binary.BigEndian.AppendUint16(optSet, 8)
	optRec := make([]byte, 0, 12)
	optRec = binary.BigEndian.AppendUint32(optRec, 1)             // scope value
	optRec = binary.BigEndian.AppendUint64(optRec, 1699999995000) // systemInitTimeMilliseconds

	// msg1：options 模板 + options 数据（锚点学习）
	msg1 := ipfixPacket(9, 1700000000, optSet, ipfixDataSet(258, optRec))
	if _, _, stats, err := DecodeIPFIX(msg1, ipfixExp, tc); err != nil || stats.Sum() != 0 {
		t.Fatalf("msg1: err=%v stats=%+v", err, stats)
	}
	// msg2：数据模板 22/21 + 数据集 → 锚点换算
	fields := []templateField{{ieFlowStartSysUpTime, 4}, {ieFlowEndSysUpTime, 4}, {ieSourceIPv4Address, 4}}
	rec := make([]byte, 0, 12)
	rec = binary.BigEndian.AppendUint32(rec, 1000)
	rec = binary.BigEndian.AppendUint32(rec, 2500)
	rec = append(rec, 10, 0, 0, 1)
	msg2 := ipfixPacket(9, 1700000000, ipfixTemplateSet(256, fields), ipfixDataSet(256, rec))
	got, _, stats, err := DecodeIPFIX(msg2, ipfixExp, tc)
	if err != nil || stats.Sum() != 0 || len(got) != 1 {
		t.Fatalf("msg2: err=%v stats=%+v n=%d", err, stats, len(got))
	}
	if got[0].TimeStartMs != 1699999996000 || got[0].TimeEndMs != 1699999997500 {
		t.Errorf("anchor times = %d/%d", got[0].TimeStartMs, got[0].TimeEndMs)
	}

	// 无锚点 obsDomain：22/21 缺锚回退报文头时间
	msg3 := ipfixPacket(77, 1700000010, ipfixTemplateSet(256, fields), ipfixDataSet(256, rec))
	got3, _, _, _ := DecodeIPFIX(msg3, ipfixExp, tc)
	if len(got3) != 1 || got3[0].TimeStartMs != 1700000010000 {
		t.Errorf("fallback times = %+v", got3)
	}
}

// TestDecodeIPFIXWithdraw —— field_count=0 模板撤回（RFC 7011 §3.4.1）。
func TestDecodeIPFIXWithdraw(t *testing.T) {
	tc := NewTemplateCache(0, 0, nil)
	fields := []templateField{{ieOctetDeltaCount, 4}}
	dg := ipfixPacket(1, 1700000000, ipfixTemplateSet(256, fields), ipfixDataSet(256, []byte{0, 0, 0, 5}))
	if got, _, stats, _ := DecodeIPFIX(dg, ipfixExp, tc); len(got) != 1 || stats.Sum() != 0 {
		t.Fatalf("initial: n=%d stats=%+v", len(got), stats)
	}
	// 撤回集：template_id=256 field_count=0
	w := make([]byte, 0, 8)
	w = binary.BigEndian.AppendUint16(w, ipfixTemplateSetID)
	w = binary.BigEndian.AppendUint16(w, 8)
	w = binary.BigEndian.AppendUint16(w, 256)
	w = binary.BigEndian.AppendUint16(w, 0)
	dg2 := ipfixPacket(1, 1700000001, w, ipfixDataSet(256, []byte{0, 0, 0, 6}))
	got, _, stats, _ := DecodeIPFIX(dg2, ipfixExp, tc)
	if len(got) != 0 || stats.SkippedDataSets != 1 {
		t.Fatalf("after withdraw: n=%d stats=%+v", len(got), stats)
	}
}

// TestDecodeIPFIXMalformed —— 畸形包：头截断/坏版本/set 越界/模板截断。
func TestDecodeIPFIXMalformed(t *testing.T) {
	tc := NewTemplateCache(0, 0, nil)
	if _, _, _, err := DecodeIPFIX(make([]byte, 8), ipfixExp, tc); err == nil {
		t.Error("short header must fail")
	}
	bad := make([]byte, ipfixHeaderLen)
	binary.BigEndian.PutUint16(bad[0:2], 9)
	if _, _, _, err := DecodeIPFIX(bad, ipfixExp, tc); err == nil {
		t.Error("version 9 must fail in ipfix decoder")
	}
	// set 长度越界
	over := make([]byte, 4)
	binary.BigEndian.PutUint16(over[2:4], 5000)
	if _, _, stats, _ := DecodeIPFIX(ipfixPacket(1, 0, over), ipfixExp, tc); stats.BadSets != 1 {
		t.Errorf("overflow set: %+v", stats)
	}
	// 模板说明符截断
	trunc := make([]byte, 0, 12)
	trunc = binary.BigEndian.AppendUint16(trunc, ipfixTemplateSetID)
	trunc = binary.BigEndian.AppendUint16(trunc, 12)
	trunc = binary.BigEndian.AppendUint16(trunc, 256)
	trunc = binary.BigEndian.AppendUint16(trunc, 2) // 声称 2 字段只有 1 个
	trunc = binary.BigEndian.AppendUint16(trunc, 1)
	trunc = binary.BigEndian.AppendUint16(trunc, 4)
	if _, _, stats, _ := DecodeIPFIX(ipfixPacket(1, 0, trunc), ipfixExp, tc); stats.BadSets != 1 {
		t.Errorf("truncated template: %+v", stats)
	}
	// 数据记录截断（模板定长 8B，set 里只有 4B）
	fields := []templateField{{ieOctetDeltaCount, 4}, {iePacketDeltaCount, 4}}
	dg := ipfixPacket(1, 0, ipfixTemplateSet(256, fields), ipfixDataSet(256, []byte{0, 0, 0, 1}))
	if _, _, stats, _ := DecodeIPFIX(dg, ipfixExp, tc); stats.SkippedDataSets != 1 {
		t.Errorf("truncated record: %+v", stats)
	}
	// options 模板 scope > field_count 非法
	badOpt := make([]byte, 0, 4+6+8)
	badOpt = binary.BigEndian.AppendUint16(badOpt, ipfixOptionsSetID)
	badOpt = binary.BigEndian.AppendUint16(badOpt, uint16(4+6+8))
	badOpt = binary.BigEndian.AppendUint16(badOpt, 258)
	badOpt = binary.BigEndian.AppendUint16(badOpt, 1)
	badOpt = binary.BigEndian.AppendUint16(badOpt, 2) // scope > fields
	badOpt = binary.BigEndian.AppendUint16(badOpt, 10)
	badOpt = binary.BigEndian.AppendUint16(badOpt, 4)
	badOpt = binary.BigEndian.AppendUint16(badOpt, 160)
	badOpt = binary.BigEndian.AppendUint16(badOpt, 8)
	if _, _, stats, _ := DecodeIPFIX(ipfixPacket(1, 0, badOpt), ipfixExp, tc); stats.BadSets != 1 {
		t.Errorf("bad options template: %+v", stats)
	}
}

// TestDecodeIPFIXV6 —— IE 27/28 v6 数据模板（与重编码 v6 模板同构）。
func TestDecodeIPFIXV6(t *testing.T) {
	tc := NewTemplateCache(0, 0, nil)
	fields := []templateField{
		{ieFlowStartMilliseconds, 8}, {ieFlowEndMilliseconds, 8},
		{ieSourceIPv6Address, 16}, {ieDestinationIPv6Address, 16},
		{ieSourceTransportPort, 2}, {ieDestinationTransportPort, 2},
		{ieProtocolIdentifier, 1},
		{iePacketDeltaCount, 8}, {ieOctetDeltaCount, 8},
		{ieTCPControlBits, 1}, {ieIPClassOfService, 1},
		{ieIngressInterface, 4}, {ieEgressInterface, 4},
		{ieBGPSourceASNumber, 4}, {ieBGPDestinationASNumber, 4},
	}
	rec := make([]byte, 0, 80)
	src := [16]byte{0x20, 0x01, 0xdb, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	dst := [16]byte{0x20, 0x01, 0xdb, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}
	rec = binary.BigEndian.AppendUint64(rec, 1700000000000)
	rec = binary.BigEndian.AppendUint64(rec, 1700000000000)
	rec = append(rec, src[:]...)
	rec = append(rec, dst[:]...)
	rec = binary.BigEndian.AppendUint16(rec, 100)
	rec = binary.BigEndian.AppendUint16(rec, 200)
	rec = append(rec, 6)
	rec = binary.BigEndian.AppendUint64(rec, 1)
	rec = binary.BigEndian.AppendUint64(rec, 2)
	rec = append(rec, 0, 0)
	rec = binary.BigEndian.AppendUint32(rec, 0)
	rec = binary.BigEndian.AppendUint32(rec, 0)
	rec = binary.BigEndian.AppendUint32(rec, 0)
	rec = binary.BigEndian.AppendUint32(rec, 0)

	dg := ipfixPacket(1, 1700000000, ipfixTemplateSet(257, fields), ipfixDataSet(257, rec))
	got, _, stats, err := DecodeIPFIX(dg, ipfixExp, tc)
	if err != nil || stats.Sum() != 0 || len(got) != 1 {
		t.Fatalf("decode: err=%v stats=%+v n=%d", err, stats, len(got))
	}
	if got[0].IPVersion != 6 || got[0].SrcIP != src || got[0].DstIP != dst || got[0].SrcPort != 100 {
		t.Errorf("v6 rec = %+v", got[0])
	}
}

// TestDecodeIPCachedScope —— 同包不同 obsDomain 数据集：模板作用域隔离。
func TestDecodeIPCachedScope(t *testing.T) {
	tc := NewTemplateCache(0, 0, nil)
	fields := []templateField{{ieOctetDeltaCount, 4}}
	dg := ipfixPacket(1, 0, ipfixTemplateSet(256, fields), ipfixDataSet(256, []byte{0, 0, 0, 5}))
	if _, _, stats, _ := DecodeIPFIX(dg, ipfixExp, tc); stats.Sum() != 0 {
		t.Fatalf("initial: %+v", stats)
	}
	// 相同模板 id 但 obsDomain=2：无模板 → 跳过
	dg2 := ipfixPacket(2, 0, ipfixDataSet(256, []byte{0, 0, 0, 5}))
	if _, _, stats, _ := DecodeIPFIX(dg2, ipfixExp, tc); stats.SkippedDataSets != 1 {
		t.Errorf("scope isolation: %+v", stats)
	}
}
