package flowcodec

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"time"
)

// —— sFlow v5 测试报文构造（任务一） ——

func sflowHeader(agentV4 [4]byte, numSamples uint32) []byte {
	h := make([]byte, 0, 28)
	h = binary.BigEndian.AppendUint32(h, 5) // version
	h = binary.BigEndian.AppendUint32(h, 1) // agent address type: IPv4
	h = append(h, agentV4[:]...)
	h = binary.BigEndian.AppendUint32(h, 66) // sub agent id
	h = binary.BigEndian.AppendUint32(h, 77) // sequence
	h = binary.BigEndian.AppendUint32(h, 86400000)
	h = binary.BigEndian.AppendUint32(h, numSamples)
	return h
}

func sflowSample(format uint32, body []byte) []byte {
	s := make([]byte, 0, 8+len(body))
	s = binary.BigEndian.AppendUint32(s, format)
	s = binary.BigEndian.AppendUint32(s, uint32(len(body)))
	return append(s, body...)
}

// sflowFlowSampleBody —— flow sample 正文（sFlow spec §5.2）。
func sflowFlowSampleBody(rate uint32, records [][]byte) []byte {
	b := make([]byte, 0, 28)
	b = binary.BigEndian.AppendUint32(b, 1)       // sequence
	b = binary.BigEndian.AppendUint32(b, 2<<24|1) // source_id
	b = binary.BigEndian.AppendUint32(b, rate)
	b = binary.BigEndian.AppendUint32(b, 1000) // sample_pool
	b = binary.BigEndian.AppendUint32(b, 0)    // drops
	b = binary.BigEndian.AppendUint32(b, 5)    // input ifIndex
	b = binary.BigEndian.AppendUint32(b, 9)    // output ifIndex
	b = binary.BigEndian.AppendUint32(b, uint32(len(records)))
	for _, r := range records {
		b = append(b, r...)
	}
	return b
}

// sflowExpandedFlowSampleBody —— expanded flow sample 正文（sFlow spec §5.3）。
func sflowExpandedFlowSampleBody(rate uint32, records [][]byte) []byte {
	b := make([]byte, 0, 40)
	b = binary.BigEndian.AppendUint32(b, 1) // sequence
	b = binary.BigEndian.AppendUint32(b, 0) // source_id_type
	b = binary.BigEndian.AppendUint32(b, 1) // source_id_index
	b = binary.BigEndian.AppendUint32(b, rate)
	b = binary.BigEndian.AppendUint32(b, 1000) // sample_pool
	b = binary.BigEndian.AppendUint32(b, 0)    // drops
	b = binary.BigEndian.AppendUint32(b, 0)    // input format
	b = binary.BigEndian.AppendUint32(b, 5)    // input value
	b = binary.BigEndian.AppendUint32(b, 0)    // output format
	b = binary.BigEndian.AppendUint32(b, 9)    // output value
	b = binary.BigEndian.AppendUint32(b, uint32(len(records)))
	for _, r := range records {
		b = append(b, r...)
	}
	return b
}

func sflowRecord(format uint32, data []byte) []byte {
	r := make([]byte, 0, 8+len(data))
	r = binary.BigEndian.AppendUint32(r, format)
	r = binary.BigEndian.AppendUint32(r, uint32(len(data)))
	return append(r, data...)
}

// rawHeaderRecord —— raw packet header 流记录（format 1）。
func rawHeaderRecord(headerProtocol uint32, frame []byte, frameLen uint32) []byte {
	d := make([]byte, 0, 16+len(frame))
	d = binary.BigEndian.AppendUint32(d, headerProtocol)
	d = binary.BigEndian.AppendUint32(d, frameLen)
	d = binary.BigEndian.AppendUint32(d, 0) // stripped
	d = binary.BigEndian.AppendUint32(d, uint32(len(frame)))
	d = append(d, frame...)
	return sflowRecord(sFlowRecordRawHeader, d)
}

// ethIPv4TCPFrame —— Ethernet + IPv4 + TCP 帧构造。
func ethIPv4TCPFrame(srcIP, dstIP [4]byte, sport, dport uint16, flags byte) []byte {
	ip := make([]byte, 20)
	ip[0] = 0x45 // v4 ihl=5
	ip[1] = 0x10 // tos
	binary.BigEndian.PutUint16(ip[2:4], 40)
	ip[8] = 64
	ip[9] = 6 // tcp
	copy(ip[12:16], srcIP[:])
	copy(ip[16:20], dstIP[:])
	tcp := make([]byte, 20)
	binary.BigEndian.PutUint16(tcp[0:2], sport)
	binary.BigEndian.PutUint16(tcp[2:4], dport)
	tcp[12] = 5 << 4
	tcp[13] = flags
	return append(ethHeader(0x0800), append(ip, tcp...)...)
}

// ethIPv6UDPFrame —— Ethernet + IPv6 + UDP 帧构造。
func ethIPv6UDPFrame(srcIP, dstIP [16]byte, sport, dport uint16) []byte {
	ip := make([]byte, 40)
	ip[0] = 0x60
	binary.BigEndian.PutUint16(ip[4:6], 8) // payload len
	ip[6] = 17                             // udp
	copy(ip[8:24], srcIP[:])
	copy(ip[24:40], dstIP[:])
	udp := make([]byte, 8)
	binary.BigEndian.PutUint16(udp[0:2], sport)
	binary.BigEndian.PutUint16(udp[2:4], dport)
	return append(ethHeader(0x86DD), append(ip, udp...)...)
}

func ethHeader(ethertype uint16) []byte {
	f := make([]byte, 14)
	for i := 0; i < 6; i++ {
		f[i] = byte(i + 1)
		f[6+i] = byte(i + 10)
	}
	binary.BigEndian.PutUint16(f[12:14], ethertype)
	return f
}

// ethVLANIPv4Frame —— 802.1Q 单层 VLAN。
func ethVLANIPv4Frame(srcIP, dstIP [4]byte) []byte {
	f := ethHeader(0x8100)
	f = append(f, 0, 100, 0x08, 0x00) // TCI + 内层 ethertype IPv4
	ip := make([]byte, 20)
	ip[0] = 0x45
	ip[9] = 17 // udp
	copy(ip[12:16], srcIP[:])
	copy(ip[16:20], dstIP[:])
	udp := make([]byte, 8)
	binary.BigEndian.PutUint16(udp[0:2], 53)
	return append(f, append(ip, udp...)...)
}

var (
	sfExp = netip.MustParseAddr("192.168.1.1")
	sfNow = time.Unix(1700000000, 0)
)

// TestDecodeSFlowIPv4TCP —— 正常流：flow sample + raw header（Ethernet/IPv4/TCP）。
func TestDecodeSFlowIPv4TCP(t *testing.T) {
	var src, dst [4]byte
	copy(src[:], []byte{10, 1, 1, 1})
	copy(dst[:], []byte{10, 1, 1, 2})
	frame := ethIPv4TCPFrame(src, dst, 44321, 443, 0x12)
	dg := append(sflowHeader([4]byte{192, 168, 1, 1}, 1),
		sflowSample(sFlowFlowSample, sflowFlowSampleBody(10, [][]byte{rawHeaderRecord(1, frame, uint32(len(frame)+18))}))...)

	recs, h, stats, err := DecodeSFlowV5(dg, sfExp, sfNow)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if h.Version != 5 || h.NumSamples != 1 || h.SubAgentID != 66 {
		t.Errorf("header = %+v", h)
	}
	if h.Agent[10] != 0xff || h.Agent[12] != 192 {
		t.Errorf("agent = %v", h.Agent)
	}
	if stats.Sum() != 0 || len(recs) != 1 {
		t.Fatalf("stats=%+v n=%d", stats, len(recs))
	}
	rec := recs[0]
	if rec.Exporter != "192.168.1.1" || rec.IPVersion != 4 {
		t.Errorf("rec = %+v", rec)
	}
	if rec.SrcPort != 44321 || rec.DstPort != 443 || rec.Proto != 6 || rec.TCPFlags != 0x12 {
		t.Errorf("l4 = %+v", rec)
	}
	if rec.SrcIP != v4Mapped(0x0A010101) || rec.DstIP != v4Mapped(0x0A010102) {
		t.Errorf("addrs = %v %v", rec.SrcIP, rec.DstIP)
	}
	if rec.SampleRate != 10 || rec.Packets != 1 {
		t.Errorf("sampling = %+v", rec)
	}
	if rec.Bytes != uint64(len(frame)+18) {
		t.Errorf("bytes = %d (want frame_length)", rec.Bytes)
	}
	if rec.InIf != 5 || rec.OutIf != 9 {
		t.Errorf("ifindex = %d/%d", rec.InIf, rec.OutIf)
	}
	if rec.TimeStartMs != sfNow.UnixMilli() || rec.TimeEndMs != rec.TimeStartMs {
		t.Errorf("times = %d/%d", rec.TimeStartMs, rec.TimeEndMs)
	}
}

// TestDecodeSFlowIPv6UDP —— IPv6/UDP 经以太网帧解析。
func TestDecodeSFlowIPv6UDP(t *testing.T) {
	var src, dst [16]byte
	copy(src[:], []byte{0x20, 0x01, 0xdb, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})
	copy(dst[:], []byte{0x20, 0x01, 0xdb, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2})
	frame := ethIPv6UDPFrame(src, dst, 5353, 53)
	dg := append(sflowHeader([4]byte{10, 0, 0, 1}, 1),
		sflowSample(sFlowFlowSample, sflowFlowSampleBody(1, [][]byte{rawHeaderRecord(1, frame, uint32(len(frame)))}))...)

	recs, _, stats, err := DecodeSFlowV5(dg, sfExp, sfNow)
	if err != nil || stats.Sum() != 0 {
		t.Fatalf("decode: err=%v stats=%+v", err, stats)
	}
	if len(recs) != 1 {
		t.Fatalf("records = %d", len(recs))
	}
	rec := recs[0]
	if rec.IPVersion != 6 || rec.Proto != 17 || rec.SrcPort != 5353 || rec.DstPort != 53 {
		t.Errorf("rec = %+v", rec)
	}
	if rec.SrcIP != src || rec.DstIP != dst {
		t.Errorf("addrs = %v %v", rec.SrcIP, rec.DstIP)
	}
}

// TestDecodeSFlowVLAN —— 802.1Q VLAN 剥层。
func TestDecodeSFlowVLAN(t *testing.T) {
	var src, dst [4]byte
	copy(src[:], []byte{10, 2, 2, 1})
	copy(dst[:], []byte{10, 2, 2, 2})
	frame := ethVLANIPv4Frame(src, dst)
	dg := append(sflowHeader([4]byte{10, 0, 0, 1}, 1),
		sflowSample(sFlowFlowSample, sflowFlowSampleBody(100, [][]byte{rawHeaderRecord(1, frame, 200)}))...)
	recs, _, stats, err := DecodeSFlowV5(dg, sfExp, sfNow)
	if err != nil || stats.Sum() != 0 || len(recs) != 1 {
		t.Fatalf("decode: err=%v stats=%+v n=%d", err, stats, len(recs))
	}
	if recs[0].Proto != 17 || recs[0].SrcPort != 53 || recs[0].SampleRate != 100 || recs[0].Bytes != 200 {
		t.Errorf("rec = %+v", recs[0])
	}
}

// TestDecodeSFlowRawIPv4Header —— header_protocol=11 裸 IPv4 报文头（无以太网）。
func TestDecodeSFlowRawIPv4Header(t *testing.T) {
	var src, dst [4]byte
	copy(src[:], []byte{10, 3, 3, 1})
	copy(dst[:], []byte{10, 3, 3, 2})
	frame := ethIPv4TCPFrame(src, dst, 1, 2, 0x04)[14:] // 去掉以太网头
	dg := append(sflowHeader([4]byte{10, 0, 0, 1}, 1),
		sflowSample(sFlowFlowSample, sflowFlowSampleBody(5, [][]byte{rawHeaderRecord(11, frame, 500)}))...)
	recs, _, stats, err := DecodeSFlowV5(dg, sfExp, sfNow)
	if err != nil || stats.Sum() != 0 || len(recs) != 1 {
		t.Fatalf("decode: err=%v stats=%+v n=%d", err, stats, len(recs))
	}
	if recs[0].SrcPort != 1 || recs[0].DstPort != 2 || recs[0].Proto != 6 || recs[0].Bytes != 500 {
		t.Errorf("rec = %+v", recs[0])
	}
}

// TestDecodeSFlowIPv4DataRecord —— IPv4 data 流记录（format 3）直接取字段。
func TestDecodeSFlowIPv4DataRecord(t *testing.T) {
	d := make([]byte, 0, 40)
	d = binary.BigEndian.AppendUint32(d, 0x0A040401) // src
	d = binary.BigEndian.AppendUint32(d, 0x0A040402) // dst
	d = binary.BigEndian.AppendUint32(d, 0)          // next hop
	d = binary.BigEndian.AppendUint32(d, 24)         // src mask
	d = binary.BigEndian.AppendUint32(d, 24)         // dst mask
	d = binary.BigEndian.AppendUint32(d, 17)         // protocol
	d = binary.BigEndian.AppendUint32(d, 1000)       // src port
	d = binary.BigEndian.AppendUint32(d, 2000)       // dst port
	d = binary.BigEndian.AppendUint32(d, 0)          // tcp flags
	d = binary.BigEndian.AppendUint32(d, 0x10)       // tos
	dg := append(sflowHeader([4]byte{10, 0, 0, 1}, 1),
		sflowSample(sFlowFlowSample, sflowFlowSampleBody(3, [][]byte{sflowRecord(sFlowRecordIPv4Data, d)}))...)
	recs, _, stats, err := DecodeSFlowV5(dg, sfExp, sfNow)
	if err != nil || stats.Sum() != 0 || len(recs) != 1 {
		t.Fatalf("decode: err=%v stats=%+v n=%d", err, stats, len(recs))
	}
	rec := recs[0]
	if rec.IPVersion != 4 || rec.Proto != 17 || rec.SrcPort != 1000 || rec.DstPort != 2000 || rec.TOS != 0x10 {
		t.Errorf("rec = %+v", rec)
	}
	if rec.SrcIP != v4Mapped(0x0A040401) || rec.DstIP != v4Mapped(0x0A040402) {
		t.Errorf("addrs = %v %v", rec.SrcIP, rec.DstIP)
	}
}

// TestDecodeSFlowExpanded —— expanded flow sample（scope 按字段展开）。
func TestDecodeSFlowExpanded(t *testing.T) {
	var src, dst [4]byte
	copy(src[:], []byte{10, 5, 5, 1})
	copy(dst[:], []byte{10, 5, 5, 2})
	frame := ethIPv4TCPFrame(src, dst, 8, 9, 0)
	dg := append(sflowHeader([4]byte{10, 0, 0, 1}, 1),
		sflowSample(sFlowExpandedFlowSample, sflowExpandedFlowSampleBody(7, [][]byte{rawHeaderRecord(1, frame, 100)}))...)
	recs, _, stats, err := DecodeSFlowV5(dg, sfExp, sfNow)
	if err != nil || stats.Sum() != 0 || len(recs) != 1 {
		t.Fatalf("decode: err=%v stats=%+v n=%d", err, stats, len(recs))
	}
	if recs[0].SrcPort != 8 || recs[0].SampleRate != 7 || recs[0].InIf != 5 || recs[0].OutIf != 9 {
		t.Errorf("rec = %+v", recs[0])
	}
}

// TestDecodeSFlowCounterSkipped —— counter sample 与非 IP 样本跳过语义。
func TestDecodeSFlowCounterSkipped(t *testing.T) {
	// counter sample（format 2）：任意 88B 计数块
	counter := make([]byte, 88)
	dg := append(sflowHeader([4]byte{10, 0, 0, 1}, 1), sflowSample(sFlowCounterSample, counter)...)
	recs, _, stats, err := DecodeSFlowV5(dg, sfExp, sfNow)
	if err != nil || len(recs) != 0 || stats.Sum() != 0 {
		t.Fatalf("counter sample: err=%v n=%d stats=%+v", err, len(recs), stats)
	}

	// 非 IP 以太网帧（ARP ethertype 0x0806）：样本内跳过计数
	arp := ethHeader(0x0806)
	arp = append(arp, make([]byte, 28)...)
	dg2 := append(sflowHeader([4]byte{10, 0, 0, 1}, 1),
		sflowSample(sFlowFlowSample, sflowFlowSampleBody(1, [][]byte{rawHeaderRecord(1, arp, 42)}))...)
	recs2, _, stats2, _ := DecodeSFlowV5(dg2, sfExp, sfNow)
	if len(recs2) != 0 || stats2.SkippedRecords != 1 {
		t.Fatalf("arp: n=%d stats=%+v", len(recs2), stats2)
	}
}

// TestDecodeSFlowUnknownSample —— 未知/私有样本类型计 skipped。
func TestDecodeSFlowUnknownSample(t *testing.T) {
	dg := append(sflowHeader([4]byte{10, 0, 0, 1}, 1), sflowSample(7<<12|1, make([]byte, 16))...)
	_, _, stats, err := DecodeSFlowV5(dg, sfExp, sfNow)
	if err != nil || stats.SkippedDataSets != 1 {
		t.Fatalf("stats=%+v err=%v", stats, err)
	}
}

// TestDecodeSFlowMalformed —— 畸形包：头截断/样本长度越界不 panic。
func TestDecodeSFlowMalformed(t *testing.T) {
	if _, _, _, err := DecodeSFlowV5(make([]byte, 10), sfExp, sfNow); err == nil {
		t.Error("truncated header must fail")
	}
	badType := sflowHeader([4]byte{1, 2, 3, 4}, 0)
	binary.BigEndian.PutUint32(badType[4:8], 9) // 非法 agent 地址类型
	if _, _, _, err := DecodeSFlowV5(badType, sfExp, sfNow); err == nil {
		t.Error("bad agent type must fail")
	}
	// 样本长度越界：声称 1000B 实际不足
	bad := append(sflowHeader([4]byte{1, 2, 3, 4}, 1), 0, 0, 0, 1, 0, 0, 3, 232)
	if _, _, stats, err := DecodeSFlowV5(bad, sfExp, sfNow); err != nil || stats.BadSets != 1 {
		t.Errorf("overflow sample: stats=%+v err=%v", stats, err)
	}
	// 记录长度越界：样本内跳过
	var src, dst [4]byte
	copy(src[:], []byte{10, 1, 1, 1})
	copy(dst[:], []byte{10, 1, 1, 2})
	frame := ethIPv4TCPFrame(src, dst, 1, 2, 0)
	rec := rawHeaderRecord(1, frame, 100)
	binary.BigEndian.PutUint32(rec[4:8], 100000) // 记录长度越界
	dg := append(sflowHeader([4]byte{1, 2, 3, 4}, 1),
		sflowSample(sFlowFlowSample, sflowFlowSampleBody(1, [][]byte{rec}))...)
	if _, _, stats, err := DecodeSFlowV5(dg, sfExp, sfNow); err != nil || stats.SkippedRecords != 1 {
		t.Errorf("overflow record: stats=%+v err=%v", stats, err)
	}
}

// TestIsSFlowV5 —— 探测：sFlow v5 与 NetFlow v5/v9/IPFIX 不冲突。
func TestIsSFlowV5(t *testing.T) {
	dg := sflowHeader([4]byte{1, 2, 3, 4}, 0)
	if !IsSFlowV5(dg) {
		t.Error("sflow packet not detected")
	}
	if IsSFlowV5(dg[:10]) {
		t.Error("truncated must not detect")
	}
	bin := make([]byte, 4)
	binary.BigEndian.PutUint32(bin, 6) // 非法版本
	if IsSFlowV5(bin) {
		t.Error("version 6 must not detect")
	}
	if IsSFlowV5(buildV5DatagramForSFlowTest()) {
		t.Error("netflow v5 must not detect as sflow")
	}
	if IsSFlowV5(v9Packet(1)) {
		t.Error("netflow v9 must not detect as sflow")
	}
}

func buildV5DatagramForSFlowTest() []byte {
	dg := make([]byte, V5HeaderLen)
	binary.BigEndian.PutUint16(dg[0:2], 5)
	return dg
}
