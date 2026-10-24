package forwarder

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"time"

	"github.com/SchearLoe/lucidnet/broker/internal/flowcodec"
	"github.com/SchearLoe/lucidnet/shared"
)

func netipParse(s string) netip.Addr { return netip.MustParseAddr(s) }

func v5Records(t *testing.T, n int) []shared.FlowRecord {
	t.Helper()
	recs, _, err := flowcodec.DecodeV5(buildV5(t, n), netipParse("10.1.1.1"))
	if err != nil || len(recs) != n {
		t.Fatalf("decode v5: %v n=%d", err, len(recs))
	}
	return recs
}

// —— 引擎级三协议解码（任务一）：版本探测入口 → 统一记录 → Kafka 目的地 ——

// v9 测试报文构造（flowcodec 测试构造为包内私有，此处独立最小复刻）。
var fwdV9Fields = [][2]uint16{{1, 4}, {2, 4}, {4, 1}, {7, 2}, {8, 4}, {11, 2}, {12, 4}, {22, 4}, {21, 4}}

const fwdV9TemplateID = 1024

func fwdV9Packet(sourceID uint32, sets ...[]byte) []byte {
	var body []byte
	for _, s := range sets {
		body = append(body, s...)
	}
	dg := make([]byte, 20+len(body))
	binary.BigEndian.PutUint16(dg[0:2], 9)
	binary.BigEndian.PutUint32(dg[4:8], 5000)
	binary.BigEndian.PutUint32(dg[8:12], 1700000000)
	binary.BigEndian.PutUint32(dg[16:20], sourceID)
	copy(dg[20:], body)
	return dg
}

func fwdV9TemplateSet() []byte {
	n := 8 + len(fwdV9Fields)*4
	s := make([]byte, 0, n)
	s = binary.BigEndian.AppendUint16(s, 0)
	s = binary.BigEndian.AppendUint16(s, uint16(n))
	s = binary.BigEndian.AppendUint16(s, fwdV9TemplateID)
	s = binary.BigEndian.AppendUint16(s, uint16(len(fwdV9Fields)))
	for _, f := range fwdV9Fields {
		s = binary.BigEndian.AppendUint16(s, f[0])
		s = binary.BigEndian.AppendUint16(s, f[1])
	}
	return s
}

func fwdV9DataSet() []byte {
	r := make([]byte, 29)
	binary.BigEndian.PutUint32(r[0:4], 1500)
	binary.BigEndian.PutUint32(r[4:8], 3)
	r[8] = 6
	binary.BigEndian.PutUint16(r[9:11], 1000)
	binary.BigEndian.PutUint32(r[11:15], 0x0A000001)
	binary.BigEndian.PutUint16(r[15:17], 80)
	binary.BigEndian.PutUint32(r[17:21], 0x0A000002)
	binary.BigEndian.PutUint32(r[21:25], 1000)
	binary.BigEndian.PutUint32(r[25:29], 2000)
	s := make([]byte, 0, 33)
	s = binary.BigEndian.AppendUint16(s, fwdV9TemplateID)
	s = binary.BigEndian.AppendUint16(s, 33)
	return append(s, r...)
}

// fwdSFlowDatagram —— sFlow v5：flow sample + raw header（Ethernet/IPv4/TCP，rate 10）。
func fwdSFlowDatagram() []byte {
	ip := make([]byte, 20)
	ip[0] = 0x45
	ip[9] = 6
	binary.BigEndian.PutUint32(ip[12:16], 0x0A010101)
	binary.BigEndian.PutUint32(ip[16:20], 0x0A010102)
	tcp := make([]byte, 20)
	binary.BigEndian.PutUint16(tcp[0:2], 44321)
	binary.BigEndian.PutUint16(tcp[2:4], 443)
	tcp[13] = 0x12
	eth := make([]byte, 14)
	binary.BigEndian.PutUint16(eth[12:14], 0x0800)
	frame := append(eth, append(ip, tcp...)...)

	hdr := make([]byte, 0, 16+len(frame))
	hdr = binary.BigEndian.AppendUint32(hdr, 1) // header_protocol ethernet
	hdr = binary.BigEndian.AppendUint32(hdr, uint32(len(frame)))
	hdr = binary.BigEndian.AppendUint32(hdr, 0)
	hdr = binary.BigEndian.AppendUint32(hdr, uint32(len(frame)))
	hdr = append(hdr, frame...)
	rec := make([]byte, 0, 8+len(hdr))
	rec = binary.BigEndian.AppendUint32(rec, 1) // format raw header
	rec = binary.BigEndian.AppendUint32(rec, uint32(len(hdr)))
	rec = append(rec, hdr...)

	body := make([]byte, 0, 28+len(rec))
	body = binary.BigEndian.AppendUint32(body, 1) // sequence
	body = binary.BigEndian.AppendUint32(body, 2<<24|1)
	body = binary.BigEndian.AppendUint32(body, 10) // sampling rate
	body = binary.BigEndian.AppendUint32(body, 0)
	body = binary.BigEndian.AppendUint32(body, 0)
	body = binary.BigEndian.AppendUint32(body, 5)
	body = binary.BigEndian.AppendUint32(body, 9)
	body = binary.BigEndian.AppendUint32(body, 1)
	body = append(body, rec...)

	dg := make([]byte, 0, 28+8+len(body))
	dg = binary.BigEndian.AppendUint32(dg, 5) // version
	dg = binary.BigEndian.AppendUint32(dg, 1) // agent v4
	dg = binary.BigEndian.AppendUint32(dg, 0x0A010101)
	dg = binary.BigEndian.AppendUint32(dg, 66)
	dg = binary.BigEndian.AppendUint32(dg, 77)
	dg = binary.BigEndian.AppendUint32(dg, 86400000)
	dg = binary.BigEndian.AppendUint32(dg, 1) // num samples
	dg = binary.BigEndian.AppendUint32(dg, 1) // sample format: flow sample
	dg = binary.BigEndian.AppendUint32(dg, uint32(len(body)))
	return append(dg, body...)
}

// TestEngineDecodeV9 —— v9 模板集先行 + 数据集 → Kafka 记录（exporter/字段正确）。
func TestEngineDecodeV9(t *testing.T) {
	sink := &stubKafka{}
	e := NewEngine(sink, &testCounters{})
	defer e.Close()
	_, _ = e.ApplyRules(&RulesSnapshot{
		Version: 1,
		Rules: []Rule{{
			ID: 11, Enabled: true,
			Match:        Match{Exporters: []string{"10.1.1.1"}},
			Destinations: []Destination{{Topic: "flows.raw", Protocol: ProtocolKafka}},
		}},
	})
	e.Process(fwdV9Packet(7, fwdV9TemplateSet(), fwdV9DataSet()), exporterOf("10.1.1.1"))
	if len(sink.msgs) != 1 {
		t.Fatalf("msgs = %d", len(sink.msgs))
	}
	rec, err := flowcodec.UnmarshalFlowRecord(sink.msgs[0].val)
	if err != nil {
		t.Fatalf("value decode: %v", err)
	}
	if rec.Exporter != "10.1.1.1" || rec.Proto != 6 || rec.SrcPort != 1000 || rec.Bytes != 1500 {
		t.Errorf("rec = %+v", rec)
	}
	if rec.SampleRate != 1 {
		t.Errorf("sample_rate = %d", rec.SampleRate)
	}
}

// TestEngineDecodeIPFIX —— IPFIX 报文（自有编码器输出）→ Kafka 记录。
func TestEngineDecodeIPFIX(t *testing.T) {
	sink := &stubKafka{}
	e := NewEngine(sink, &testCounters{})
	defer e.Close()
	_, _ = e.ApplyRules(&RulesSnapshot{
		Version: 1,
		Rules: []Rule{{
			ID: 12, Enabled: true,
			Match:        Match{Exporters: []string{"10.1.1.1"}},
			Destinations: []Destination{{Topic: "flows.raw", Protocol: ProtocolKafka}},
		}},
	})
	enc := flowcodec.NewIPFIXEncoder(77, time.Hour)
	now := time.Unix(1700000000, 0)
	rec := v5Records(t, 1)[0]
	rec.TimeStartMs = now.UnixMilli()
	rec.TimeEndMs = now.Add(time.Second).UnixMilli()
	enc.Append(rec)
	msg := enc.Flush(now, flowcodec.IPFIXAlgoDeterministic, 1)
	if msg == nil {
		t.Fatal("flush empty")
	}
	e.Process(msg, exporterOf("10.1.1.1"))
	if len(sink.msgs) != 1 {
		t.Fatalf("msgs = %d", len(sink.msgs))
	}
	got, err := flowcodec.UnmarshalFlowRecord(sink.msgs[0].val)
	if err != nil {
		t.Fatalf("value decode: %v", err)
	}
	if got.Bytes != rec.Bytes || got.SrcPort != rec.SrcPort || got.Proto != rec.Proto {
		t.Errorf("rec mismatch: %+v", got)
	}
}

// TestEngineDecodeSFlow —— sFlow v5 → Kafka 记录（采样率/五元组语义）。
func TestEngineDecodeSFlow(t *testing.T) {
	sink := &stubKafka{}
	e := NewEngine(sink, &testCounters{})
	defer e.Close()
	_, _ = e.ApplyRules(&RulesSnapshot{
		Version: 1,
		Rules: []Rule{{
			ID: 13, Enabled: true,
			Match:        Match{Exporters: []string{"10.1.1.1"}},
			Destinations: []Destination{{Topic: "flows.raw", Protocol: ProtocolKafka}},
		}},
	})
	dg := fwdSFlowDatagram()
	if !flowcodec.IsSFlowV5(dg) {
		t.Fatal("sflow not detected")
	}
	e.Process(dg, exporterOf("10.1.1.1"))
	if len(sink.msgs) != 1 {
		t.Fatalf("msgs = %d", len(sink.msgs))
	}
	rec, err := flowcodec.UnmarshalFlowRecord(sink.msgs[0].val)
	if err != nil {
		t.Fatalf("value decode: %v", err)
	}
	if rec.IPVersion != 4 || rec.Proto != 6 || rec.SrcPort != 44321 || rec.DstPort != 443 {
		t.Errorf("rec = %+v", rec)
	}
	if rec.SampleRate != 10 || rec.Packets != 1 {
		t.Errorf("sampling semantics: rate=%d packets=%d", rec.SampleRate, rec.Packets)
	}
}

// TestEngineDecodeTemplateMissing —— 模板缺失场景：数据集跳过 + 解码错误计数，
// 模板学习后恢复。
func TestEngineDecodeTemplateMissing(t *testing.T) {
	sink := &stubKafka{}
	tc := &testCounters{}
	e := NewEngine(sink, tc)
	defer e.Close()
	_, _ = e.ApplyRules(&RulesSnapshot{
		Version: 1,
		Rules: []Rule{{
			ID: 14, Enabled: true,
			Match:        Match{Exporters: []string{"10.1.1.1"}},
			Destinations: []Destination{{Topic: "flows.raw", Protocol: ProtocolKafka}},
		}},
	})
	// 数据集先行（模板未学）→ 跳过计数，无产出
	e.Process(fwdV9Packet(7, fwdV9DataSet()), exporterOf("10.1.1.1"))
	if tc.decodeErr != 1 || len(sink.msgs) != 0 {
		t.Fatalf("missing template: decodeErr=%d msgs=%d", tc.decodeErr, len(sink.msgs))
	}
	// 模板学习 → 后续数据集解码
	e.Process(fwdV9Packet(7, fwdV9TemplateSet()), exporterOf("10.1.1.1"))
	e.Process(fwdV9Packet(7, fwdV9DataSet()), exporterOf("10.1.1.1"))
	if len(sink.msgs) != 1 {
		t.Fatalf("after learn: msgs=%d decodeErr=%d", len(sink.msgs), tc.decodeErr)
	}
}

// —— 会话重建重放（任务二）：sig 变更 → 新会话继承旧会话缓冲并按序续传 ——

// testDestSig —— 按测试目的地处参计算 e.dests 键。
func testDestSig(ruleID int32, idx int, addr string, proto Protocol, rs *Resample) string {
	d := &Destination{Addr: addr, Protocol: proto, Resample: rs}
	return sig(ruleID, idx, d)
}

func (e *Engine) lookupDestForTest(ruleID int32, idx int, addr string, proto Protocol, rs *Resample) runtimeDest {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.dests[testDestSig(ruleID, idx, addr, proto, rs)]
}

func (s *udpSender) replayLenForTest() int {
	if s.replay == nil {
		return 0
	}
	s.order.Lock()
	defer s.order.Unlock()
	return s.replay.len()
}

// forceDown —— 确定性地标记目的地 down：直写健康位后短窗复核，规避 pre-down
// 报文仍在途的 recordOK 竞争（恢复后无写飞行，第二次必生效）。
func forceDown(t *testing.T, s *udpSender) {
	t.Helper()
	for i := 0; i < 50; i++ {
		s.mu.Lock()
		s.down = true
		s.mu.Unlock()
		time.Sleep(2 * time.Millisecond)
		if s.IsDown() {
			return
		}
	}
	t.Fatal("cannot force sender down")
}

// TestEngineSessionRebuildReplay —— 同一逻辑目的地（同 addr，resample 变更触发
// sig 变更）：down 期间缓冲的报文经 stash 移交新会话，先于新数据按序送达。
func TestEngineSessionRebuildReplay(t *testing.T) {
	sink := newUDPSink(t)
	e := NewEngine(nil, &testCounters{}) // 默认重放策略 5s/512MB
	defer e.Close()

	mk := func(ver uint64, rate uint32) *RulesSnapshot {
		return &RulesSnapshot{
			Version: ver,
			Rules: []Rule{{
				ID: 21, Enabled: true,
				Match:        Match{Exporters: []string{"10.1.1.1"}},
				Destinations: []Destination{{Addr: sink.addr, Protocol: ProtocolIPFIX, Resample: &Resample{Mode: ResampleDeterministic, Rate: rate}}},
			}},
		}
	}
	if _, verrs := e.ApplyRules(mk(1, 1)); len(verrs) > 0 {
		t.Fatalf("verrs: %v", verrs)
	}
	// 先触发一次目的地惰性构建（healthy 流量直发，吸收掉）
	e.Process(buildV5(t, 25), exporterOf("10.1.1.1"))
	_ = sink.recv(t)

	rs := &Resample{Mode: ResampleDeterministic, Rate: 1}
	pd := e.lookupDestForTest(21, 0, sink.addr, ProtocolIPFIX, rs).(*proxyDest)
	forceDown(t, pd.sender)

	// down 期间两包记录进入会话编码 → 数据报级缓冲（seq 0、1）
	e.Process(buildV5(t, 25), exporterOf("10.1.1.1"))
	e.Process(buildV5(t, 25), exporterOf("10.1.1.1"))
	if got := pd.sender.replayLenForTest(); got != 2 {
		t.Fatalf("buffered = %d (want 2)", got)
	}

	// 热更新：resample 1→2 → sig 变更 → 旧会话缓冲移交新会话（同 addr 同 key）
	if _, verrs := e.ApplyRules(mk(2, 2)); len(verrs) > 0 {
		t.Fatalf("verrs2: %v", verrs)
	}
	// 新流量触发新会话建立（up 态）→ 装入继承缓冲 → 旧数据先发、新数据后发
	e.Process(buildV5(t, 25), exporterOf("10.1.1.1"))

	m1, m2, m3 := sink.recv(t), sink.recv(t), sink.recv(t)
	for i, m := range [][]byte{m1, m2, m3} {
		if binary.BigEndian.Uint16(m[0:2]) != 10 {
			t.Fatalf("msg %d not ipfix", i)
		}
	}
	seq := func(m []byte) uint32 { return binary.BigEndian.Uint32(m[8:12]) }
	// IPFIX sequence = 累计数据记录数：down 前首包 seq=25 已直发；down 期间缓冲的
	// 两包（50/75）按序重放，新会话首包（rate=2 → ~12 记录，seq=12）随后。
	if seq(m1) != 50 || seq(m2) != 75 || seq(m3) != 12 {
		t.Fatalf("replay order by sequence: %d/%d/%d (want 50/75/12：旧会话缓冲先于新会话)", seq(m1), seq(m2), seq(m3))
	}
}

// TestEngineReplayAddrChangeNoTransfer —— 目的地地址变更（ReplayKey 变化）：
// 旧缓冲不跨目的地迁移，随旧会话关闭清空。
func TestEngineReplayAddrChangeNoTransfer(t *testing.T) {
	sink1 := newUDPSink(t)
	sink2 := newUDPSink(t)
	e := NewEngine(nil, &testCounters{})
	defer e.Close()

	mk := func(addr string, ver uint64) *RulesSnapshot {
		return &RulesSnapshot{
			Version: ver,
			Rules: []Rule{{
				ID: 22, Enabled: true,
				Match:        Match{Exporters: []string{"10.1.1.1"}},
				Destinations: []Destination{{Addr: addr, Protocol: ProtocolIPFIX}},
			}},
		}
	}
	if _, verrs := e.ApplyRules(mk(sink1.addr, 1)); len(verrs) > 0 {
		t.Fatalf("verrs: %v", verrs)
	}
	e.Process(buildV5(t, 25), exporterOf("10.1.1.1"))
	_ = sink1.recv(t) // 惰性构建期流量
	pd := e.lookupDestForTest(22, 0, sink1.addr, ProtocolIPFIX, nil).(*proxyDest)
	forceDown(t, pd.sender)
	e.Process(buildV5(t, 25), exporterOf("10.1.1.1"))
	if pd.sender.replayLenForTest() != 1 {
		t.Fatalf("buffered = %d", pd.sender.replayLenForTest())
	}

	if _, verrs := e.ApplyRules(mk(sink2.addr, 2)); len(verrs) > 0 {
		t.Fatalf("verrs2: %v", verrs)
	}
	e.Process(buildV5(t, 25), exporterOf("10.1.1.1"))
	// 新目的地只收到新会话数据（seq=25，无继承缓冲）；旧目的地不再有任何输出
	m := sink2.recv(t)
	if binary.BigEndian.Uint32(m[8:12]) != 25 {
		t.Fatalf("new dest first message must be fresh session: seq=%d", binary.BigEndian.Uint32(m[8:12]))
	}
	_ = sink1.conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	buf := make([]byte, 1500)
	if _, _, err := sink1.conn.ReadFrom(buf); err == nil {
		t.Error("old dest must not receive after addr change")
	}
}

// TestEnginePruneReplayStash —— 暂存区窗口老化（语义直测）。
func TestEnginePruneReplayStash(t *testing.T) {
	e := NewEngine(nil, &testCounters{})
	base := time.Now()
	e.now = func() time.Time { return base }
	e.replayStash["1|a"] = []replayItem{
		{data: dgOf(1, 8), at: base.Add(-10 * time.Second)}, // 超窗
		{data: dgOf(2, 8), at: base.Add(-1 * time.Second)},  // 窗内
	}
	e.replayStash["2|b"] = []replayItem{
		{data: dgOf(3, 8), at: base.Add(-30 * time.Second)}, // 整键超窗
	}
	e.mu.Lock()
	e.pruneReplayStashLocked()
	e.mu.Unlock()
	if len(e.replayStash) != 1 || len(e.replayStash["1|a"]) != 1 {
		t.Fatalf("stash after prune = %#v", e.replayStash)
	}
}
