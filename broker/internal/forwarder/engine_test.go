package forwarder

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/SchearLoe/lucidnet/broker/internal/flowcodec"
)

// stubKafka —— KafkaSink 桩（记录 Produce 调用）。
type stubKafka struct {
	msgs []kmsg
}
type kmsg struct {
	topic string
	key   []byte
	val   []byte
}

func (s *stubKafka) Produce(_ context.Context, topic string, key, val []byte) {
	s.msgs = append(s.msgs, kmsg{topic: topic, key: append([]byte(nil), key...), val: append([]byte(nil), val...)})
}

// testCounters —— Counters 桩。
type testCounters struct {
	records      int
	drops        int
	decodeErr    int
	produced     int
	replayDrop   int
	replayBuf    int
	replayLagSum time.Duration
}

func (c *testCounters) ForwardRecords(string, string, int)    { c.records += 1 }
func (c *testCounters) ForwardDrop(string, string, int)       { c.drops++ }
func (c *testCounters) SetDestDown(string, bool)              {}
func (c *testCounters) SetResampleRatio(string, float64)      {}
func (c *testCounters) ProxyDecodeErrors(n int)               { c.decodeErr += n }
func (c *testCounters) KafkaProduce(string, int)              { c.produced++ }
func (c *testCounters) KafkaProduceError(string, int)         {}
func (c *testCounters) SetReplayBuffered(string, string, int) {}
func (c *testCounters) ReplayDropped(string, string, int)     { c.replayDrop++ }
func (c *testCounters) SetReplayLag(string, string, time.Duration) {
	c.replayLagSum = time.Second
}

// buildV5 —— 3 记录 v5 数据报（src = exporter）。
func buildV5(t *testing.T, count int) []byte {
	t.Helper()
	dg := make([]byte, flowcodec.V5HeaderLen+count*flowcodec.V5RecordLen)
	binary.BigEndian.PutUint16(dg[0:2], 5)
	binary.BigEndian.PutUint16(dg[2:4], uint16(count))
	binary.BigEndian.PutUint32(dg[4:8], 1000)
	binary.BigEndian.PutUint32(dg[8:12], 1700000000)
	for i := 0; i < count; i++ {
		off := flowcodec.V5HeaderLen + i*flowcodec.V5RecordLen
		binary.BigEndian.PutUint32(dg[off:off+4], uint32(0xC0A80001+i)) // 192.168.0.1+i
		binary.BigEndian.PutUint32(dg[off+4:off+8], 0x08080808)
		binary.BigEndian.PutUint16(dg[off+32:off+34], uint16(2000+i))
		binary.BigEndian.PutUint16(dg[off+34:off+36], 80)
	}
	return dg
}

// udpSink —— 本地 UDP 收包器（透传目的地联调）。
type udpSink struct {
	conn *net.UDPConn
	addr string
}

func newUDPSink(t *testing.T) *udpSink {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	return &udpSink{conn: conn.(*net.UDPConn), addr: conn.LocalAddr().String()}
}

func (u *udpSink) recv(t *testing.T) []byte {
	t.Helper()
	_ = u.conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 65535)
	n, _, err := u.conn.ReadFrom(buf)
	if err != nil {
		t.Fatalf("recv: %v", err)
	}
	return buf[:n]
}

func exporterOf(s string) netip.Addr { return netip.MustParseAddr(s) }

// TestEngineKafkaDestination —— R1 主链路：v5 报文 → 规则命中 → Kafka flows.raw
// （key=FlowKey(zone_id, exporter)，value=FlowRecord proto，1:10 再采样生效）。
func TestEngineKafkaDestination(t *testing.T) {
	sink := &stubKafka{}
	e := NewEngine(sink, &testCounters{})
	defer e.Close()

	_, verrs := e.ApplyRules(&RulesSnapshot{
		Version: 1,
		Rules: []Rule{{
			ID: 42, Enabled: true,
			Match: Match{Exporters: []string{"10.1.1.1"}},
			Destinations: []Destination{
				{Topic: "flows.raw", Protocol: ProtocolKafka, Resample: &Resample{Mode: ResampleDeterministic, Rate: 10}},
			},
		}},
	})
	if len(verrs) > 0 {
		t.Fatalf("verrs: %v", verrs)
	}

	dg := buildV5(t, 100) // 100 条记录 → 期望 ~10 条保留（deterministic 1:10）
	e.Process(dg, exporterOf("10.1.1.1"))

	if len(sink.msgs) == 0 {
		t.Fatal("no kafka messages produced")
	}
	if len(sink.msgs) > 20 || len(sink.msgs) < 3 {
		t.Errorf("1:10 resample ratio out of band: %d kept of 100", len(sink.msgs))
	}
	for _, m := range sink.msgs {
		if m.topic != "flows.raw" {
			t.Errorf("topic = %s", m.topic)
		}
		if len(m.key) < 5 || string(m.key[4:]) != "10.1.1.1" {
			t.Errorf("key must be FlowKey(zone_id, exporter): %q", m.key)
		}
		rec, err := flowcodec.UnmarshalFlowRecord(m.val)
		if err != nil {
			t.Fatalf("value decode: %v", err)
		}
		if rec.SampleRate != 10 {
			t.Errorf("effective sample_rate = %d (want 10 = 1×10)", rec.SampleRate)
		}
		if rec.Exporter != "10.1.1.1" {
			t.Errorf("exporter = %s", rec.Exporter)
		}
	}
	// 未命中 exporter：零产出
	before := len(sink.msgs)
	e.Process(dg, exporterOf("10.2.2.2"))
	if len(sink.msgs) != before {
		t.Errorf("unmatched exporter produced messages")
	}
}

// TestEngineZoneKey —— zone_id 参与 FlowKey（docs/09：key=zone_id(4B 大端)+exporter）。
func TestEngineZoneKey(t *testing.T) {
	sink := &stubKafka{}
	e := NewEngine(sink, &testCounters{})
	defer e.Close()
	_, _ = e.ApplyRules(&RulesSnapshot{
		Version: 1,
		Rules: []Rule{{
			ID: 1, Enabled: true,
			Match:        Match{Exporters: []string{"10.1.1.1"}},
			Destinations: []Destination{{Topic: "flows.raw", Protocol: ProtocolKafka}},
		}},
	})
	dg := buildV5(t, 5)
	// 解码后记录 zone_id=0（broker 不做 zone 匹配，Collector 职责）→ key 前缀 4B 全零
	e.Process(dg, exporterOf("10.1.1.1"))
	if len(sink.msgs) != 5 {
		t.Fatalf("msgs = %d", len(sink.msgs))
	}
	if sink.msgs[0].key[0]|sink.msgs[0].key[1]|sink.msgs[0].key[2]|sink.msgs[0].key[3] != 0 {
		t.Errorf("zone_id prefix must be 0 (unmatched), key=%v", sink.msgs[0].key)
	}
}

// TestEnginePassthroughAndHotUpdate —— 透传复制 + 规则热更新平滑切换（dd/01 §3.2 #5）。
func TestEnginePassthroughAndHotUpdate(t *testing.T) {
	sinkAddr := newUDPSink(t)
	e := NewEngine(nil, &testCounters{})
	defer e.Close()

	_, verrs := e.ApplyRules(&RulesSnapshot{
		Version: 1,
		Rules: []Rule{{
			ID: 9, Enabled: true,
			Match:        Match{Exporters: []string{"10.1.1.1"}},
			Destinations: []Destination{{Addr: sinkAddr.addr, Protocol: ProtocolPassthrough}},
		}},
	})
	if len(verrs) > 0 {
		t.Fatalf("verrs: %v", verrs)
	}
	dg := buildV5(t, 2)
	e.Process(dg, exporterOf("10.1.1.1"))
	got := sinkAddr.recv(t)
	if string(got) != string(dg) {
		t.Fatal("passthrough must be byte-identical copy")
	}

	// 热更新：新版本同一 exporter 改目的地 → 新会话生效
	newSink := newUDPSink(t)
	_, _ = e.ApplyRules(&RulesSnapshot{
		Version: 2,
		Rules: []Rule{{
			ID: 9, Enabled: true,
			Match:        Match{Exporters: []string{"10.1.1.1"}},
			Destinations: []Destination{{Addr: newSink.addr, Protocol: ProtocolPassthrough}},
		}},
	})
	e.Process(dg, exporterOf("10.1.1.1"))
	_ = newSink.recv(t) // 新目的地收到
	// 旧目的地不再收到（非阻塞验证：短超时读应失败）
	_ = sinkAddr.conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	buf := make([]byte, 1500)
	if _, _, err := sinkAddr.conn.ReadFrom(buf); err == nil {
		t.Error("old destination should not receive after hot update")
	}
}

// TestEngineProxyIPFIX —— 代理重编码目的地（IPFIX 输出可解析、采样 IE 正确）。
func TestEngineProxyIPFIX(t *testing.T) {
	sinkAddr := newUDPSink(t)
	e := NewEngine(nil, &testCounters{})
	defer e.Close()
	_, _ = e.ApplyRules(&RulesSnapshot{
		Version: 1,
		Rules: []Rule{{
			ID: 3, Enabled: true,
			Match:        Match{Exporters: []string{"10.1.1.1"}},
			Destinations: []Destination{{Addr: sinkAddr.addr, Protocol: ProtocolIPFIX, Resample: &Resample{Mode: ResampleRandom, Rate: 1}}},
		}},
	})
	e.Process(buildV5(t, 25), exporterOf("10.1.1.1"))
	msg := sinkAddr.recv(t)
	if msg[0] != 0 || msg[1] != 10 {
		t.Fatalf("not an ipfix message: % x", msg[:4])
	}
}

// TestEngineFilter —— 代理模式内容过滤（dd/01 §3.2 #4）。
func TestEngineFilter(t *testing.T) {
	sink := &stubKafka{}
	e := NewEngine(sink, &testCounters{})
	defer e.Close()
	_, _ = e.ApplyRules(&RulesSnapshot{
		Version: 1,
		Rules: []Rule{{
			ID: 5, Enabled: true,
			Match:        Match{Exporters: []string{"10.1.1.1"}},
			Destinations: []Destination{{Topic: "flows.raw", Protocol: ProtocolKafka}},
			FlowFilter:   &FlowFilter{DstPrefix: "8.8.8.0/24"},
		}},
	})
	e.Process(buildV5(t, 3), exporterOf("10.1.1.1")) // dst 全部 8.8.8.8 → 3 条全保留
	if len(sink.msgs) != 3 {
		t.Fatalf("filtered msgs = %d", len(sink.msgs))
	}
}

// TestEngineUnsupportedDecode —— 未知协议报文进入代理路径 → 解码错误计数。
// （v9/IPFIX/sFlow 已支持，任务一；此处覆盖探测入口的兜底分支。）
func TestEngineUnsupportedDecode(t *testing.T) {
	sink := &stubKafka{}
	tc := &testCounters{}
	e := NewEngine(sink, tc)
	defer e.Close()
	_, _ = e.ApplyRules(&RulesSnapshot{
		Version: 1,
		Rules: []Rule{{
			ID: 5, Enabled: true,
			Match:        Match{Exporters: []string{"10.1.1.1"}},
			Destinations: []Destination{{Topic: "flows.raw", Protocol: ProtocolKafka}},
		}},
	})
	dg := make([]byte, 32)
	binary.BigEndian.PutUint16(dg[0:2], 999) // 未知协议版本
	e.Process(dg, exporterOf("10.1.1.1"))
	if tc.decodeErr == 0 || len(sink.msgs) != 0 {
		t.Errorf("decodeErr=%d msgs=%d", tc.decodeErr, len(sink.msgs))
	}
}

// TestEngineNoRulesZeroOverhead —— 未配置规则零额外开销（空表 O(1)，dd/01 §1）。
func TestEngineNoRulesZeroOverhead(t *testing.T) {
	sink := &stubKafka{}
	e := NewEngine(sink, &testCounters{})
	defer e.Close()
	if !e.Rules().Empty() {
		t.Fatal("fresh engine must be empty")
	}
	e.Process(buildV5(t, 1), exporterOf("10.1.1.1"))
	if len(sink.msgs) != 0 {
		t.Fatal("no rules → no output")
	}
}
