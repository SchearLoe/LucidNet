package producer

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/SchearLoe/lucidnet/shared"
)

func testRec() *shared.FlowRecord {
	var src, dst [16]byte
	src[10], src[11] = 0xff, 0xff
	src[12], src[13], src[14], src[15] = 192, 0, 2, 23
	dst[10], dst[11] = 0xff, 0xff
	dst[12], dst[13], dst[14], dst[15] = 203, 0, 113, 7
	return &shared.FlowRecord{
		TimeStartMs: 1700000000500, TimeEndMs: 1700000000900,
		Exporter: "10.255.0.1", DeviceID: 1, InIf: 5, OutIf: 9,
		SrcIP: src, DstIP: dst, SrcPort: 1024, DstPort: 443,
		Proto: 6, IPVersion: 4, Packets: 10, Bytes: 1500,
		TCPFlags: 0x12, SampleRate: 1, SrcAS: 65001, DstAS: 65002,
		ZoneID: 7, IfRole: shared.IfRoleInBoundary, ZoneSide: uint8(shared.ZoneSideDst),
	}
}

func TestConsoleProduce(t *testing.T) {
	var buf bytes.Buffer
	w := bufio.NewWriter(&buf)
	c := NewConsole(w)
	if err := c.Produce(context.Background(), testRec()); err != nil {
		t.Fatalf("produce: %v", err)
	}
	if err := c.Flush(context.Background()); err != nil {
		t.Fatalf("flush: %v", err)
	}
	line := buf.String()
	if !strings.HasSuffix(line, "\n") || strings.Count(line, "\n") != 1 {
		t.Fatalf("output must be single JSON line: %q", line)
	}
	var env struct {
		Topic  string `json:"topic"`
		KeyHex string `json:"key_hex"`
		Record struct {
			Exporter string `json:"exporter"`
			SrcIP    string `json:"src_ip"`
			ZoneID   int32  `json:"zone_id"`
			ZoneSide uint32 `json:"zone_side"`
			IfRole   uint32 `json:"if_role"`
		} `json:"record"`
	}
	if err := json.Unmarshal([]byte(line), &env); err != nil {
		t.Fatalf("unmarshal: %v\nline: %s", err, line)
	}
	if env.Topic != shared.TopicFlowsRaw {
		t.Errorf("topic = %q, want %q", env.Topic, shared.TopicFlowsRaw)
	}
	// key 契约：FlowKey(zone_id, exporter) = zone_id 4B 大端 + exporter（09 §2）
	wantKey := shared.FlowKey(7, "10.255.0.1")
	if key, err := hex.DecodeString(env.KeyHex); err != nil {
		t.Fatalf("key_hex decode: %v", err)
	} else if !bytes.Equal(key, wantKey) {
		t.Errorf("key = %x, want %x (FlowKey(zone_id, exporter))", key, wantKey)
	}
	if env.Record.Exporter != "10.255.0.1" || env.Record.SrcIP != "192.0.2.23" {
		t.Errorf("record fields = %+v", env.Record)
	}
	if env.Record.ZoneID != 7 || env.Record.ZoneSide != 1 || env.Record.IfRole != 1 {
		t.Errorf("enriched fields = %+v (zone/side/role)", env.Record)
	}
	if err := c.Close(); err != nil {
		t.Errorf("close: %v", err)
	}
}

func TestFileProduceAppend(t *testing.T) {
	path := filepath.Join(t.TempDir(), "flows.jsonl")
	f, err := NewFile(path)
	if err != nil {
		t.Fatalf("new file: %v", err)
	}
	for i := 0; i < 3; i++ {
		if err := f.Produce(context.Background(), testRec()); err != nil {
			t.Fatalf("produce: %v", err)
		}
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if f.Count() != 3 {
		t.Errorf("count = %d, want 3", f.Count())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if n := strings.Count(string(data), "\n"); n != 3 {
		t.Errorf("lines = %d, want 3", n)
	}

	// 追加语义：重开再写一条
	f2, err := NewFile(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if err := f2.Produce(context.Background(), testRec()); err != nil {
		t.Fatalf("produce 2: %v", err)
	}
	if err := f2.Flush(context.Background()); err != nil {
		t.Fatalf("flush 2: %v", err)
	}
	if err := f2.Close(); err != nil {
		t.Fatalf("close 2: %v", err)
	}
	data, _ = os.ReadFile(path)
	if n := strings.Count(string(data), "\n"); n != 4 {
		t.Errorf("lines after append = %d, want 4", n)
	}
}

func TestKafkaStub(t *testing.T) {
	if _, err := NewKafka(KafkaConfig{}); err == nil {
		t.Error("no brokers: want error")
	}
	cfg := DefaultKafkaConfig([]string{"kafka:9092"})
	if cfg.Topic != shared.TopicFlowsRaw || cfg.Linger != DefaultLinger || cfg.BatchMaxBytes != DefaultBatchMaxBytes {
		t.Errorf("defaults = %+v (dd/02 §4: topic flows.raw / linger 50ms / batch 64KB)", cfg)
	}
	if cfg.Compression != "lz4" || cfg.MaxBufferBytes != DefaultMaxBufferBytes {
		t.Errorf("defaults = %+v (lz4 / 100MB 背压阈值)", cfg)
	}
	p, err := NewKafka(cfg)
	if err != nil {
		t.Fatalf("new kafka: %v", err)
	}
	if err := p.Produce(context.Background(), testRec()); !errors.Is(err, ErrKafkaNotImplemented) {
		t.Errorf("produce err = %v, want ErrKafkaNotImplemented", err)
	}
	if err := p.Flush(context.Background()); !errors.Is(err, ErrKafkaNotImplemented) {
		t.Errorf("flush err = %v, want ErrKafkaNotImplemented", err)
	}
	if err := p.Close(); err != nil {
		t.Errorf("close: %v", err)
	}
}

func TestFlowKeyContract(t *testing.T) {
	// key 契约引用 09 §2 / shared：同 zone 同 exporter 必须同 key（分区有序）
	k1 := shared.FlowKey(7, "10.0.0.1")
	k2 := shared.FlowKey(7, "10.0.0.1")
	if !bytes.Equal(k1, k2) {
		t.Error("same (zone, exporter) must produce same key")
	}
	if shared.ZoneFromKey(k1) != 7 {
		t.Errorf("ZoneFromKey = %d, want 7", shared.ZoneFromKey(k1))
	}
	if bytes.Equal(k1, shared.FlowKey(8, "10.0.0.1")) {
		t.Error("different zone must produce different key")
	}
}
