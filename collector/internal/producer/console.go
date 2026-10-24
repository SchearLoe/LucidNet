package producer

import (
	"bufio"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"

	"github.com/SchearLoe/lucidnet/shared"
)

// JSON 行开发输出（console / file）：proto+lz4 接入前的 flows.raw 替身。
// key_hex = shared.FlowKey(zone_id, exporter) 十六进制，便于核对分区键契约（09 §2）。

// recordJSON —— shared.FlowRecord 的 JSON 镜像（键名 = proto 字段名 snake_case）。
type recordJSON struct {
	TimeStartMs int64  `json:"time_start_ms"`
	TimeEndMs   int64  `json:"time_end_ms"`
	Exporter    string `json:"exporter"`
	DeviceID    uint32 `json:"device_id"`
	InIf        uint32 `json:"in_if"`
	OutIf       uint32 `json:"out_if"`
	SrcIP       string `json:"src_ip"`
	DstIP       string `json:"dst_ip"`
	SrcPort     uint32 `json:"src_port"`
	DstPort     uint32 `json:"dst_port"`
	Proto       uint32 `json:"proto"`
	IPVersion   uint32 `json:"ip_version"`
	Packets     uint64 `json:"packets"`
	Bytes       uint64 `json:"bytes"`
	TCPFlags    uint32 `json:"tcp_flags"`
	TOS         uint32 `json:"tos"`
	SampleRate  uint32 `json:"sample_rate"`
	SrcAS       uint32 `json:"src_as"`
	DstAS       uint32 `json:"dst_as"`
	BGPNextHop  string `json:"bgp_next_hop"`
	SrcGeo      uint32 `json:"src_geo"`
	DstGeo      uint32 `json:"dst_geo"`
	AppID       uint32 `json:"app_id"`
	ZoneID      int32  `json:"zone_id"`
	IfRole      uint32 `json:"if_role"`
	ZoneSide    uint32 `json:"zone_side"`
}

// envelopeJSON —— 输出行信封：分区键 + 记录体。
type envelopeJSON struct {
	Topic  string     `json:"topic"`
	KeyHex string     `json:"key_hex"`
	Record recordJSON `json:"record"`
}

// ip16Text —— 16B 地址 → 文本（v4 映射还原为点分）。
func ip16Text(b [16]byte) string {
	a := netip.AddrFrom16(b)
	if a.Is4In6() {
		return a.Unmap().String()
	}
	return a.String()
}

// MarshalRecordJSON —— 记录 + 分区键 → JSON 行（含结尾换行）。
func MarshalRecordJSON(topic string, rec *shared.FlowRecord) []byte {
	env := envelopeJSON{
		Topic:  topic,
		KeyHex: hex.EncodeToString(shared.FlowKey(rec.ZoneID, rec.Exporter)),
		Record: recordJSON{
			TimeStartMs: rec.TimeStartMs,
			TimeEndMs:   rec.TimeEndMs,
			Exporter:    rec.Exporter,
			DeviceID:    rec.DeviceID,
			InIf:        rec.InIf,
			OutIf:       rec.OutIf,
			SrcIP:       ip16Text(rec.SrcIP),
			DstIP:       ip16Text(rec.DstIP),
			SrcPort:     rec.SrcPort,
			DstPort:     rec.DstPort,
			Proto:       rec.Proto,
			IPVersion:   rec.IPVersion,
			Packets:     rec.Packets,
			Bytes:       rec.Bytes,
			TCPFlags:    rec.TCPFlags,
			TOS:         rec.TOS,
			SampleRate:  rec.SampleRate,
			SrcAS:       rec.SrcAS,
			DstAS:       rec.DstAS,
			BGPNextHop:  ip16Text(rec.BGPNextHop),
			SrcGeo:      rec.SrcGeo,
			DstGeo:      rec.DstGeo,
			AppID:       rec.AppID,
			ZoneID:      rec.ZoneID,
			IfRole:      uint32(rec.IfRole),
			ZoneSide:    uint32(rec.ZoneSide),
		},
	}
	b, err := json.Marshal(env)
	if err != nil { // recordJSON 无不可序列化字段，理论不可达
		return []byte(fmt.Sprintf("{\"topic\":%q,\"marshal_error\":%q}\n", topic, err.Error()))
	}
	return append(b, '\n')
}

// Console —— 控制台输出实现（开发/演示：flows.raw → stdout JSON 行）。
type Console struct {
	topic string
	w     *bufio.Writer
}

// NewConsole —— 构造（w 通常为 os.Stdout）。
func NewConsole(w *bufio.Writer) *Console {
	return &Console{topic: shared.TopicFlowsRaw, w: w}
}

// Produce —— 写一行 JSON。
func (c *Console) Produce(ctx context.Context, rec *shared.FlowRecord) error {
	if _, err := c.w.Write(MarshalRecordJSON(c.topic, rec)); err != nil {
		return fmt.Errorf("console produce: %w", err)
	}
	return nil
}

// Flush —— 冲刷缓冲。
func (c *Console) Flush(ctx context.Context) error {
	if err := c.w.Flush(); err != nil {
		return fmt.Errorf("console flush: %w", err)
	}
	return nil
}

// Close —— 冲刷并关闭（不关闭底层 writer 所有权归调用方）。
func (c *Console) Close() error { return c.w.Flush() }

// File —— 文件输出实现（开发/回放留档：flows.raw → 追加 JSON 行文件）。
type File struct {
	topic string
	f     *os.File
	w     *bufio.Writer
	n     int64
}

// NewFile —— 打开追加写文件。
func NewFile(path string) (*File, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, fmt.Errorf("open flow output file %s: %w", path, err)
	}
	return &File{topic: shared.TopicFlowsRaw, f: f, w: bufio.NewWriter(f)}, nil
}

// Produce —— 追加一行 JSON。
func (p *File) Produce(ctx context.Context, rec *shared.FlowRecord) error {
	if _, err := p.w.Write(MarshalRecordJSON(p.topic, rec)); err != nil {
		return fmt.Errorf("file produce: %w", err)
	}
	p.n++
	return nil
}

// Flush —— 冲刷 + fsync。
func (p *File) Flush(ctx context.Context) error {
	if err := p.w.Flush(); err != nil {
		return fmt.Errorf("file flush: %w", err)
	}
	if err := p.f.Sync(); err != nil {
		return fmt.Errorf("file sync: %w", err)
	}
	return nil
}

// Close —— 冲刷并关闭文件。
func (p *File) Close() error {
	if err := p.w.Flush(); err != nil {
		return fmt.Errorf("file close flush: %w", err)
	}
	return p.f.Close()
}

// Count —— 已写入条数（测试/诊断）。
func (p *File) Count() int64 { return p.n }
