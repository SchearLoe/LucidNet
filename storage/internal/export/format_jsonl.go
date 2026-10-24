package export

import (
	"encoding/json"
	"fmt"
	"time"
)

// jsonlFormatter —— JSON Lines 格式（docs/dd/04 §5.1 --format=jsonl）。
// 每行一个 JSON 对象；头两行为 # 注释（取证元数据，消费方应跳过 # 行）。
type jsonlFormatter struct {
	loc *time.Location
}

// jsonlRowLayout —— ISO8601 毫秒布局（含时区偏移）。
const jsonlRowLayout = "2006-01-02T15:04:05.000Z07:00"

// jsonlRow —— JSON 行负载（键序固定，黄金文件断言基准）。
type jsonlRow struct {
	TimeStart  string `json:"time_start"`
	TimeEnd    string `json:"time_end"`
	Proto      int    `json:"proto"`
	SrcIP      string `json:"src_ip"`
	SrcPort    int    `json:"src_port"`
	DstIP      string `json:"dst_ip"`
	DstPort    int    `json:"dst_port"`
	IPVersion  int    `json:"ip_version"`
	Packets    uint64 `json:"packets"`
	Bytes      uint64 `json:"bytes"`
	TCPFlags   int    `json:"tcp_flags"`
	InIf       uint32 `json:"in_if"`
	OutIf      uint32 `json:"out_if"`
	SampleRate uint32 `json:"sample_rate"`
}

// Header 渲染注释行（JSONL 无列头概念，仅取证元数据）。
func (f jsonlFormatter) Header(m Meta) string { return metaComment(m) }

// Row 渲染单行 JSON。
func (f jsonlFormatter) Row(r Row) (string, error) {
	if err := validateRow(r); err != nil {
		return "", fmt.Errorf("format jsonl row: %w", err)
	}
	start, end := rowTimes(r, f.loc)
	out, err := json.Marshal(jsonlRow{
		TimeStart:  start.Format(jsonlRowLayout),
		TimeEnd:    end.Format(jsonlRowLayout),
		Proto:      int(r.Proto),
		SrcIP:      FormatIP(r.SrcIP),
		SrcPort:    int(r.SrcPort),
		DstIP:      FormatIP(r.DstIP),
		DstPort:    int(r.DstPort),
		IPVersion:  int(r.IPVersion),
		Packets:    r.Packets,
		Bytes:      r.Bytes,
		TCPFlags:   int(r.TCPFlags),
		InIf:       r.InIf,
		OutIf:      r.OutIf,
		SampleRate: r.SampleRate,
	})
	if err != nil {
		return "", fmt.Errorf("format jsonl row: %w", err)
	}
	return string(out) + "\n", nil
}
