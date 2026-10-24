package export

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/SchearLoe/lucidnet/storage/internal/query"
)

// ErrBadRow —— 格式化输入行非法哨兵错误。
var ErrBadRow = errors.New("bad export row")

// Format —— 导出格式（docs/dd/04 §5.1：text|csv|jsonl，默认 text；
// text = docs/00 §7 数据流转格式化文本）。
type Format string

// 导出格式枚举。
const (
	FormatText  Format = "text"
	FormatCSV   Format = "csv"
	FormatJSONL Format = "jsonl"
)

// Row —— 格式化输入行（源自 flows_raw 明细列；IP 为 16B 网络序，
// v4 为 ::ffff: 映射，docs/00 §1）。
type Row struct {
	TimeStartMs, TimeEndMs int64
	SrcIP, DstIP           [16]byte
	SrcPort, DstPort       uint16
	Proto                  uint8
	IPVersion              uint8
	Packets, Bytes         uint64
	TCPFlags               uint8
	InIf, OutIf            uint32
	SampleRate             uint32
}

// Meta —— 文件头条件元数据（docs/00 §7：字段顺序与过滤条件随任务参数
// 持久化在导出文件头注释，满足取证可追溯）。
type Meta struct {
	ZoneID      int32
	ZoneName    string
	WindowStart time.Time // 任务时间窗（绝对时间，RFC3339 渲染）
	WindowEnd   time.Time
	Loc         *time.Location // 渲染时区；nil=UTC
	Fields      []string       // 字段顺序（可追溯）
	Filters     []string       // "k=v" 过滤条件摘要（可追溯）
}

// Formatter —— 逐行格式化器（Header 一次、Row 每行一次，均含尾随 \n）。
type Formatter interface {
	Header(m Meta) string
	Row(r Row) (string, error)
}

// NewFormatter 按格式构造格式化器；渲染时区取 m.Loc（nil=UTC）。
func NewFormatter(f Format, m Meta) (Formatter, error) {
	loc := m.Loc
	if loc == nil {
		loc = time.UTC
	}
	switch f {
	case FormatText, "":
		return textFormatter{loc: loc}, nil
	case FormatCSV:
		return csvFormatter{loc: loc}, nil
	case FormatJSONL:
		return jsonlFormatter{loc: loc}, nil
	default:
		return nil, fmt.Errorf("unsupported export format %q (want text|csv|jsonl)", f)
	}
}

// —— 共享渲染辅助 ——

// FormatIP —— 展示地址（docs/00 §7 示例）：IPv4 保持 ::ffff:a.b.c.d 映射形
// （示例第 2 行 "::ffff:1.2.3.4:55555"；docs/00 §1 展示层按 ip_version 决定格式，
// 两处并存歧义属契约缺口，见模块 README），IPv6 原样。
// 注意 net.IP.String() 会剥掉 v4 映射前缀，须手工还原。
func FormatIP(b [16]byte) string {
	ip := net.IP(b[:])
	if v4 := ip.To4(); v4 != nil {
		return "::ffff:" + v4.String()
	}
	return ip.String()
}

// protoNames —— 协议号 → 助记（docs/00 §7 示例 TCP/UDP；未知 → 十进制串）。
var protoNames = map[uint8]string{
	1:  "ICMP",
	6:  "TCP",
	17: "UDP",
	47: "GRE",
	50: "ESP",
	58: "ICMP6",
}

// ProtoName 渲染协议列。
func ProtoName(p uint8) string {
	if n, ok := protoNames[p]; ok {
		return n
	}
	return strconv.Itoa(int(p))
}

// FlagsSymbol —— flags 符号串：单 bit → 助记（FIN/SYN/RST/PSH/ACK/URG）；
// 其余 → 8 位点串，位序 CWR,ECE,URG,ACK,PSH,RST,SYN,FIN（高位→低位）。
// 契约注记：docs/00 §7 示例同时出现 ".A.S."（5 位）与 "SYN" 且未定义位序
// 与单符号映射表（契约缺口见模块 README）；本骨架固化上述规则，
// 以 testdata 黄金文件为断言基准。
func FlagsSymbol(f uint8) string {
	switch f {
	case 0x01:
		return "FIN"
	case 0x02:
		return "SYN"
	case 0x04:
		return "RST"
	case 0x08:
		return "PSH"
	case 0x10:
		return "ACK"
	case 0x20:
		return "URG"
	}
	const chars = "CEUAPRSF"
	var b [8]byte
	for i := range 8 {
		if f&(1<<(7-uint(i))) != 0 {
			b[i] = chars[i]
		} else {
			b[i] = '.'
		}
	}
	return string(b[:])
}

// FilterSummary —— 过滤条件渲染为 "k=v" 摘要（文件头取证注释，docs/00 §7）。
func FilterSummary(f query.Filters) []string {
	var out []string
	if s := strings.TrimSpace(f.SrcIP); s != "" {
		out = append(out, "src_ip="+s)
	}
	if s := strings.TrimSpace(f.DstIP); s != "" {
		out = append(out, "dst_ip="+s)
	}
	if f.SrcPort != nil {
		out = append(out, "src_port="+strconv.FormatUint(uint64(*f.SrcPort), 10))
	}
	if f.DstPort != nil {
		out = append(out, "dst_port="+strconv.FormatUint(uint64(*f.DstPort), 10))
	}
	if f.Proto != nil {
		out = append(out, "proto="+strconv.FormatUint(uint64(*f.Proto), 10))
	}
	if f.ZoneID != nil {
		out = append(out, "zone_id="+strconv.FormatInt(int64(*f.ZoneID), 10))
	}
	if f.DeviceID != nil {
		out = append(out, "device_id="+strconv.FormatUint(uint64(*f.DeviceID), 10))
	}
	if f.InIf != nil {
		out = append(out, "in_if="+strconv.FormatUint(uint64(*f.InIf), 10))
	}
	if f.OutIf != nil {
		out = append(out, "out_if="+strconv.FormatUint(uint64(*f.OutIf), 10))
	}
	if f.IPVersion != nil {
		out = append(out, "ip_version="+strconv.FormatUint(uint64(*f.IPVersion), 10))
	}
	return out
}

// rowTimes —— 行时间 → 渲染时区的开始/结束时刻。
func rowTimes(r Row, loc *time.Location) (time.Time, time.Time) {
	if loc == nil {
		loc = time.UTC
	}
	return time.UnixMilli(r.TimeStartMs).In(loc), time.UnixMilli(r.TimeEndMs).In(loc)
}

// validateRow —— 行时间合法性（end >= start，均非负）。
func validateRow(r Row) error {
	if r.TimeStartMs < 0 || r.TimeEndMs < r.TimeStartMs {
		return fmt.Errorf("validate row: time range %d..%d: %w", r.TimeStartMs, r.TimeEndMs, ErrBadRow)
	}
	return nil
}

// metaComment —— 文件头条件注释两行（text/jsonl 共用；csv 前缀 # 行）。
func metaComment(m Meta) string {
	var sb strings.Builder
	loc := m.Loc
	if loc == nil {
		loc = time.UTC
	}
	if m.ZoneID != 0 || m.ZoneName != "" {
		sb.WriteString("# LucidNet flow export | zone=" + m.ZoneName + "(" + strconv.FormatInt(int64(m.ZoneID), 10) + ")")
	} else {
		sb.WriteString("# LucidNet flow export")
	}
	sb.WriteString(" | window=")
	sb.WriteString(m.WindowStart.In(loc).Format("2006-01-02T15:04:05Z07:00"))
	sb.WriteString("/")
	sb.WriteString(m.WindowEnd.In(loc).Format("15:04:05"))
	sb.WriteString("\n")
	// 取证可追溯：字段顺序 + 过滤条件（docs/00 §7）
	sb.WriteString("# fields=" + strings.Join(m.Fields, ","))
	if len(m.Filters) > 0 {
		sb.WriteString(" | filters=" + strings.Join(m.Filters, " "))
	}
	sb.WriteString("\n")
	return sb.String()
}

// pad —— 定宽左对齐，超宽时补一个空格分隔。
func pad(s string, w int) string {
	if len(s) >= w {
		return s + " "
	}
	return s + strings.Repeat(" ", w-len(s))
}
