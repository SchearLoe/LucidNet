package export

import (
	"encoding/csv"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// csvFormatter —— CSV 格式（docs/dd/04 §5.1 --format=csv）。
// 头两行为 # 注释（取证元数据），第三行起为 CSV 记录；
// IP 与端口分列、flags 取十进制数值（机器可读优先）。
type csvFormatter struct {
	loc *time.Location
}

// csvHeader —— CSV 列头。
var csvHeader = []string{
	"start", "end", "proto", "src_ip", "src_port", "dst_ip", "dst_port",
	"packets", "bytes", "tcp_flags", "in_if", "out_if", "sample_rate",
}

// csvRowLayout —— CSV 时间布局（含日期，机器可读完整时刻）。
const csvRowLayout = "2006-01-02 15:04:05.000"

// Header 渲染注释行 + CSV 列头。
func (f csvFormatter) Header(m Meta) string {
	var sb strings.Builder
	sb.WriteString(metaComment(m))
	cw := csv.NewWriter(&sb)
	_ = cw.Write(csvHeader)
	cw.Flush()
	// Writer 内部错误只在 Flush 后 Error() 暴露；目标是 strings.Builder 不会失败
	return sb.String()
}

// Row 渲染单条 CSV 记录。
func (f csvFormatter) Row(r Row) (string, error) {
	if err := validateRow(r); err != nil {
		return "", fmt.Errorf("format csv row: %w", err)
	}
	start, end := rowTimes(r, f.loc)
	record := []string{
		start.Format(csvRowLayout),
		end.Format(csvRowLayout),
		strconv.Itoa(int(r.Proto)),
		FormatIP(r.SrcIP),
		strconv.Itoa(int(r.SrcPort)),
		FormatIP(r.DstIP),
		strconv.Itoa(int(r.DstPort)),
		strconv.FormatUint(r.Packets, 10),
		strconv.FormatUint(r.Bytes, 10),
		strconv.Itoa(int(r.TCPFlags)),
		strconv.FormatUint(uint64(r.InIf), 10),
		strconv.FormatUint(uint64(r.OutIf), 10),
		strconv.FormatUint(uint64(r.SampleRate), 10),
	}
	var sb strings.Builder
	cw := csv.NewWriter(&sb)
	if err := cw.Write(record); err != nil {
		return "", fmt.Errorf("format csv row: %w", err)
	}
	cw.Flush()
	if err := cw.Error(); err != nil {
		return "", fmt.Errorf("format csv row: %w", err)
	}
	return sb.String(), nil
}
