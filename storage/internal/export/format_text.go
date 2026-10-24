package export

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// textFormatter —— docs/00 §7 定宽多空格对齐文本（"数据流转格式化文本"）。
//
// 列宽（骨架固化的黄金格式，黄金文件 testdata/golden/flows_text.golden）：
//
//	start 24 | end 18 | proto 6 | src 24 | dst 24 | pkts 6 | bytes 9 | flags 8 | if_in/if_out 13 | sample 不定宽
//
// docs/00 §7 示例中各列间隙不完全一致（示例非等宽字体排印），本实现取
// 覆盖示例最宽值的固化列宽并以黄金文件断言（契约缺口见模块 README）。
type textFormatter struct {
	loc *time.Location
}

// textStartLayout / textEndLayout —— 开始（含日期）与结束（仅时刻，同日语义，
// docs/00 §7 示例）的时间布局。
const (
	textStartLayout = "2006-01-02 15:04:05.000"
	textEndLayout   = "15:04:05.000"
)

// textWidths —— 列宽表（除末列 sample 外依次对应）。
var textWidths = [...]int{24, 18, 6, 24, 24, 6, 9, 8, 13}

// textLabels —— 文本头标签（docs/00 §7 列名）。
var textLabels = [...]string{"start", "end", "proto", "src", "dst", "pkts", "bytes", "flags", "if_in/if_out", "sample"}

// Header 渲染条件注释 + 定宽列头。
func (f textFormatter) Header(m Meta) string {
	var sb strings.Builder
	sb.WriteString(metaComment(m))
	sb.WriteString("# ")
	for i, l := range textLabels {
		if i < len(textWidths) {
			sb.WriteString(pad(l, textWidths[i]))
		} else {
			sb.WriteString(l)
		}
	}
	sb.WriteString("\n")
	return sb.String()
}

// Row 渲染单行（docs/00 §7 逐字段：定宽对齐、v4 映射还原显示、flags 符号串）。
func (f textFormatter) Row(r Row) (string, error) {
	if err := validateRow(r); err != nil {
		return "", fmt.Errorf("format text row: %w", err)
	}
	start, end := rowTimes(r, f.loc)
	var sb strings.Builder
	sb.WriteString(pad(start.Format(textStartLayout), textWidths[0]))
	sb.WriteString(pad(end.Format(textEndLayout), textWidths[1]))
	sb.WriteString(pad(ProtoName(r.Proto), textWidths[2]))
	sb.WriteString(pad(FormatIP(r.SrcIP)+":"+strconv.Itoa(int(r.SrcPort)), textWidths[3]))
	sb.WriteString(pad(FormatIP(r.DstIP)+":"+strconv.Itoa(int(r.DstPort)), textWidths[4]))
	sb.WriteString(pad(strconv.FormatUint(r.Packets, 10), textWidths[5]))
	sb.WriteString(pad(strconv.FormatUint(r.Bytes, 10), textWidths[6]))
	sb.WriteString(pad(FlagsSymbol(r.TCPFlags), textWidths[7]))
	sb.WriteString(pad(strconv.Itoa(int(r.InIf))+"/"+strconv.Itoa(int(r.OutIf)), textWidths[8]))
	sb.WriteString(strconv.FormatUint(uint64(r.SampleRate), 10))
	sb.WriteString("\n")
	return sb.String(), nil
}
