package export

import (
	"flag"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/SchearLoe/lucidnet/storage/internal/query"
)

var update = flag.Bool("update", false, "rewrite golden files")

// goldenZone —— docs/00 §7 示例时区（UTC+8）。
var goldenZone = time.FixedZone("UTC+8", 8*3600)

// goldenMeta / goldenRows —— 复刻 docs/00 §7 示例两行（IPv6 行 + v4 映射行）。
func goldenMeta() Meta {
	dstPort := uint32(443)
	zone := int32(101)
	return Meta{
		ZoneID:      101,
		ZoneName:    "客户A",
		WindowStart: time.Date(2026, 10, 24, 13, 5, 0, 0, goldenZone),
		WindowEnd:   time.Date(2026, 10, 24, 13, 15, 0, 0, goldenZone),
		Loc:         goldenZone,
		Fields:      query.DefaultFields,
		Filters:     FilterSummary(query.Filters{DstPort: &dstPort, ZoneID: &zone}),
	}
}

func goldenRows() []Row {
	v6src := [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01}
	v6dst := [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0x05, 0, 0, 0, 0, 0, 0, 0, 0, 0x00, 0x80}
	v4src := [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 1, 2, 3, 4}
	v4dst := [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 5, 6, 7, 8}
	start := time.Date(2026, 10, 24, 13, 5, 1, 0, goldenZone)
	return []Row{
		{
			TimeStartMs: start.Add(123 * time.Millisecond).UnixMilli(),
			TimeEndMs:   start.Add(2*time.Second + 400*time.Millisecond).UnixMilli(), // → 13:05:03.400
			SrcIP:       v6src, DstIP: v6dst,
			SrcPort: 44321, DstPort: 443,
			Proto: 6, IPVersion: 6,
			Packets: 120, Bytes: 86400,
			TCPFlags: 0x12, // ACK|SYN
			InIf:     12, OutIf: 15,
			SampleRate: 1,
		},
		{
			TimeStartMs: start.Add(200 * time.Millisecond).UnixMilli(),
			TimeEndMs:   start.Add(350 * time.Millisecond).UnixMilli(),
			SrcIP:       v4src, DstIP: v4dst,
			SrcPort: 55555, DstPort: 80,
			Proto: 6, IPVersion: 4,
			Packets: 10, Bytes: 6400,
			TCPFlags: 0x02, // SYN
			InIf:     3, OutIf: 4,
			SampleRate: 100,
		},
	}
}

// render —— 完整产物文本（Header + 逐行）。
func render(t *testing.T, f Format) string {
	t.Helper()
	formatter, err := NewFormatter(f, goldenMeta())
	if err != nil {
		t.Fatalf("new formatter %s: %v", f, err)
	}
	out := formatter.Header(goldenMeta())
	for i, r := range goldenRows() {
		s, err := formatter.Row(r)
		if err != nil {
			t.Fatalf("format %s row %d: %v", f, i, err)
		}
		out += s
	}
	return out
}

// TestGoldenFormats —— text/csv/jsonl 三格式黄金文件比对（docs/00 §7 逐字段）。
func TestGoldenFormats(t *testing.T) {
	for _, tc := range []struct {
		format Format
		file   string
	}{
		{FormatText, "flows_text.golden"},
		{FormatCSV, "flows_csv.golden"},
		{FormatJSONL, "flows_jsonl.golden"},
	} {
		t.Run(string(tc.format), func(t *testing.T) {
			got := render(t, tc.format)
			path := filepath.Join("testdata", "golden", tc.file)
			if *update {
				if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
					t.Fatalf("mkdir golden dir: %v", err)
				}
				if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
					t.Fatalf("write golden: %v", err)
				}
				return
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read golden %s（先 go test -update 生成并人工核对）: %v", path, err)
			}
			if got != string(want) {
				t.Errorf("golden mismatch %s:\n--- want ---\n%s\n--- got ---\n%s", path, want, got)
			}
		})
	}
}

// TestTextFormatterFields —— text 逐字段断言（00 §7：定宽、映射还原、flags 符号、sample 列）。
func TestTextFormatterFields(t *testing.T) {
	formatter := textFormatter{loc: goldenZone}
	row := goldenRows()[1] // v4 映射行
	s, err := formatter.Row(row)
	if err != nil {
		t.Fatalf("row: %v", err)
	}
	for _, want := range []string{
		"2026-10-24 13:05:01.200 ", // start 定宽（含尾随空隙）
		"13:05:01.350 ",            // end 仅时刻
		"TCP   ",                   // proto 助记
		"::ffff:1.2.3.4:55555   ",  // v4 映射还原显示 + 端口
		"::ffff:5.6.7.8:80   ",
		"10    ",        // pkts
		"6400    ",      // bytes
		"SYN   ",        // 单 bit flags 助记
		"3/4          ", // if_in/if_out
		"100\n",         // sample 末列 + 换行
	} {
		if !contains(s, want) {
			t.Errorf("text row missing %q:\n%s", want, s)
		}
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	})()
}

// TestFlagsSymbol —— flags 符号串规则表驱动。
func TestFlagsSymbol(t *testing.T) {
	cases := []struct {
		in   uint8
		want string
	}{
		{0x00, "........"},
		{0x01, "FIN"},
		{0x02, "SYN"},
		{0x04, "RST"},
		{0x08, "PSH"},
		{0x10, "ACK"},
		{0x20, "URG"},
		{0x12, "...A..S."}, // SYN|ACK
		{0x1f, "...APRSF"}, // FIN|SYN|RST|PSH|ACK（无 URG/ECE/CWR）
		{0xff, "CEUAPRSF"}, // 全 1
	}
	for _, c := range cases {
		if got := FlagsSymbol(c.in); got != c.want {
			t.Errorf("FlagsSymbol(0x%02x) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestFormatIP —— v4 映射还原显示（::ffff: 形）与 v6 原样。
func TestFormatIP(t *testing.T) {
	v4 := [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 1, 2, 3, 4}
	if got := FormatIP(v4); got != "::ffff:1.2.3.4" {
		t.Errorf("FormatIP(v4mapped) = %q, want ::ffff:1.2.3.4", got)
	}
	v6 := [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	if got := FormatIP(v6); got != "2001:db8::1" {
		t.Errorf("FormatIP(v6) = %q, want 2001:db8::1", got)
	}
}

// TestProtoName —— 协议助记与未知回退。
func TestProtoName(t *testing.T) {
	for p, want := range map[uint8]string{1: "ICMP", 6: "TCP", 17: "UDP", 58: "ICMP6", 132: "132"} {
		if got := ProtoName(p); got != want {
			t.Errorf("ProtoName(%d) = %q, want %q", p, got, want)
		}
	}
}

// TestNewFormatterBadFormat —— 非法格式报错。
func TestNewFormatterBadFormat(t *testing.T) {
	if _, err := NewFormatter(Format("xlsx"), goldenMeta()); err == nil {
		t.Fatal("expect error for unsupported format")
	}
}

// TestBadRowTimes —— end<start / 负时间行报 ErrBadRow。
func TestBadRowTimes(t *testing.T) {
	formatter, err := NewFormatter(FormatText, goldenMeta())
	if err != nil {
		t.Fatalf("new formatter: %v", err)
	}
	bad := goldenRows()[0]
	bad.TimeEndMs = bad.TimeStartMs - 1
	if _, err := formatter.Row(bad); err == nil {
		t.Fatal("expect error for end<start")
	}
	bad2 := goldenRows()[0]
	bad2.TimeStartMs = -1
	if _, err := formatter.Row(bad2); err == nil {
		t.Fatal("expect error for negative start")
	}
}

// TestFilterSummary —— 过滤条件取证摘要完整覆盖。
func TestFilterSummary(t *testing.T) {
	sp, dp, pr, dev, ii, io, ipv := uint32(1234), uint32(443), uint32(6), uint32(7), uint32(12), uint32(13), uint8(6)
	zone := int32(101)
	got := FilterSummary(query.Filters{
		SrcIP: "2001:db8::/32", DstIP: "1.2.3.4",
		SrcPort: &sp, DstPort: &dp, Proto: &pr, ZoneID: &zone,
		DeviceID: &dev, InIf: &ii, OutIf: &io, IPVersion: &ipv,
	})
	want := []string{
		"src_ip=2001:db8::/32", "dst_ip=1.2.3.4", "src_port=1234", "dst_port=443",
		"proto=6", "zone_id=101", "device_id=7", "in_if=12", "out_if=13", "ip_version=6",
	}
	if len(got) != len(want) {
		t.Fatalf("FilterSummary len = %d, want %d (%v)", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("FilterSummary[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}
