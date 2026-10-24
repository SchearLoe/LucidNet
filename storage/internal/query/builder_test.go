package query

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// baseReq —— 合法基准请求（epoch 秒，09 §6）。
func baseReq() SearchRequest {
	zone := int32(101)
	return SearchRequest{
		TimeStart: 1771901100, // 2026-02-24T02:45:00Z
		TimeEnd:   1771901100 + 900,
		Filters:   Filters{ZoneID: &zone},
	}
}

// TestBuildBasicSQL —— 基础 SQL 生成逐段断言（时间窗 + 分区裁剪 + 条件 + 排序分页）。
func TestBuildBasicSQL(t *testing.T) {
	b := NewBuilder()
	built, err := b.Build(baseReq())
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	wantSQL := strings.Join([]string{
		"SELECT " + strings.Join(DefaultFields, ", "),
		"FROM flows_raw_all",
		"WHERE time_second >= toDateTime('2026-02-24 02:45:00')",
		"  AND time_second < toDateTime('2026-02-24 03:00:00')",
		"  AND toYYYYMMDD(time_second) BETWEEN toYYYYMMDD(toDateTime('2026-02-24 02:45:00')) AND toYYYYMMDD(toDateTime('2026-02-24 03:00:00'))",
		"  AND zone_id = 101",
		"ORDER BY time_second ASC",
		"LIMIT 1000",
	}, "\n")
	if built.SQL != wantSQL {
		t.Errorf("SQL mismatch:\n--- want ---\n%s\n--- got ---\n%s", wantSQL, built.SQL)
	}

	wantEst := strings.Join([]string{
		"SELECT count() AS total_estimate",
		"FROM flows_raw_all",
		"WHERE time_second >= toDateTime('2026-02-24 02:45:00')",
		"  AND time_second < toDateTime('2026-02-24 03:00:00')",
		"  AND toYYYYMMDD(time_second) BETWEEN toYYYYMMDD(toDateTime('2026-02-24 02:45:00')) AND toYYYYMMDD(toDateTime('2026-02-24 03:00:00'))",
		"  AND zone_id = 101",
	}, "\n")
	if built.EstimateSQL != wantEst {
		t.Errorf("estimate SQL mismatch:\n--- want ---\n%s\n--- got ---\n%s", wantEst, built.EstimateSQL)
	}
	if built.Page != 1 || built.PageSize != DefaultPageSize || built.CursorMode {
		t.Errorf("paging = %d/%d cursor=%v", built.Page, built.PageSize, built.CursorMode)
	}
}

// TestBuildFiltersSQL —— 维度条件（8 个上限内）+ 排序 + 分页 OFFSET（dd/04 §2.2）。
func TestBuildFiltersSQL(t *testing.T) {
	sp, dp, pr, dev, ii, ipv := uint32(1234), uint32(443), uint32(6), uint32(7), uint32(12), uint8(6)
	req := baseReq()
	req.Filters = Filters{
		SrcIP: "1.2.3.4", DstIP: "2001:db8::/32",
		SrcPort: &sp, DstPort: &dp, Proto: &pr,
		DeviceID: &dev, InIf: &ii, IPVersion: &ipv,
	}
	req.OrderBy = "bytes"
	req.Desc = true
	req.Page = 3
	req.PageSize = 100
	req.Fields = []string{"time_second", "src_ip", "bytes", "bytes"} // 重复列去重

	built, err := NewBuilder().Build(req)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	for _, want := range []string{
		"src_ip = toIPv6('::ffff:1.2.3.4')", // v4 单 IP 归一化映射（docs/00 §1）
		"isIPAddressInRange(dst_ip, '2001:db8::/32')",
		"src_port = 1234", "dst_port = 443", "proto = 6",
		"device_id = 7", "in_if = 12", "ip_version = 6",
		"ORDER BY bytes DESC", "LIMIT 100", "OFFSET 200",
	} {
		if !strings.Contains(built.SQL, want) {
			t.Errorf("SQL missing %q:\n%s", want, built.SQL)
		}
	}
	if got := strings.Count(built.SQL, "bytes"); got < 2 { // select 1 + order 1
		t.Errorf("dedup fields broken: %s", built.SQL)
	}
}

// TestBuildV4Prefix —— v4 前缀归一化为 ::ffff: 映射前缀（isIPAddressInRange 跨族不可比）。
func TestBuildV4Prefix(t *testing.T) {
	req := baseReq()
	req.Filters = Filters{SrcIP: "1.2.3.0/24"}
	built, err := NewBuilder().Build(req)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if !strings.Contains(built.SQL, "isIPAddressInRange(src_ip, '::ffff:1.2.3.0/120')") {
		t.Errorf("v4 prefix not normalized:\n%s", built.SQL)
	}
}

// TestBuildWindowCap —— 时间窗 >6h 拒绝（dd/04 §2.1 上限，超限引导异步导出）。
func TestBuildWindowCap(t *testing.T) {
	req := baseReq()
	req.TimeEnd = req.TimeStart + int64((6*time.Hour)/time.Second) // 恰 6h：允许
	if _, err := NewBuilder().Build(req); err != nil {
		t.Fatalf("6h window must pass: %v", err)
	}
	req.TimeEnd = req.TimeStart + int64((6*time.Hour)/time.Second) + 1
	_, err := NewBuilder().Build(req)
	if !errors.Is(err, ErrWindowTooLarge) {
		t.Fatalf("6h+1s err = %v, want ErrWindowTooLarge", err)
	}
}

// TestBuildFilterRules —— 条件数下限/上限与取值范围校验表驱动。
func TestBuildFilterRules(t *testing.T) {
	u32 := func(v uint32) *uint32 { return &v }
	cases := []struct {
		name string
		mut  func(*SearchRequest)
		want error
	}{
		{"no filters", func(r *SearchRequest) { r.Filters = Filters{} }, ErrNoFilters},
		{"too many filters", func(r *SearchRequest) {
			sp, dp, pr, dev, ii, io := u32(1), u32(2), u32(3), u32(4), u32(5), u32(6)
			ipv := uint8(4)
			r.Filters = Filters{SrcIP: "1.1.1.1", DstIP: "2.2.2.2",
				SrcPort: sp, DstPort: dp, Proto: pr, DeviceID: dev, InIf: ii, OutIf: io, IPVersion: &ipv}
		}, ErrTooManyFilters},
		{"bad ip", func(r *SearchRequest) { r.Filters = Filters{SrcIP: "not-an-ip"} }, ErrBadFilter},
		{"bad prefix", func(r *SearchRequest) { r.Filters = Filters{DstIP: "1.2.3.4/99"} }, ErrBadFilter},
		{"src_port overflow", func(r *SearchRequest) { r.Filters = Filters{SrcPort: u32(65536)} }, ErrBadFilter},
		{"dst_port overflow", func(r *SearchRequest) { r.Filters = Filters{DstPort: u32(70000)} }, ErrBadFilter},
		{"proto zero", func(r *SearchRequest) { r.Filters = Filters{Proto: u32(0)} }, ErrBadFilter},
		{"proto overflow", func(r *SearchRequest) { r.Filters = Filters{Proto: u32(256)} }, ErrBadFilter},
		{"bad ip_version", func(r *SearchRequest) { v := uint8(5); r.Filters = Filters{IPVersion: &v} }, ErrBadFilter},
		{"zero time", func(r *SearchRequest) { r.TimeStart = 0 }, ErrBadTimeRange},
		{"end<=start", func(r *SearchRequest) { r.TimeEnd = r.TimeStart }, ErrBadTimeRange},
		{"bad field", func(r *SearchRequest) { r.Fields = []string{"* FROM x"} }, ErrBadField},
		{"bad order", func(r *SearchRequest) { r.OrderBy = "1; DROP TABLE" }, ErrBadOrderBy},
		{"page>50 no cursor", func(r *SearchRequest) { r.Page = 51 }, ErrCursorRequired},
		{"page=50 ok", func(r *SearchRequest) { r.Page = 50 }, nil},
		{"cursor with custom order", func(r *SearchRequest) {
			r.Cursor = Cursor{TimeSecond: 1771901100, SrcIP: "1.2.3.4"}.Encode()
			r.OrderBy = "bytes"
		}, ErrCursorWithCustomOrder},
		{"cursor default order ok", func(r *SearchRequest) {
			r.Cursor = Cursor{TimeSecond: 1771901100, SrcIP: "1.2.3.4"}.Encode()
			r.OrderBy = "time_second"
		}, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req := baseReq()
			c.mut(&req)
			_, err := NewBuilder().Build(req)
			if c.want == nil {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if !errors.Is(err, c.want) {
				t.Fatalf("err = %v, want %v", err, c.want)
			}
		})
	}
}

// TestBuildCursorMode —— 游标模式：元组谓词 + 表排序键升序 + 无 OFFSET。
func TestBuildCursorMode(t *testing.T) {
	req := baseReq()
	cur := Cursor{
		TimeSecond: 1771901100, Exporter: "ex'p\"1", ZoneID: 101,
		InIf: 12, OutIf: 15, Proto: 6, DstPort: 443, SrcIP: "1.2.3.4",
	}
	req.Cursor = cur.Encode()
	req.PageSize = 200

	built, err := NewBuilder().Build(req)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if !built.CursorMode {
		t.Fatal("expect cursor mode")
	}
	for _, want := range []string{
		"ORDER BY (time_second, exporter, zone_id, in_if, out_if, proto, dst_port, src_ip) ASC",
		"LIMIT 200",
		"(toDateTime('2026-02-24 02:45:00'), 'ex\\'p\"1', 101, 12, 15, 6, 443, toIPv6('::ffff:1.2.3.4'))",
	} {
		if !strings.Contains(built.SQL, want) {
			t.Errorf("cursor SQL missing %q:\n%s", want, built.SQL)
		}
	}
	if strings.Contains(built.SQL, "OFFSET") {
		t.Errorf("cursor mode must not use OFFSET:\n%s", built.SQL)
	}
	if strings.Contains(built.SQL, "src_ip = toIPv6") {
		t.Errorf("tuple element must be a literal, not a condition:\n%s", built.SQL)
	}
}

// TestBuildPageSizeClamp —— page_size 上限 10,000 截断。
func TestBuildPageSizeClamp(t *testing.T) {
	req := baseReq()
	req.PageSize = 999_999
	built, err := NewBuilder().Build(req)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if built.PageSize != MaxPageSize {
		t.Errorf("page_size = %d, want %d", built.PageSize, MaxPageSize)
	}
}

// TestWithTable —— 查询表覆盖（本地表指向）。
func TestWithTable(t *testing.T) {
	built, err := NewBuilder(WithTable("flows_raw")).Build(baseReq())
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if !strings.Contains(built.SQL, "FROM flows_raw\n") {
		t.Errorf("table not overridden:\n%s", built.SQL)
	}
}

// TestCursorRoundtrip —— 游标编解码往返 + 非法输入。
func TestCursorRoundtrip(t *testing.T) {
	cur := Cursor{TimeSecond: 1771901100, Exporter: "10.0.0.1", SrcIP: "2001:db8::1", ZoneID: 7, DstPort: 80}
	got, err := DecodeCursor(cur.Encode())
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got != cur {
		t.Errorf("roundtrip = %+v, want %+v", got, cur)
	}
	for _, bad := range []string{"", "!!!", "e30=", "eyJ0cyI6MH0="} { // 空/非b64/{}/ts=0
		if _, err := DecodeCursor(bad); !errors.Is(err, ErrBadCursor) {
			t.Errorf("DecodeCursor(%q) err = %v, want ErrBadCursor", bad, err)
		}
	}
	// SrcIP 非法：JSON 合法但 IP 不合法
	badIP := Cursor{TimeSecond: 1, SrcIP: "bogus"}
	if _, err := DecodeCursor(badIP.Encode()); !errors.Is(err, ErrBadCursor) {
		t.Errorf("bad src_ip cursor err = %v, want ErrBadCursor", err)
	}
}

// TestCheckFields —— 白名单校验复用（export 任务模型用）。
func TestCheckFields(t *testing.T) {
	if got, err := CheckFields(nil); err != nil || len(got) != len(DefaultFields) {
		t.Fatalf("CheckFields(nil) = %v, %v", got, err)
	}
	if _, err := CheckFields([]string{"time_second; DROP"}); !errors.Is(err, ErrBadField) {
		t.Fatalf("err = %v, want ErrBadField", err)
	}
}

// TestFiltersCount —— 条件计数。
func TestFiltersCount(t *testing.T) {
	var f Filters
	if f.Count() != 0 {
		t.Fatalf("empty count = %d", f.Count())
	}
	if got := baseReq().Filters.Count(); got != 1 {
		t.Fatalf("zone only count = %d", got)
	}
}
