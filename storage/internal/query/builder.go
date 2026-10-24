package query

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"
)

// 查询约束（docs/dd/04 §2.1/§2.2：防打爆，产品层面显式提示）。
const (
	// MaxWindow —— 查询时间窗上限，超限引导走异步导出（docs/dd/04 §2.1）。
	MaxWindow = 6 * time.Hour
	// MaxFilters —— 维度条件上限（docs/dd/04 §2.1）。
	MaxFilters = 8
	// DefaultPageSize / MaxPageSize —— 返回行数（docs/dd/04 §2.1：默认 1,000，同步上限 10,000）。
	DefaultPageSize = 1000
	MaxPageSize     = 10_000
	// MaxOffsetPages —— 超过强制游标模式（docs/dd/04 §2.2：page>50 时强制游标）。
	MaxOffsetPages = 50
	// TotalEstimateCap —— total_estimate 截断阈值（docs/dd/04 §2.2：uniqExact 超 1000 万显示 ">10M"）。
	TotalEstimateCap = 10_000_000
)

// Builder 默认查询表：Distributed 包装表（docs/hld/04 §3；Inserter 直写本地表）。
const defaultTable = "flows_raw_all"

// chTimeLayout —— ClickHouse DateTime 字面量布局。
const chTimeLayout = "2006-01-02 15:04:05"

// 构建器哨兵错误（HTTP 层统一映射 400）。
var (
	ErrWindowTooLarge        = errors.New("time window exceeds 6h cap, use async export instead (docs/dd/04 §2.1)")
	ErrBadTimeRange          = errors.New("time_start/time_end invalid")
	ErrBadFilter             = errors.New("filter value out of range")
	ErrNoFilters             = errors.New("at least 1 dimension filter required (docs/dd/04 §2.1)")
	ErrTooManyFilters        = errors.New("more than 8 dimension filters (docs/dd/04 §2.1)")
	ErrBadField              = errors.New("field not in whitelist")
	ErrBadOrderBy            = errors.New("order_by not in whitelist")
	ErrCursorRequired        = errors.New("page beyond 50 requires cursor mode (docs/dd/04 §2.2)")
	ErrBadCursor             = errors.New("malformed cursor")
	ErrCursorWithCustomOrder = errors.New("cursor mode requires default order_by=time_second")
)

// fieldWhitelist —— 请求字段 → flows_raw 列名白名单（docs/dd/04 §2.2：
// 白名单字段→列名映射，禁止任意 SQL）。
var fieldWhitelist = map[string]string{
	"time_second": "time_second",
	"time_ms":     "time_ms",
	"exporter":    "exporter",
	"device_id":   "device_id",
	"in_if":       "in_if",
	"out_if":      "out_if",
	"src_ip":      "src_ip",
	"dst_ip":      "dst_ip",
	"src_port":    "src_port",
	"dst_port":    "dst_port",
	"proto":       "proto",
	"ip_version":  "ip_version",
	"packets":     "packets",
	"bytes":       "bytes",
	"tcp_flags":   "tcp_flags",
	"tos":         "tos",
	"sample_rate": "sample_rate",
	"src_as":      "src_as",
	"dst_as":      "dst_as",
	"app_id":      "app_id",
	"zone_id":     "zone_id",
	"if_role":     "if_role",
}

// DefaultFields —— 默认返回字段（docs/dd/04 §2.2 示例请求的 fields 列表）。
var DefaultFields = []string{
	"time_second", "src_ip", "src_port", "dst_ip", "dst_port", "proto",
	"bytes", "packets", "tcp_flags", "in_if", "out_if", "sample_rate",
}

// orderWhitelist —— 排序字段白名单。
var orderWhitelist = map[string]bool{
	"time_second": true,
	"bytes":       true,
	"packets":     true,
	"src_ip":      true,
	"dst_ip":      true,
	"src_port":    true,
	"dst_port":    true,
}

// cursorSortKey —— 游标续读排序键 = flows_raw 表 ORDER BY 键（docs/00 §4）。
// 行序依据；排序键完全相同的相邻行间序不保证（_batch 列契约缺口，见模块 README）。
const cursorSortKey = "time_second, exporter, zone_id, in_if, out_if, proto, dst_port, src_ip"

// Filters —— 过滤条件（docs/dd/04 §2.2 filters；指针=nil=未提供）。
type Filters struct {
	SrcIP     string  `json:"src_ip,omitempty"`
	DstIP     string  `json:"dst_ip,omitempty"`
	SrcPort   *uint32 `json:"src_port,omitempty"`
	DstPort   *uint32 `json:"dst_port,omitempty"`
	Proto     *uint32 `json:"proto,omitempty"`
	ZoneID    *int32  `json:"zone_id,omitempty"`
	DeviceID  *uint32 `json:"device_id,omitempty"`
	InIf      *uint32 `json:"in_if,omitempty"`
	OutIf     *uint32 `json:"out_if,omitempty"`
	IPVersion *uint8  `json:"ip_version,omitempty"`
}

// Count 返回已提供的维度条件数（docs/dd/04 §2.1：≥1 且 ≤8）。
func (f Filters) Count() int {
	n := 0
	if strings.TrimSpace(f.SrcIP) != "" {
		n++
	}
	if strings.TrimSpace(f.DstIP) != "" {
		n++
	}
	for _, p := range []*uint32{f.SrcPort, f.DstPort, f.Proto, f.DeviceID, f.InIf, f.OutIf} {
		if p != nil {
			n++
		}
	}
	if f.ZoneID != nil {
		n++
	}
	if f.IPVersion != nil {
		n++
	}
	return n
}

// SearchRequest —— POST /api/v1/flows/search 请求体（docs/dd/04 §2.2）。
// 时间参数单位 = epoch 秒（docs/09 §6 2026-10-25 裁定：跨模块查询 API 统一
// epoch 秒，对齐 ClickHouse time 列秒精度）。
type SearchRequest struct {
	TimeStart int64    `json:"time_start"` // epoch 秒
	TimeEnd   int64    `json:"time_end"`   // epoch 秒
	Filters   Filters  `json:"filters"`
	OrderBy   string   `json:"order_by"`
	Desc      bool     `json:"desc"`
	Page      int      `json:"page"`
	PageSize  int      `json:"page_size"`
	Fields    []string `json:"fields"`
	Cursor    string   `json:"cursor"` // base64 游标；提供即进入游标模式
}

// Built —— 构建产物（骨架回显 SQL；接 CH 执行后填充 rows/total_estimate）。
type Built struct {
	SQL         string
	EstimateSQL string
	Fields      []string
	Page        int
	PageSize    int
	CursorMode  bool
}

// Builder —— SQL 构建器（docs/dd/04 §2.2）。
type Builder struct {
	table string
}

// Option —— Builder 配置项。
type Option func(*Builder)

// WithTable 覆盖查询表（默认 flows_raw_all；单测可指向本地表名）。
func WithTable(t string) Option { return func(b *Builder) { b.table = t } }

// NewBuilder 构造构建器。
func NewBuilder(opts ...Option) *Builder {
	b := &Builder{table: defaultTable}
	for _, o := range opts {
		o(b)
	}
	return b
}

// Build 校验请求并生成查询/估算 SQL。
func (b *Builder) Build(req SearchRequest) (Built, error) {
	start, end, err := validateWindow(req)
	if err != nil {
		return Built{}, err
	}
	conds, err := b.filterConds(req.Filters)
	if err != nil {
		return Built{}, err
	}
	fields, err := resolveFields(req.Fields)
	if err != nil {
		return Built{}, err
	}
	orderBy, err := resolveOrder(req.OrderBy)
	if err != nil {
		return Built{}, err
	}
	page, size, cursorMode, err := resolvePaging(req, orderBy)
	if err != nil {
		return Built{}, err
	}

	var cur *Cursor
	if cursorMode {
		c, err := DecodeCursor(req.Cursor)
		if err != nil {
			return Built{}, err
		}
		cur = &c
	}

	sql, err := b.buildSQL(fields, start, end, conds, orderBy, req.Desc, page, size, cur)
	if err != nil {
		return Built{}, err
	}
	estSQL, err := b.buildEstimateSQL(start, end, conds)
	if err != nil {
		return Built{}, err
	}
	return Built{
		SQL:         sql,
		EstimateSQL: estSQL,
		Fields:      fields,
		Page:        page,
		PageSize:    size,
		CursorMode:  cursorMode,
	}, nil
}

func validateWindow(req SearchRequest) (time.Time, time.Time, error) {
	if req.TimeStart <= 0 || req.TimeEnd <= req.TimeStart {
		return time.Time{}, time.Time{}, fmt.Errorf("validate window: start=%d end=%d: %w", req.TimeStart, req.TimeEnd, ErrBadTimeRange)
	}
	start := time.Unix(req.TimeStart, 0).UTC()
	end := time.Unix(req.TimeEnd, 0).UTC()
	if end.Sub(start) > MaxWindow {
		return time.Time{}, time.Time{}, fmt.Errorf("validate window: %s: %w", end.Sub(start), ErrWindowTooLarge)
	}
	return start, end, nil
}

// filterConds —— 过滤条件 → WHERE 片段（全部经白名单/数值校验，杜绝注入）。
func (b *Builder) filterConds(f Filters) ([]string, error) {
	var conds []string
	if s := strings.TrimSpace(f.SrcIP); s != "" {
		c, err := ipCond("src_ip", s)
		if err != nil {
			return nil, fmt.Errorf("filter src_ip: %w", err)
		}
		conds = append(conds, c)
	}
	if s := strings.TrimSpace(f.DstIP); s != "" {
		c, err := ipCond("dst_ip", s)
		if err != nil {
			return nil, fmt.Errorf("filter dst_ip: %w", err)
		}
		conds = append(conds, c)
	}
	if f.SrcPort != nil {
		if *f.SrcPort > 65535 {
			return nil, fmt.Errorf("filter src_port %d exceeds UInt16: %w", *f.SrcPort, ErrBadFilter)
		}
		conds = append(conds, "src_port = "+strconv.FormatUint(uint64(*f.SrcPort), 10))
	}
	if f.DstPort != nil {
		if *f.DstPort > 65535 {
			return nil, fmt.Errorf("filter dst_port %d exceeds UInt16: %w", *f.DstPort, ErrBadFilter)
		}
		conds = append(conds, "dst_port = "+strconv.FormatUint(uint64(*f.DstPort), 10))
	}
	if f.Proto != nil {
		if *f.Proto == 0 || *f.Proto > 255 {
			return nil, fmt.Errorf("filter proto %d not in [1,255]: %w", *f.Proto, ErrBadFilter)
		}
		conds = append(conds, "proto = "+strconv.FormatUint(uint64(*f.Proto), 10))
	}
	if f.ZoneID != nil {
		// 0=未命中为合法显式条件
		conds = append(conds, "zone_id = "+strconv.FormatInt(int64(*f.ZoneID), 10))
	}
	if f.DeviceID != nil {
		conds = append(conds, "device_id = "+strconv.FormatUint(uint64(*f.DeviceID), 10))
	}
	if f.InIf != nil {
		conds = append(conds, "in_if = "+strconv.FormatUint(uint64(*f.InIf), 10))
	}
	if f.OutIf != nil {
		conds = append(conds, "out_if = "+strconv.FormatUint(uint64(*f.OutIf), 10))
	}
	if f.IPVersion != nil {
		if *f.IPVersion != 4 && *f.IPVersion != 6 {
			return nil, fmt.Errorf("filter ip_version %d not in {4,6}: %w", *f.IPVersion, ErrBadFilter)
		}
		conds = append(conds, "ip_version = "+strconv.FormatUint(uint64(*f.IPVersion), 10))
	}
	n := f.Count()
	if n == 0 {
		return nil, ErrNoFilters
	}
	if n > MaxFilters {
		return nil, fmt.Errorf("%d filters: %w", n, ErrTooManyFilters)
	}
	return conds, nil
}

// ipCond —— IP/前缀条件（docs/dd/04 §2.2：bloom for ip 下推）。
// 单 IP：等值 toIPv6('…')，v4 字面量先转 ::ffff: 映射（docs/00 §1）；
// 前缀：isIPAddressInRange(col, 'cidr')，v4 前缀归一化为 96+bits 的
// ::ffff: 映射前缀——CH isIPAddressInRange 不跨族匹配，flows_raw IPv6 列
// 中存的是 v4-mapped 地址，裸 v4 前缀会恒为假。
func ipCond(col, val string) (string, error) {
	if strings.Contains(val, "/") {
		p, err := netip.ParsePrefix(val)
		if err != nil {
			return "", fmt.Errorf("parse prefix %q: %w", val, ErrBadFilter)
		}
		s := p.String()
		if p.Addr().Is4() {
			m := p.Masked()
			s = "::ffff:" + m.Addr().String() + "/" + strconv.Itoa(96+p.Bits())
		}
		return fmt.Sprintf("isIPAddressInRange(%s, '%s')", col, s), nil
	}
	lit, err := ipLiteral(val)
	if err != nil {
		return "", err
	}
	return col + " = " + lit, nil
}

// ipLiteral —— 解析 IP 为 CH IPv6 字面量 toIPv6('…')；v4 一律转 ::ffff: 映射
// （docs/00 §1），与 flows_raw IPv6 列存储一致。
func ipLiteral(val string) (string, error) {
	ip, err := netip.ParseAddr(val)
	if err != nil {
		return "", fmt.Errorf("parse ip %q: %w", val, ErrBadFilter)
	}
	if ip.Is4() {
		ip = netip.AddrFrom16(ip.As16())
	}
	return "toIPv6('" + ip.String() + "')", nil
}

// CheckFields —— 校验字段白名单并返回去重列（供 export 任务模型复用；
// docs/dd/04 §2.2：白名单字段→列名映射，禁止任意 SQL）。
// 入参为空时返回 DefaultFields。
func CheckFields(fields []string) ([]string, error) { return resolveFields(fields) }

func resolveFields(req []string) ([]string, error) {
	if len(req) == 0 {
		return slices.Clone(DefaultFields), nil
	}
	seen := make(map[string]bool, len(req))
	out := make([]string, 0, len(req))
	for _, f := range req {
		col, ok := fieldWhitelist[f]
		if !ok {
			return nil, fmt.Errorf("resolve fields: %q: %w", f, ErrBadField)
		}
		if !seen[col] {
			seen[col] = true
			out = append(out, col)
		}
	}
	return out, nil
}

func resolveOrder(req string) (string, error) {
	if req == "" {
		return "time_second", nil
	}
	if !orderWhitelist[req] {
		return "", fmt.Errorf("resolve order: %q: %w", req, ErrBadOrderBy)
	}
	return req, nil
}

func resolvePaging(req SearchRequest, orderBy string) (page, size int, cursorMode bool, err error) {
	page = req.Page
	if page <= 0 {
		page = 1
	}
	size = req.PageSize
	if size <= 0 {
		size = DefaultPageSize
	}
	if size > MaxPageSize {
		size = MaxPageSize // 同步上限 10,000（docs/dd/04 §2.1）
	}
	cursorMode = req.Cursor != ""
	if cursorMode && req.OrderBy != "" && req.OrderBy != "time_second" {
		return 0, 0, false, fmt.Errorf("resolve paging: order_by=%q: %w", req.OrderBy, ErrCursorWithCustomOrder)
	}
	if !cursorMode && page > MaxOffsetPages {
		return 0, 0, false, fmt.Errorf("resolve paging: page=%d: %w", page, ErrCursorRequired)
	}
	return page, size, cursorMode, nil
}

func (b *Builder) buildSQL(fields []string, start, end time.Time, conds []string,
	orderBy string, desc bool, page, size int, cur *Cursor,
) (string, error) {
	var sb strings.Builder
	sb.WriteString("SELECT ")
	sb.WriteString(strings.Join(fields, ", "))
	sb.WriteString("\nFROM ")
	sb.WriteString(b.table)
	sb.WriteString("\nWHERE ")
	parts, err := whereParts(start, end, conds, cur)
	if err != nil {
		return "", err
	}
	sb.WriteString(strings.Join(parts, "\n  AND "))
	if cur != nil {
		// 游标模式固定按表排序键升序续读（确定性分页）
		sb.WriteString("\nORDER BY (" + cursorSortKey + ") ASC")
	} else {
		dir := "ASC"
		if desc {
			dir = "DESC"
		}
		sb.WriteString("\nORDER BY " + orderBy + " " + dir)
	}
	offset := (page - 1) * size
	if cur != nil {
		offset = 0
	}
	sb.WriteString("\nLIMIT " + strconv.Itoa(size))
	if offset > 0 {
		sb.WriteString(" OFFSET " + strconv.Itoa(offset))
	}
	return sb.String(), nil
}

// buildEstimateSQL —— total_estimate 查询（docs/dd/04 §2.2）。
// 骨架用 count()；服务层以 TotalEstimateCap 截断展示 ">10M"（接 CH 执行 TODO）。
func (b *Builder) buildEstimateSQL(start, end time.Time, conds []string) (string, error) {
	var sb strings.Builder
	sb.WriteString("SELECT count() AS total_estimate\nFROM ")
	sb.WriteString(b.table)
	sb.WriteString("\nWHERE ")
	parts, err := whereParts(start, end, conds, nil)
	if err != nil {
		return "", err
	}
	sb.WriteString(strings.Join(parts, "\n  AND "))
	return sb.String(), nil
}

// whereParts —— 时间窗（半开区间）+ 分区裁剪 + 条件 + 游标谓词。
func whereParts(start, end time.Time, conds []string, cur *Cursor) ([]string, error) {
	s := start.Format(chTimeLayout)
	e := end.Format(chTimeLayout)
	parts := []string{
		fmt.Sprintf("time_second >= toDateTime('%s')", s),
		fmt.Sprintf("time_second < toDateTime('%s')", e),
		// 分区裁剪：PARTITION BY toYYYYMMDD(time_second)（docs/00 §4）
		fmt.Sprintf("toYYYYMMDD(time_second) BETWEEN toYYYYMMDD(toDateTime('%s')) AND toYYYYMMDD(toDateTime('%s'))", s, e),
	}
	parts = append(parts, conds...)
	if cur != nil {
		c, err := cur.predicate()
		if err != nil {
			return nil, err
		}
		parts = append(parts, c)
	}
	return parts, nil
}

// quoteSQL —— 单引号字面量转义（IP/字符串均已先行校验，此处纵深防御）。
func quoteSQL(s string) string {
	return strings.NewReplacer(`\`, `\\`, `'`, `\'`).Replace(s)
}

// Cursor —— 深分页游标负载（docs/dd/04 §2.2）。
// 注：dd/04 §2.2 提到的 `_batch` 列在 docs/00 §4 flows_raw DDL 中不存在
// （契约缺口见模块 README），骨架以表排序键元组作为续读依据。
type Cursor struct {
	TimeSecond int64  `json:"ts"` // epoch 秒
	Exporter   string `json:"exp"`
	ZoneID     int32  `json:"z"`
	InIf       uint32 `json:"ii"`
	OutIf      uint32 `json:"io"`
	Proto      uint32 `json:"p"`
	DstPort    uint32 `json:"dp"`
	SrcIP      string `json:"sip"` // 展示形（v4 为 ::ffff: 映射）
}

// Encode 序列化为 base64(JSON)。
func (c Cursor) Encode() string {
	b, err := json.Marshal(c)
	if err != nil {
		return ""
	}
	return base64.StdEncoding.EncodeToString(b)
}

// DecodeCursor 解析 base64(JSON) 游标。
func DecodeCursor(s string) (Cursor, error) {
	if s == "" {
		return Cursor{}, fmt.Errorf("decode cursor: empty: %w", ErrBadCursor)
	}
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return Cursor{}, fmt.Errorf("decode cursor base64: %w", ErrBadCursor)
	}
	var c Cursor
	if err := json.Unmarshal(b, &c); err != nil {
		// 双重错误链：保留底层解析错误，同时挂哨兵供 HTTP 层映射 400
		return Cursor{}, fmt.Errorf("decode cursor json: %v: %w", err, ErrBadCursor)
	}
	if c.TimeSecond <= 0 {
		return Cursor{}, fmt.Errorf("decode cursor: time_second %d: %w", c.TimeSecond, ErrBadCursor)
	}
	if _, err := ipLiteral(c.SrcIP); err != nil {
		return Cursor{}, fmt.Errorf("decode cursor src_ip: %w", ErrBadCursor)
	}
	return c, nil
}

// predicate —— 游标元组比较谓词（元组 > 上一页末行排序键）。
// 元组元素为字面量（ipLiteral），非条件表达式。
func (c Cursor) predicate() (string, error) {
	src, err := ipLiteral(c.SrcIP)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf(
		"(%s) > (toDateTime('%s'), '%s', %d, %d, %d, %d, %d, %s)",
		cursorSortKey,
		time.Unix(c.TimeSecond, 0).UTC().Format(chTimeLayout),
		quoteSQL(c.Exporter),
		c.ZoneID, c.InIf, c.OutIf, c.Proto, c.DstPort,
		src,
	), nil
}
