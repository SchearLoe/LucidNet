package export

import (
	"context"
	"fmt"
	"strconv"
)

// RowSource —— 导出取数接口（dd/04 §5.2 执行器第 1 步：按 (day, exporter)
// 切片子查询 + 游标流式读取；真实实现接 CH 游标查询 max_block_size=65536，
// TODO）。游标语义由实现自定义，Runner 只做透传/持久化。
type RowSource interface {
	// FetchRows 返回 cursor 之后的一批行与新游标（next="" 表示已耗尽）。
	FetchRows(ctx context.Context, j Job, cursor string, limit int) (rows []Row, next string, err error)
	// EstimateRows 返回总行数估计（0=未知；进度展示降级为已处理行数）。
	EstimateRows(ctx context.Context, j Job) int64
}

// SequenceSource —— 确定性合成行源（联调桩/cmd 空跑/单测）：固定行数、
// 内容按序号生成（v4 映射与 v6 交替、flags/端口变化），游标 = 已读行数。
type SequenceSource struct {
	Total int64
}

// NewSequenceSource 构造 total 行的合成源。
func NewSequenceSource(total int64) *SequenceSource { return &SequenceSource{Total: total} }

// EstimateRows 返回总行数。
func (s *SequenceSource) EstimateRows(_ context.Context, _ Job) int64 { return s.Total }

// FetchRows 按 cursor（已读行数）顺序产出行。
func (s *SequenceSource) FetchRows(_ context.Context, _ Job, cursor string, limit int) ([]Row, string, error) {
	if limit <= 0 {
		return nil, "", fmt.Errorf("sequence source fetch: limit %d must be positive", limit)
	}
	off := int64(0)
	if cursor != "" {
		v, err := strconv.ParseInt(cursor, 10, 64)
		if err != nil || v < 0 {
			return nil, "", fmt.Errorf("sequence source fetch: bad cursor %q", cursor)
		}
		off = v
	}
	if off >= s.Total {
		return nil, "", nil
	}
	n := s.Total - off
	if int64(limit) < n {
		n = int64(limit)
	}
	rows := make([]Row, 0, n)
	for i := int64(0); i < n; i++ {
		rows = append(rows, syntheticRow(off+i))
	}
	next := ""
	if off+n < s.Total {
		next = strconv.FormatInt(off+n, 10)
	}
	return rows, next, nil
}

// syntheticRow —— 第 i 行合成数据（确定性：时间/端口/flags/采样率随序号变化，
// v4(奇数行 ::ffff: 映射) 与 v6(偶数行) 交替）。
func syntheticRow(i int64) Row {
	const baseMs = 1771901100123 // 2026-02-24T03:25:00.123Z 附近
	v6 := [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	v6[15] = byte(i + 1)
	v4 := [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 1, byte(i >> 8), byte(i)}
	r := Row{
		TimeStartMs: baseMs + i*1000,
		TimeEndMs:   baseMs + i*1000 + 277,
		Proto:       6,
		IPVersion:   6,
		SrcPort:     uint16(40000 + i%1000),
		DstPort:     uint16(80 + i%3),
		Packets:     uint64(10 + i%120),
		Bytes:       uint64(640 + i%8600),
		TCPFlags:    uint8(i % 8), // 0..7：覆盖 FIN/SYN/RST/PSH 单符号与组合
		InIf:        uint32(3 + i%8),
		OutIf:       uint32(4 + i%8),
		SampleRate:  uint32(1 + i%100),
	}
	if i%2 == 1 {
		r.SrcIP = v4
		r.DstIP = v4
		r.IPVersion = 4
	} else {
		r.SrcIP = v6
		r.DstIP = v6
	}
	return r
}
