// Package wire —— proto3 线格式编解码原语（protobuf encoding 规范）。
//
// 存在原因：gen/go 代码生成尚未接入（proto/ 为线格式权威，docs/09 §0/§10），
// Broker 需要的少量消息（FlowRecord、Master 注册/心跳）先以本包手工编解码，
// 生成代码就绪后整体替换。字段与 proto/lucidnet/v1 严格一一对应，只增不改。
package wire

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
)

// proto3 wire type（仅用到本仓库出现的两类）。
const (
	WireVarint = 0
	WireBytes  = 2
)

// ErrTruncated —— 解析越界（输入被截断）。
var ErrTruncated = errors.New("wire: truncated protobuf input")

// Writer —— 累积式 proto3 编码器（零反射，字段按 proto 定义序写入）。
type Writer struct {
	Buf []byte
}

// Reset 复用底层缓冲。
func (w *Writer) Reset() { w.Buf = w.Buf[:0] }

// Bytes 返回已编码内容。
func (w *Writer) Bytes() []byte { return w.Buf }

func (w *Writer) tag(field int, wireType int) {
	w.Buf = binary.AppendUvarint(w.Buf, uint64(field)<<3|uint64(wireType))
}

// Uint 写 varint 标量字段（int32/int64/uint32/uint64/bool/enum）。
func (w *Writer) Uint(field int, v uint64) {
	if v == 0 {
		return // proto3 隐式存在：零值不编码
	}
	w.tag(field, WireVarint)
	w.Buf = binary.AppendUvarint(w.Buf, v)
}

// Int 写带符号整型（正数按 varint；负数按 int64 补码 10B 编码，本仓库无负数标量需求，
// zone_id 可为 0/正，int32 负值场景预留 zigzag 不必要——与 protoc int32 编码保持一致）。
func (w *Writer) Int(field int, v int64) {
	if v == 0 {
		return
	}
	w.tag(field, WireVarint)
	w.Buf = binary.AppendUvarint(w.Buf, uint64(v))
}

// Bool 写 bool 字段。
func (w *Writer) Bool(field int, v bool) {
	if !v {
		return
	}
	w.tag(field, WireVarint)
	w.Buf = append(w.Buf, 1)
}

// Bytes 写 bytes 字段；空切片不编码。
func (w *Writer) BytesField(field int, v []byte) {
	if len(v) == 0 {
		return
	}
	w.tag(field, WireBytes)
	w.Buf = binary.AppendUvarint(w.Buf, uint64(len(v)))
	w.Buf = append(w.Buf, v...)
}

// String 写 string 字段；空串不编码。
func (w *Writer) String(field int, v string) {
	if v == "" {
		return
	}
	w.tag(field, WireBytes)
	w.Buf = binary.AppendUvarint(w.Buf, uint64(len(v)))
	w.Buf = append(w.Buf, v...)
}

// Fixed32 写 fixed32/sfixed32/float 字段（即使 0 也编码，proto3 fixed 类型仍带隐式存在）。
func (w *Writer) Fixed32(field int, v uint32) {
	w.tag(field, 5)
	w.Buf = binary.LittleEndian.AppendUint32(w.Buf, v)
}

// Fixed64 写 fixed64/sfixed64/double 字段。
func (w *Writer) Fixed64(field int, v uint64) {
	w.tag(field, 1)
	w.Buf = binary.LittleEndian.AppendUint64(w.Buf, v)
}

// Reader —— proto3 解码器（顺序遍历字段；未知字段自动跳过，向前兼容 docs/09 §0）。
type Reader struct {
	Buf []byte
}

// NewReader 构造解码器。
func NewReader(b []byte) *Reader { return &Reader{Buf: b} }

// Field —— 当前字段（Next 返回 true 后有效）。
type Field struct {
	Number   int
	WireType int
	Varint   uint64
	Fixed32  uint32
	Fixed64  uint64
	Bytes    []byte
}

// Next 推进到下一个字段；输入耗尽返回 false。
func (r *Reader) Next() (Field, error) {
	if len(r.Buf) == 0 {
		return Field{}, nil
	}
	tag, n := binary.Uvarint(r.Buf)
	if n <= 0 {
		return Field{}, fmt.Errorf("wire: bad field tag: %w", ErrTruncated)
	}
	r.Buf = r.Buf[n:]
	f := Field{Number: int(tag >> 3), WireType: int(tag & 0x7)}
	switch f.WireType {
	case WireVarint:
		v, n := binary.Uvarint(r.Buf)
		if n <= 0 {
			return Field{}, fmt.Errorf("wire: field %d varint: %w", f.Number, ErrTruncated)
		}
		r.Buf = r.Buf[n:]
		f.Varint = v
	case 1: // fixed64
		if len(r.Buf) < 8 {
			return Field{}, fmt.Errorf("wire: field %d fixed64: %w", f.Number, ErrTruncated)
		}
		f.Fixed64 = binary.LittleEndian.Uint64(r.Buf)
		r.Buf = r.Buf[8:]
	case WireBytes:
		l, n := binary.Uvarint(r.Buf)
		if n <= 0 || uint64(len(r.Buf)-n) < l {
			return Field{}, fmt.Errorf("wire: field %d bytes: %w", f.Number, ErrTruncated)
		}
		f.Bytes = r.Buf[n : n+int(l)]
		r.Buf = r.Buf[n+int(l):]
	case 5: // fixed32
		if len(r.Buf) < 4 {
			return Field{}, fmt.Errorf("wire: field %d fixed32: %w", f.Number, ErrTruncated)
		}
		f.Fixed32 = binary.LittleEndian.Uint32(r.Buf)
		r.Buf = r.Buf[4:]
	default:
		return Field{}, fmt.Errorf("wire: field %d unsupported wire type %d", f.Number, f.WireType)
	}
	return f, nil
}

// Float64 把 fixed64 字段读作 double。
func (f Field) Float64() float64 { return math.Float64frombits(f.Fixed64) }

// Float32 把 fixed32 字段读作 float。
func (f Field) Float32() float32 { return math.Float32frombits(f.Fixed32) }
