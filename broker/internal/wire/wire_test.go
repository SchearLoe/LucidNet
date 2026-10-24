package wire

import (
	"bytes"
	"testing"
)

func TestWriterReaderRoundtrip(t *testing.T) {
	var w Writer
	w.String(3, "10.1.1.1")
	w.Int(1, 1234567890)
	w.Uint(13, 42)
	w.BytesField(7, bytes.Repeat([]byte{0xab}, 16))
	w.Bool(2, true)

	rd := NewReader(w.Bytes())
	seen := map[int]Field{}
	for {
		f, err := rd.Next()
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		if f.Number == 0 {
			break
		}
		seen[f.Number] = f
	}
	if got := string(seen[3].Bytes); got != "10.1.1.1" {
		t.Errorf("field 3 = %q", got)
	}
	if got := int64(seen[1].Varint); got != 1234567890 {
		t.Errorf("field 1 = %d", got)
	}
	if got := seen[13].Varint; got != 42 {
		t.Errorf("field 13 = %d", got)
	}
	if len(seen[7].Bytes) != 16 {
		t.Errorf("field 7 len = %d", len(seen[7].Bytes))
	}
	if seen[2].Varint != 1 {
		t.Errorf("field 2 = %d", seen[2].Varint)
	}
}

func TestWriterSkipsZero(t *testing.T) {
	var w Writer
	w.Uint(5, 0)
	w.String(3, "")
	w.Int(1, 0)
	if len(w.Bytes()) != 0 {
		t.Errorf("zero values must not encode, got % x", w.Bytes())
	}
}

func TestReaderUnknownFieldSkipped(t *testing.T) {
	// 字段 99（向后兼容：未知字段跳过，docs/09 §0 只增不改）
	// tag = 99<<3 | 0 = 792 → varint {0x98, 0x06}，值 1
	raw := []byte{0x98, 0x06, 0x01}
	var msg Writer
	msg.Uint(1, 7)
	raw = append(raw, msg.Bytes()...)
	rd := NewReader(raw)
	f, err := rd.Next()
	if err != nil {
		t.Fatalf("parse unknown: %v", err)
	}
	if f.Number != 99 {
		t.Fatalf("field = %d", f.Number)
	}
	f2, err := rd.Next()
	if err != nil || f2.Number != 1 || f2.Varint != 7 {
		t.Fatalf("after unknown: f=%+v err=%v", f2, err)
	}
}

func TestReaderTruncated(t *testing.T) {
	rd := NewReader([]byte{0x08}) // tag 无载荷
	if _, err := rd.Next(); err == nil {
		t.Fatal("expect truncation error")
	}
}
