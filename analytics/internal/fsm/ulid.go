package fsm

import (
	"crypto/rand"
	"time"
)

// ulidAlphabet —— Crockford Base32（ULID 标准，dd/03 §6.1：每攻击一个 ULID）。
const ulidAlphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// NewULID 生成 26 字符 ULID：48bit 毫秒时间戳 + 80bit 随机数，
// 同毫秒内按时间有序（随机部分不保证单调，骨架满足攻击标识用途）。
func NewULID(now time.Time) string {
	var b [16]byte
	ms := now.UnixMilli()
	b[0] = byte(ms >> 40)
	b[1] = byte(ms >> 32)
	b[2] = byte(ms >> 24)
	b[3] = byte(ms >> 16)
	b[4] = byte(ms >> 8)
	b[5] = byte(ms)
	// crypto/rand.Read 自 Go 1.24 起保证填满且不返回错误。
	_, _ = rand.Read(b[6:])

	var id [26]byte
	// 10 字符时间（48bit）
	id[0] = ulidAlphabet[(b[0]&224)>>5]
	id[1] = ulidAlphabet[b[0]&31]
	id[2] = ulidAlphabet[(b[1]&248)>>3]
	id[3] = ulidAlphabet[((b[1]&7)<<2)|((b[2]&192)>>6)]
	id[4] = ulidAlphabet[(b[2]&62)>>1]
	id[5] = ulidAlphabet[((b[2]&1)<<4)|((b[3]&240)>>4)]
	id[6] = ulidAlphabet[((b[3]&15)<<1)|((b[4]&128)>>7)]
	id[7] = ulidAlphabet[(b[4]&124)>>2]
	id[8] = ulidAlphabet[((b[4]&3)<<3)|((b[5]&224)>>5)]
	id[9] = ulidAlphabet[b[5]&31]
	// 16 字符随机（80bit）
	id[10] = ulidAlphabet[(b[6]&248)>>3]
	id[11] = ulidAlphabet[((b[6]&7)<<2)|((b[7]&192)>>6)]
	id[12] = ulidAlphabet[(b[7]&62)>>1]
	id[13] = ulidAlphabet[((b[7]&1)<<4)|((b[8]&240)>>4)]
	id[14] = ulidAlphabet[((b[8]&15)<<1)|((b[9]&128)>>7)]
	id[15] = ulidAlphabet[(b[9]&124)>>2]
	id[16] = ulidAlphabet[((b[9]&3)<<3)|((b[10]&224)>>5)]
	id[17] = ulidAlphabet[b[10]&31]
	id[18] = ulidAlphabet[(b[11]&248)>>3]
	id[19] = ulidAlphabet[((b[11]&7)<<2)|((b[12]&192)>>6)]
	id[20] = ulidAlphabet[(b[12]&62)>>1]
	id[21] = ulidAlphabet[((b[12]&1)<<4)|((b[13]&240)>>4)]
	id[22] = ulidAlphabet[((b[13]&15)<<1)|((b[14]&128)>>7)]
	id[23] = ulidAlphabet[(b[14]&124)>>2]
	id[24] = ulidAlphabet[((b[14]&3)<<3)|((b[15]&224)>>5)]
	id[25] = ulidAlphabet[b[15]&31]
	return string(id[:])
}
