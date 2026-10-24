package zone

import (
	"math"
	"math/bits"
)

// radix —— 路径压缩二进制 trie（前缀 LPM，dd/02 §3.3“前缀按族分 radix 树”）。
//
// 键统一 128bit（key128；v4 放高 32bit，低 96bit 为 0），按族分树：keyLen=32（v4）/128（v6）。
// 每个节点持有一段压缩 skip 位串（左对齐：段第 i 位在 bit63-i）+ 可选 entry（zone_id + mask_len）。
// 构建期插入 + 查询两操作；不支持增量删除 —— 热更新走整树重建 + 原子换指针（matcher.go），
// 与“copy-on-write 指针替换”语义一致（dd/02 §3.3）。

// key128 —— 128bit 键，hi=bit0..63，lo=bit64..127。
type key128 struct {
	hi, lo uint64
}

// radixNode —— trie 节点。
type radixNode struct {
	child   [2]*radixNode
	skip    uint64 // 压缩段，左对齐；仅高 skipLen 位有效，低位恒 0
	skipLen uint8
	zone    int32 // has=true 时有效
	maskLen uint8 // has=true 时有效（该 entry 的前缀长度）
	has     bool
}

// radixTree —— 一棵按族定长的 LPM 树。
type radixTree struct {
	root   *radixNode
	keyLen int // 32（v4）或 128（v6）
}

// insert —— 构建期插入；(key, maskLen) 重复插入时后者覆盖。
func (t *radixTree) insert(k key128, maskLen int, zoneID int32) {
	t.root = insertNode(t.root, k, 0, maskLen, zoneID)
}

// lookup —— 最长前缀匹配：返回 (zone_id, 命中 entry 的 mask_len, 是否命中)。
func (t *radixTree) lookup(k key128) (zoneID int32, maskLen int, ok bool) {
	n := t.root
	pos := 0
	for n != nil {
		if commonBits(k, pos, n.skip, n.skipLen) < int(n.skipLen) {
			break // 在压缩段内分叉：更深层不可能有匹配
		}
		pos += int(n.skipLen)
		if n.has {
			zoneID, maskLen, ok = n.zone, int(n.maskLen), true
		}
		if pos >= t.keyLen {
			break
		}
		n = n.child[keyBit(k, pos)]
		pos++
	}
	return zoneID, maskLen, ok
}

// insertNode —— 递归插入；pos 为当前已消费的键位。
func insertNode(n *radixNode, k key128, pos, maskLen int, zoneID int32) *radixNode {
	if n == nil {
		return newChain(k, pos, maskLen, zoneID)
	}
	remaining := maskLen - pos
	c := commonBits(k, pos, n.skip, n.skipLen)
	if remaining < c {
		c = remaining
	}
	if c < int(n.skipLen) {
		// 在第 c 位分叉：上层节点持有公共前缀（保持左对齐：只保留高 c 位），
		// 旧/新子树各自下沉。注意左对齐段不能用 >> 截取（会错位），必须掩码保留高位。
		//
		// 子节点对齐约定（与 lookup/insertNode 尾部一致）：父节点 skip 段结束后第 1 位
		// 用作 child 下标并被下行路径消耗（pos++），子节点 skip 从分叉位之后开始。
		// rest 为旧节点剩余段（含分叉位，左对齐）；old 丢弃分叉位后从 pos+c+1 起步。
		rest := n.skip << uint(c)
		upper := &radixNode{skip: maskTopBits(n.skip, c), skipLen: uint8(c)}
		old := &radixNode{
			child:   n.child,
			skip:    rest << 1,
			skipLen: n.skipLen - uint8(c) - 1,
			zone:    n.zone,
			maskLen: n.maskLen,
			has:     n.has,
		}
		if c == remaining {
			// 新前缀在旧节点压缩段内结束 → entry 挂在上层节点
			upper.has = true
			upper.zone = zoneID
			upper.maskLen = uint8(maskLen)
			upper.child[skipBit(rest, 0)] = old
			return upper
		}
		b := keyBit(k, pos+c)
		upper.child[b] = newChain(k, pos+c+1, maskLen, zoneID)
		upper.child[b^1] = old
		return upper
	}
	pos += int(n.skipLen)
	if pos == maskLen {
		n.has = true
		n.zone = zoneID
		n.maskLen = uint8(maskLen)
		return n
	}
	b := keyBit(k, pos)
	n.child[b] = insertNode(n.child[b], k, pos+1, maskLen, zoneID)
	return n
}

// newChain —— 为 k[pos:maskLen] 建一条压缩链（每段 ≤64bit，跨 64bit 边界自动续链）。
func newChain(k key128, pos, maskLen int, zoneID int32) *radixNode {
	n := maskLen - pos
	if n > 64 {
		n = 64
	}
	node := &radixNode{skip: keyBits(k, pos, n), skipLen: uint8(n)}
	if end := pos + n; end == maskLen {
		node.has = true
		node.zone = zoneID
		node.maskLen = uint8(maskLen)
		return node
	} else {
		b := keyBit(k, end)
		node.child[b] = newChain(k, end+1, maskLen, zoneID)
		return node
	}
}

// keyBit —— 键第 i 位（0 = 最高位）。
func keyBit(k key128, i int) uint8 {
	if i < 64 {
		return uint8(k.hi >> uint(63-i) & 1)
	}
	return uint8(k.lo >> uint(127-i) & 1)
}

// skipBit —— 压缩段第 i 位。
func skipBit(skip uint64, i int) uint8 {
	return uint8(skip >> uint(63-i) & 1)
}

// keyBits —— 取 k[pos:pos+n] 左对齐到 uint64 高位；越界位读 0（n ≤ 64）。
func keyBits(k key128, pos, n int) uint64 {
	if n <= 0 {
		return 0
	}
	if n > 64 {
		n = 64
	}
	var v uint64
	switch {
	case pos >= 128:
		v = 0
	case pos >= 64:
		v = k.lo << uint(pos-64)
	case pos+n <= 64:
		v = k.hi << uint(pos)
	default:
		take := 64 - pos
		low := n - take
		v = k.hi << uint(pos)
		v |= (k.lo >> uint(64-low)) << uint(64-n)
	}
	if n >= 64 {
		return v
	}
	return v & (math.MaxUint64 << uint(64-n))
}

// maskTopBits —— 保留 v 的高 bits 位（左对齐不变），低位清零；bits=0 时返回 0。
func maskTopBits(v uint64, bits int) uint64 {
	if bits <= 0 {
		return 0
	}
	if bits >= 64 {
		return v
	}
	return v & (math.MaxUint64 << uint(64-bits))
}

// commonBits —— 键 k[pos:] 与压缩段 skip（skipLen 位，均左对齐）的公共前缀位数。
func commonBits(k key128, pos int, skip uint64, skipLen uint8) int {
	if skipLen == 0 {
		return 0
	}
	x := keyBits(k, pos, int(skipLen)) ^ skip
	if x == 0 {
		return int(skipLen)
	}
	return bits.LeadingZeros64(x)
}
