package httpapi

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"strconv"
	"time"
)

// newTraceID 生成 16B 随机 trace id（hex）。
func newTraceID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return time.Now().UTC().Format("20060102150405.000000000")
	}
	return hex.EncodeToString(b[:])
}

// atoi32 解析非负 int32 查询参数（空/非法返回 0 并由调用方决定语义）。
func atoi32(s string) int32 {
	v, err := strconv.ParseInt(s, 10, 32)
	if err != nil {
		return 0
	}
	return int32(v)
}

// atoi64 解析 int64 查询参数。
func atoi64(s string) int64 {
	v, _ := strconv.ParseInt(s, 10, 64)
	return v
}

// pageParams 解析 docs/00 §6 分页参数（page 从 1 起，默认 1/20，上限 500）。
func pageParams(r *http.Request) (page, pageSize int) {
	page = int(atoi64(r.URL.Query().Get("page")))
	pageSize = int(atoi64(r.URL.Query().Get("page_size")))
	if page < 1 {
		page = 1
	}
	if pageSize < 1 {
		pageSize = 20
	}
	if pageSize > 500 {
		pageSize = 500
	}
	return page, pageSize
}
