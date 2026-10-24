package rbac

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
)

// 口令哈希：stdlib pbkdf2（Go 1.24+ crypto/pbkdf2），SHA-256。
// 存储格式：pbkdf2$sha256$<iters>$<salt_b64>$<hash_b64>。

const (
	pbkdf2Iters = 60000
	saltLen     = 16
	keyLen      = 32
)

// HashPassword 生成 pbkdf2 口令哈希。
func HashPassword(password string) (string, error) {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("read salt: %w", err)
	}
	key, err := pbkdf2.Key(sha256.New, password, salt, pbkdf2Iters, keyLen)
	if err != nil {
		return "", fmt.Errorf("pbkdf2 key: %w", err)
	}
	return fmt.Sprintf("pbkdf2$sha256$%d$%s$%s",
		pbkdf2Iters,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key)), nil
}

// VerifyPassword 校验口令。
func VerifyPassword(password, stored string) (bool, error) {
	parts := strings.Split(stored, "$")
	if len(parts) != 5 || parts[0] != "pbkdf2" || parts[1] != "sha256" {
		return false, fmt.Errorf("unsupported hash format")
	}
	iters, err := strconv.Atoi(parts[2])
	if err != nil {
		return false, fmt.Errorf("parse iters: %w", err)
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[3])
	if err != nil {
		return false, fmt.Errorf("decode salt: %w", err)
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, fmt.Errorf("decode hash: %w", err)
	}
	got, err := pbkdf2.Key(sha256.New, password, salt, iters, len(want))
	if err != nil {
		return false, fmt.Errorf("pbkdf2 key: %w", err)
	}
	// 恒时比较防时序侧信道
	diff := 0
	for i := range got {
		diff |= int(got[i] ^ want[i])
	}
	return diff == 0, nil
}
