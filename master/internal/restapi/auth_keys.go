package restapi

import (
	"net/http"
)

// JWT 公钥暴露（docs/dd/07 §4：RS256 密钥对私钥仅 Master 持有，LucidBGP 经
// JWKS 公钥验签）。
//
// GET /api/v1/auth/jwks        —— RFC 7517 JWKS（Java 客户端标准消费形态）
// GET /api/v1/auth/jwks.pem    —— SPKI PEM（运维导出/网关侧脚本验签用）
//
// 两端点均不鉴权：JWKS 只含公钥材料，泄露不构成威胁。

// handleJWKS 返回公钥集（RS256 未配置时 keys 为空数组——调用方据此回落带外共享密钥）。
func (s *Server) handleJWKS(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=300")
	_, _ = w.Write(s.d.Signer.JWKS())
}

// handleJWKSPem 返回 SPKI PEM 公钥（未配置 RS256 时 404）。
func (s *Server) handleJWKSPem(w http.ResponseWriter, _ *http.Request) {
	pemBytes := s.d.Signer.PublicKeyPEM()
	if len(pemBytes) == 0 {
		writeErr(w, http.StatusNotFound, 404, "rs256 not configured")
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Cache-Control", "public, max-age=300")
	_, _ = w.Write(pemBytes)
}
