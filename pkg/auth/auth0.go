package auth

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Auth0Claims Auth0 JWT 中的用户信息
type Auth0Claims struct {
	Sub     string `json:"sub"`     // Auth0 用户唯一标识 (e.g., "auth0|xxx" or "google-oauth2|xxx")
	Email   string `json:"email"`   // 用户邮箱
	Name    string `json:"name"`    // 用户名
	Picture string `json:"picture"` // 用户头像 URL
}

// Auth0Validator Auth0 JWT 验证器
type Auth0Validator struct {
	domain   string
	audience string
	issuer   string

	// JWKS 缓存
	jwks      *JWKS
	jwksMu    sync.RWMutex
	jwksCache time.Time
	jwksTTL   time.Duration
}

// JWKS JSON Web Key Set
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// JWK JSON Web Key
type JWK struct {
	Kty string `json:"kty"` // Key type (e.g., "RSA")
	Kid string `json:"kid"` // Key ID
	Use string `json:"use"` // Key use (e.g., "sig")
	N   string `json:"n"`   // RSA modulus
	E   string `json:"e"`   // RSA exponent
	Alg string `json:"alg"` // Algorithm (e.g., "RS256")
}

// NewAuth0Validator 创建新的 Auth0 验证器
func NewAuth0Validator(domain, audience string) *Auth0Validator {
	return &Auth0Validator{
		domain:   domain,
		audience: audience,
		issuer:   fmt.Sprintf("https://%s/", domain),
		jwksTTL:  1 * time.Hour, // JWKS 缓存 1 小时
	}
}

// ValidateAccessToken 验证 Auth0 access token
func (v *Auth0Validator) ValidateAccessToken(ctx context.Context, tokenString string) (*Auth0Claims, error) {
	// 获取 JWKS
	jwks, err := v.getJWKS(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get JWKS: %w", err)
	}

	// 解析 token (不验证，先获取 header 中的 kid)
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// 验证签名算法
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		// 获取 kid
		kid, ok := token.Header["kid"].(string)
		if !ok {
			return nil, fmt.Errorf("kid not found in token header")
		}

		// 从 JWKS 中查找对应的公钥
		pubKey, err := jwks.GetPublicKey(kid)
		if err != nil {
			return nil, err
		}

		return pubKey, nil
	}, jwt.WithAudience(v.audience), jwt.WithIssuer(v.issuer))

	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	if !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	// 提取 claims
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("invalid claims type")
	}

	return &Auth0Claims{
		Sub:     getStringClaim(claims, "sub"),
		Email:   getStringClaim(claims, "email"),
		Name:    getStringClaim(claims, "name"),
		Picture: getStringClaim(claims, "picture"),
	}, nil
}

// ParseIDToken 解析 Auth0 ID token (用于从 session 中提取用户信息)
// ID token 使用相同的 JWKS 验证
func (v *Auth0Validator) ParseIDToken(ctx context.Context, tokenString string) (*Auth0Claims, error) {
	// ID token 验证与 access token 类似，但 audience 是 client_id
	// 这里简化处理，只提取 claims 而不做完整验证
	// 因为 session 中的 ID token 已经在 callback 时验证过了

	jwks, err := v.getJWKS(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get JWKS: %w", err)
	}

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		kid, ok := token.Header["kid"].(string)
		if !ok {
			return nil, fmt.Errorf("kid not found in token header")
		}

		return jwks.GetPublicKey(kid)
	}, jwt.WithIssuer(v.issuer))

	if err != nil {
		return nil, fmt.Errorf("failed to parse ID token: %w", err)
	}

	if !token.Valid {
		return nil, fmt.Errorf("invalid ID token")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("invalid claims type")
	}

	return &Auth0Claims{
		Sub:     getStringClaim(claims, "sub"),
		Email:   getStringClaim(claims, "email"),
		Name:    getStringClaim(claims, "name"),
		Picture: getStringClaim(claims, "picture"),
	}, nil
}

// getJWKS 获取 JWKS (带缓存)
func (v *Auth0Validator) getJWKS(ctx context.Context) (*JWKS, error) {
	v.jwksMu.RLock()
	if v.jwks != nil && time.Since(v.jwksCache) < v.jwksTTL {
		jwks := v.jwks
		v.jwksMu.RUnlock()
		return jwks, nil
	}
	v.jwksMu.RUnlock()

	// 需要刷新 JWKS
	v.jwksMu.Lock()
	defer v.jwksMu.Unlock()

	// 双重检查
	if v.jwks != nil && time.Since(v.jwksCache) < v.jwksTTL {
		return v.jwks, nil
	}

	// 从 Auth0 获取 JWKS
	jwksURL := fmt.Sprintf("https://%s/.well-known/jwks.json", v.domain)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURL, nil)
	if err != nil {
		return nil, err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("JWKS request failed with status: %d", resp.StatusCode)
	}

	var jwks JWKS
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return nil, fmt.Errorf("failed to decode JWKS: %w", err)
	}

	v.jwks = &jwks
	v.jwksCache = time.Now()

	return &jwks, nil
}

// GetPublicKey 从 JWKS 中获取指定 kid 的公钥
func (j *JWKS) GetPublicKey(kid string) (interface{}, error) {
	for _, key := range j.Keys {
		if key.Kid == kid {
			return key.ToRSAPublicKey()
		}
	}
	return nil, fmt.Errorf("key with kid %s not found", kid)
}

// ToRSAPublicKey 将 JWK 转换为 RSA 公钥
func (k *JWK) ToRSAPublicKey() (*rsa.PublicKey, error) {
	if k.Kty != "RSA" {
		return nil, fmt.Errorf("unsupported key type: %s", k.Kty)
	}

	// 解码 N (modulus) - base64url 编码
	nBytes, err := base64.RawURLEncoding.DecodeString(k.N)
	if err != nil {
		return nil, fmt.Errorf("failed to decode N: %w", err)
	}

	// 解码 E (exponent) - base64url 编码
	eBytes, err := base64.RawURLEncoding.DecodeString(k.E)
	if err != nil {
		return nil, fmt.Errorf("failed to decode E: %w", err)
	}

	// 构建 RSA 公钥
	n := new(big.Int).SetBytes(nBytes)

	var e int
	for _, b := range eBytes {
		e = e<<8 + int(b)
	}

	return &rsa.PublicKey{
		N: n,
		E: e,
	}, nil
}

// getStringClaim 安全地从 claims 中获取字符串值
func getStringClaim(claims jwt.MapClaims, key string) string {
	if val, ok := claims[key]; ok {
		if str, ok := val.(string); ok {
			return str
		}
	}
	return ""
}
