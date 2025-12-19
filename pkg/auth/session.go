package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// SharedSession Math-Agents 共享的 session 结构
// 存储在 Redis key: authsession:{session_id}
type SharedSession struct {
	UserID       string `json:"user_id"`       // Math-Agents 的用户 ID (UUID)
	AccessToken  string `json:"access_token"`  // Auth0 access token
	IDToken      string `json:"id_token"`      // Auth0 ID token
	RefreshToken string `json:"refresh_token"` // Auth0 refresh token
}

// SessionService 共享 session 服务
type SessionService struct {
	redis redis.UniversalClient
}

// NewSessionService 创建 session 服务
func NewSessionService(redisClient redis.UniversalClient) *SessionService {
	return &SessionService{
		redis: redisClient,
	}
}

// GetSharedSession 从 Redis 获取共享 session
// 这个 session 是由 Math-Agents (app.scimigo.com) 创建的
func (s *SessionService) GetSharedSession(ctx context.Context, sessionID string) (*SharedSession, error) {
	if sessionID == "" {
		return nil, fmt.Errorf("empty session ID")
	}

	key := fmt.Sprintf("authsession:%s", sessionID)
	data, err := s.redis.Get(ctx, key).Bytes()
	if err != nil {
		if err == redis.Nil {
			return nil, fmt.Errorf("session not found")
		}
		return nil, fmt.Errorf("failed to get session: %w", err)
	}

	var session SharedSession
	if err := json.Unmarshal(data, &session); err != nil {
		return nil, fmt.Errorf("failed to unmarshal session: %w", err)
	}

	return &session, nil
}

// CreateSession 创建新的 session (用于 QukaAI 自己的登录流程)
// 格式与 Math-Agents 兼容，可以实现 SSO
func (s *SessionService) CreateSession(ctx context.Context, sessionID string, session *SharedSession, ttl time.Duration) error {
	key := fmt.Sprintf("authsession:%s", sessionID)

	data, err := json.Marshal(session)
	if err != nil {
		return fmt.Errorf("failed to marshal session: %w", err)
	}

	if err := s.redis.Set(ctx, key, data, ttl).Err(); err != nil {
		return fmt.Errorf("failed to set session: %w", err)
	}

	return nil
}

// DeleteSession 删除 session
func (s *SessionService) DeleteSession(ctx context.Context, sessionID string) error {
	key := fmt.Sprintf("authsession:%s", sessionID)
	return s.redis.Del(ctx, key).Err()
}

// ExtendSession 延长 session 过期时间
func (s *SessionService) ExtendSession(ctx context.Context, sessionID string, ttl time.Duration) error {
	key := fmt.Sprintf("authsession:%s", sessionID)
	return s.redis.Expire(ctx, key, ttl).Err()
}
