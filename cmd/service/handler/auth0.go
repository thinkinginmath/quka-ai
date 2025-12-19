package handler

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/quka-ai/quka-ai/app/core"
	v1 "github.com/quka-ai/quka-ai/app/logic/v1"
	"github.com/quka-ai/quka-ai/app/response"
	"github.com/quka-ai/quka-ai/pkg/auth"
	"github.com/quka-ai/quka-ai/pkg/errors"
	"github.com/quka-ai/quka-ai/pkg/i18n"
	"github.com/quka-ai/quka-ai/pkg/types"
	"github.com/quka-ai/quka-ai/pkg/utils"
)

const (
	// SessionTTL session 过期时间 (7 天)
	SessionTTL = 7 * 24 * time.Hour
	// CookieMaxAge cookie 过期时间 (秒)
	CookieMaxAge = 7 * 24 * 60 * 60
)

// Auth0TokenResponse Auth0 token endpoint 响应
type Auth0TokenResponse struct {
	AccessToken  string `json:"access_token"`
	IDToken      string `json:"id_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
}

// Auth0Login 重定向到 Auth0 登录页面
// GET /api/v1/auth/login?redirect_uri=xxx
func (s *HttpSrv) Auth0Login(c *gin.Context) {
	if !s.Core.Auth0Enabled() {
		response.APIError(c, errors.New("Auth0Login", i18n.ERROR_NOT_IMPLEMENTED, nil).Code(http.StatusNotImplemented))
		return
	}

	cfg := s.Core.Cfg().Auth0

	// 获取重定向 URI (登录成功后返回的页面)
	redirectURI := c.Query("redirect_uri")
	if redirectURI == "" {
		// 默认重定向到前端首页
		redirectURI = strings.TrimSuffix(cfg.CallbackURL, "/api/v1/auth/callback")
	}

	// 使用 base64 编码 redirect_uri 作为 state
	state := base64.URLEncoding.EncodeToString([]byte(redirectURI))

	// 构建 Auth0 授权 URL
	authURL := fmt.Sprintf(
		"https://%s/authorize?client_id=%s&response_type=code&scope=%s&redirect_uri=%s&audience=%s&state=%s",
		cfg.Domain,
		cfg.ClientID,
		url.QueryEscape("openid profile email offline_access"),
		url.QueryEscape(cfg.CallbackURL),
		url.QueryEscape(cfg.Audience),
		state,
	)

	c.Redirect(http.StatusFound, authURL)
}

// Auth0Callback Auth0 OAuth 回调处理
// GET /api/v1/auth/callback?code=xxx&state=xxx
func (s *HttpSrv) Auth0Callback(c *gin.Context) {
	tracePrefix := "Auth0Callback"

	if !s.Core.Auth0Enabled() {
		response.APIError(c, errors.New(tracePrefix, i18n.ERROR_NOT_IMPLEMENTED, nil).Code(http.StatusNotImplemented))
		return
	}

	code := c.Query("code")
	state := c.Query("state")
	errorParam := c.Query("error")

	// 检查 Auth0 返回的错误
	if errorParam != "" {
		errorDesc := c.Query("error_description")
		response.APIError(c, errors.New(tracePrefix+".Auth0Error", i18n.ERROR_UNAUTHORIZED, fmt.Errorf("%s: %s", errorParam, errorDesc)).Code(http.StatusUnauthorized))
		return
	}

	if code == "" {
		response.APIError(c, errors.New(tracePrefix+".MissingCode", i18n.ERROR_INVALID_PARAM, nil).Code(http.StatusBadRequest))
		return
	}

	cfg := s.Core.Cfg().Auth0

	// 1. 用授权码换取 tokens
	tokens, err := exchangeCodeForTokens(cfg, code)
	if err != nil {
		response.APIError(c, errors.New(tracePrefix+".ExchangeCode", i18n.ERROR_INTERNAL, err))
		return
	}

	// 2. 解析 ID token 获取用户信息
	auth0Claims, err := s.Core.Auth0Validator().ParseIDToken(c, tokens.IDToken)
	if err != nil {
		response.APIError(c, errors.New(tracePrefix+".ParseIDToken", i18n.ERROR_UNAUTHORIZED, err).Code(http.StatusUnauthorized))
		return
	}

	// 3. 获取或创建 QukaAI 用户
	user, err := getOrCreateAuth0User(c, s.Core, auth0Claims)
	if err != nil {
		response.APIError(c, errors.New(tracePrefix+".GetOrCreateUser", i18n.ERROR_INTERNAL, err))
		return
	}

	// 4. 创建共享 session (写入 Redis)
	sessionID := uuid.New().String()
	session := &auth.SharedSession{
		UserID:       user.ID,
		AccessToken:  tokens.AccessToken,
		IDToken:      tokens.IDToken,
		RefreshToken: tokens.RefreshToken,
	}

	if err := s.Core.SessionService().CreateSession(c, sessionID, session, SessionTTL); err != nil {
		response.APIError(c, errors.New(tracePrefix+".CreateSession", i18n.ERROR_INTERNAL, err))
		return
	}

	// 5. 设置 cookie (domain: .scimigo.com)
	cookieDomain := extractCookieDomain(cfg.CallbackURL)
	c.SetCookie(
		"session_id",
		sessionID,
		CookieMaxAge,
		"/",
		cookieDomain,
		true,  // secure (HTTPS only)
		true,  // httpOnly
	)

	// 6. 重定向到原始页面
	redirectURI := ""
	if state != "" {
		decoded, err := base64.URLEncoding.DecodeString(state)
		if err == nil {
			redirectURI = string(decoded)
		}
	}
	if redirectURI == "" {
		redirectURI = strings.TrimSuffix(cfg.CallbackURL, "/api/v1/auth/callback")
	}

	c.Redirect(http.StatusFound, redirectURI)
}

// Auth0Logout 登出处理
// POST /api/v1/auth/logout
func (s *HttpSrv) Auth0Logout(c *gin.Context) {
	tracePrefix := "Auth0Logout"

	if !s.Core.Auth0Enabled() {
		response.APIError(c, errors.New(tracePrefix, i18n.ERROR_NOT_IMPLEMENTED, nil).Code(http.StatusNotImplemented))
		return
	}

	cfg := s.Core.Cfg().Auth0

	// 1. 删除 Redis 中的 session
	if sessionID, err := c.Cookie("session_id"); err == nil && sessionID != "" {
		_ = s.Core.SessionService().DeleteSession(c, sessionID)
	}

	// 2. 清除 cookie
	cookieDomain := extractCookieDomain(cfg.CallbackURL)
	c.SetCookie(
		"session_id",
		"",
		-1,
		"/",
		cookieDomain,
		true,
		true,
	)

	// 3. 获取前端返回 URL
	returnTo := c.Query("return_to")
	if returnTo == "" {
		returnTo = strings.TrimSuffix(cfg.CallbackURL, "/api/v1/auth/callback")
	}

	// 4. 返回 Auth0 logout URL (让前端重定向)
	logoutURL := fmt.Sprintf(
		"https://%s/v2/logout?client_id=%s&returnTo=%s",
		cfg.Domain,
		cfg.ClientID,
		url.QueryEscape(returnTo),
	)

	response.APISuccess(c, gin.H{
		"logout_url": logoutURL,
	})
}

// Auth0Me 获取当前登录用户信息 (通过 Auth0 session)
// GET /api/v1/auth/me
func (s *HttpSrv) Auth0Me(c *gin.Context) {
	claims, _ := v1.InjectTokenClaim(c)

	user, err := v1.NewUserLogic(c, s.Core).GetUser(claims.Appid, claims.User)
	if err != nil {
		response.APIError(c, err)
		return
	}

	response.APISuccess(c, GetUserResponse{
		UserID:      user.ID,
		Avatar:      user.Avatar,
		UserName:    user.Name,
		Email:       user.Email,
		PlanID:      user.PlanID,
		Appid:       user.Appid,
		ServiceMode: s.Core.Plugins.Name(),
		SystemRole:  user.SystemRole,
	})
}

// exchangeCodeForTokens 用授权码换取 Auth0 tokens
func exchangeCodeForTokens(cfg core.Auth0Config, code string) (*Auth0TokenResponse, error) {
	tokenURL := fmt.Sprintf("https://%s/oauth/token", cfg.Domain)

	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("client_id", cfg.ClientID)
	data.Set("client_secret", cfg.ClientSecret)
	data.Set("code", code)
	data.Set("redirect_uri", cfg.CallbackURL)

	req, err := http.NewRequest("POST", tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token request failed: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token exchange failed: %s", string(body))
	}

	var tokens Auth0TokenResponse
	if err := json.Unmarshal(body, &tokens); err != nil {
		return nil, fmt.Errorf("failed to parse token response: %w", err)
	}

	return &tokens, nil
}

// extractCookieDomain 从 callback URL 提取 cookie domain
// 例如: https://kb.scimigo.com/api/v1/auth/callback -> .scimigo.com
func extractCookieDomain(callbackURL string) string {
	u, err := url.Parse(callbackURL)
	if err != nil {
		return ""
	}

	host := u.Hostname()
	parts := strings.Split(host, ".")
	if len(parts) >= 2 {
		// 返回顶级域 + 一级域，例如 .scimigo.com
		return "." + strings.Join(parts[len(parts)-2:], ".")
	}
	return host
}

// getOrCreateAuth0User 根据 Auth0 Claims 获取或创建用户
// 这是懒加载的核心逻辑: 首次登录时自动创建 QukaAI 用户
func getOrCreateAuth0User(ctx context.Context, appCore *core.Core, auth0Claims *auth.Auth0Claims) (*types.User, error) {
	appid := appCore.DefaultAppid()

	// 1. 尝试通过 auth0_id 查找现有用户
	user, err := appCore.Store().UserStore().GetByAuth0ID(ctx, appid, auth0Claims.Sub)
	if err == nil {
		return user, nil
	}

	if err != sql.ErrNoRows {
		return nil, fmt.Errorf("failed to get user by auth0_id: %w", err)
	}

	// 2. 用户不存在，创建新用户
	userID := utils.GenUniqIDStr()
	now := time.Now().Unix()

	// 用户名处理: 如果没有名字，使用邮箱前缀
	userName := auth0Claims.Name
	if userName == "" && auth0Claims.Email != "" {
		parts := strings.Split(auth0Claims.Email, "@")
		userName = parts[0]
	}
	if userName == "" {
		userName = "User"
	}

	// 头像处理: 使用 Auth0 提供的头像或默认头像
	avatar := auth0Claims.Picture
	if avatar == "" {
		avatar = appCore.Cfg().Site.DefaultAvatar
	}

	auth0ID := auth0Claims.Sub
	newUser := types.User{
		ID:        userID,
		Appid:     appid,
		Auth0ID:   &auth0ID,
		Email:     auth0Claims.Email,
		Name:      userName,
		Avatar:    avatar,
		Source:    "auth0",
		UpdatedAt: now,
		CreatedAt: now,
	}

	// 3. 事务: 创建用户 + 默认 plan + 默认 workspace
	err = appCore.Store().Transaction(ctx, func(txCtx context.Context) error {
		// 创建默认 plan
		defaultPlan, err := appCore.Plugins.CreateUserDefaultPlan(txCtx, appid, userID)
		if err != nil {
			return fmt.Errorf("failed to create default plan: %w", err)
		}
		newUser.PlanID = defaultPlan

		// 创建用户
		if err := appCore.Store().UserStore().Create(txCtx, newUser); err != nil {
			return fmt.Errorf("failed to create user: %w", err)
		}

		// 创建默认 workspace
		spaceID := utils.GenRandomID()
		spaceName := fmt.Sprintf("%s's Knowledge Base", userName)
		if err := appCore.Store().SpaceStore().Create(txCtx, types.Space{
			SpaceID:     spaceID,
			Title:       spaceName,
			Description: "default space",
			CreatedAt:   now,
		}); err != nil {
			return fmt.Errorf("failed to create space: %w", err)
		}

		// 关联用户和 workspace
		if err := appCore.Store().UserSpaceStore().Create(txCtx, types.UserSpace{
			UserID:    userID,
			SpaceID:   spaceID,
			Role:      "chief",
			CreatedAt: now,
		}); err != nil {
			return fmt.Errorf("failed to create user-space relation: %w", err)
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	return &newUser, nil
}
