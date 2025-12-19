package middleware

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/samber/lo"

	"github.com/quka-ai/quka-ai/app/core"
	v1 "github.com/quka-ai/quka-ai/app/logic/v1"
	"github.com/quka-ai/quka-ai/app/response"
	"github.com/quka-ai/quka-ai/pkg/auth"
	"github.com/quka-ai/quka-ai/pkg/errors"
	"github.com/quka-ai/quka-ai/pkg/i18n"
	"github.com/quka-ai/quka-ai/pkg/security"
	"github.com/quka-ai/quka-ai/pkg/types"
	"github.com/quka-ai/quka-ai/pkg/utils"
)

func I18n() gin.HandlerFunc {
	var allowList []string
	for k := range i18n.ALLOW_LANG {
		allowList = append(allowList, k)
	}
	l := i18n.NewLocalizer(allowList...)

	return response.ProvideResponseLocalizer(l)
}

// AcceptLanguage 目前服务端支持 en: English, zh-CN: 简体中文
func AcceptLanguage() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		lang := ctx.Request.Header.Get("Accept-Language")
		if lang == "" {
			ctx.Set(v1.LANGUAGE_KEY, types.LANGUAGE_EN_KEY)
			return
		}

		res := utils.ParseAcceptLanguage(lang)
		if len(res) == 0 {
			ctx.Set(v1.LANGUAGE_KEY, types.LANGUAGE_EN_KEY)
			return
		}

		ctx.Set(v1.LANGUAGE_KEY, lo.If(strings.Contains(res[0].Tag, "zh"), types.LANGUAGE_CN_KEY).Else(types.LANGUAGE_EN_KEY))
	}
}

const (
	ACCESS_TOKEN_HEADER_KEY = "X-Access-Token"
	AUTH_TOKEN_HEADER_KEY   = "X-Authorization"
	APPID_HEADER            = "X-Appid"
)

func AuthorizationFromQuery(core *core.Core) gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenValue := c.Query("token")
		tokenType := c.Query("token-type")

		var (
			passed bool
			err    error
		)

		if tokenType == "authorization" {
			passed, err = ParseAuthToken(c, tokenValue, core)
		} else {
			passed, err = ParseAccessToken(c, tokenValue, core)
		}

		if err != nil {
			response.APIError(c, err)
			return
		}

		if !passed {
			response.APIError(c, errors.New("middleware.AuthorizationFromQuery", i18n.ERROR_UNAUTHORIZED, nil).Code(http.StatusUnauthorized))
			return
		}
	}
}

func Authorization(core *core.Core) gin.HandlerFunc {
	tracePrefix := "middleware.TryGetAccessToken"
	return func(ctx *gin.Context) {
		matched, err := checkAccessToken(ctx, core)
		if err != nil {
			response.APIError(ctx, errors.Trace(tracePrefix, err))
			return
		}

		if matched {
			return
		}

		if matched, err = checkAuthToken(ctx, core); err != nil {
			response.APIError(ctx, errors.Trace(tracePrefix, err))
			return
		}

		if !matched {
			response.APIError(ctx, errors.New(tracePrefix, i18n.ERROR_UNAUTHORIZED, err).Code(http.StatusUnauthorized))
		}
	}
}

func SetAppid(core *core.Core) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		// appid := ctx.Request.Header.Get(APPID_HEADER)
		// check appid exist
		ctx.Set(v1.APPID_KEY, core.DefaultAppid())
	}
}

func checkAccessToken(c *gin.Context, core *core.Core) (bool, error) {
	tokenValue := c.GetHeader(ACCESS_TOKEN_HEADER_KEY)
	if tokenValue == "" {
		// try get
		// errors.New("checkAccessToken.GetHeader.ACCESS_TOKEN_HEADER_KEY.nil", i18n.ERROR_UNAUTHORIZED, nil).Code(http.StatusUnauthorized)
		return false, nil
	}

	return ParseAccessToken(c, tokenValue, core)
}

func ParseAccessToken(c *gin.Context, tokenValue string, core *core.Core) (bool, error) {
	if tokenValue == "" {
		return false, nil
	}

	appid, exist := v1.InjectAppid(c)
	if !exist {
		appid = core.DefaultAppid()
	}

	token, err := core.Store().AccessTokenStore().GetAccessToken(c, appid, tokenValue)
	if err != nil && err != sql.ErrNoRows {
		return false, errors.New("ParseAccessToken.AccessTokenStore.GetAccessToken", i18n.ERROR_INTERNAL, err)
	}

	if token == nil || token.ExpiresAt < time.Now().Unix() {
		return false, errors.New("ParseAccessToken.token.check", i18n.ERROR_UNAUTHORIZED, fmt.Errorf("nil token")).Code(http.StatusUnauthorized)
	}

	user, err := core.Store().UserStore().GetUser(c, token.Appid, token.UserID)
	if err != nil {
		return false, errors.New("ParseAccessToken.UserStore.GetUser", i18n.ERROR_INTERNAL, err)
	}

	c.Set(v1.TOKEN_CONTEXT_KEY, security.NewTokenClaims(user.Appid, core.DefaultAppid(), user.ID, user.PlanID, "", token.ExpiresAt))
	return true, nil
}

func checkAuthToken(c *gin.Context, core *core.Core) (bool, error) {
	tokenValue := c.GetHeader(AUTH_TOKEN_HEADER_KEY)
	if tokenValue == "" {
		// try get
		// errors.New("checkAuthToken.GetHeader.AUTH_TOKEN_HEADER_KEY.nil", i18n.ERROR_UNAUTHORIZED, nil).Code(http.StatusUnauthorized)
		return false, nil
	}

	return ParseAuthToken(c, tokenValue, core)
}

func FlexibleAuth(core *core.Core) gin.HandlerFunc {
	return func(c *gin.Context) {
		// 1. 尝试 Auth0 Bearer Token 认证 (Authorization: Bearer xxx)
		if core.Auth0Enabled() {
			if authHeader := c.GetHeader("Authorization"); strings.HasPrefix(authHeader, "Bearer ") {
				token := strings.TrimPrefix(authHeader, "Bearer ")
				passed, authErr := ParseAuth0Token(c, token, core)
				if authErr != nil {
					response.APIError(c, errors.Trace("middleware.FlexibleAuth.ParseAuth0Token", authErr))
					return
				}
				if passed {
					return
				}
			}
		}

		// 2. 尝试共享 Session Cookie 认证 (session_id cookie from .scimigo.com)
		if core.Auth0Enabled() && core.SessionService() != nil {
			if sessionID, err := c.Cookie("session_id"); err == nil && sessionID != "" {
				passed, authErr := ParseSharedSessionCookie(c, sessionID, core)
				if authErr != nil {
					// Session 无效不是致命错误，继续尝试其他认证方式
					// 只有在明确的内部错误时才返回错误
					if !strings.Contains(authErr.Error(), "session not found") {
						response.APIError(c, errors.Trace("middleware.FlexibleAuth.ParseSharedSessionCookie", authErr))
						return
					}
				}
				if passed {
					return
				}
			}
		}

		// 3. 尝试 Header 认证 (X-Access-Token)
		matched, err := checkAccessToken(c, core)
		if err != nil {
			response.APIError(c, errors.Trace("middleware.FlexibleAuth.checkAccessToken", err))
			return
		}

		if matched {
			return
		}

		// 4. 尝试 Header 认证 (X-Authorization)
		matched, err = checkAuthToken(c, core)
		if err != nil {
			response.APIError(c, errors.Trace("middleware.FlexibleAuth.checkAuthToken", err))
			return
		}

		if matched {
			return
		}

		// 5. 尝试 Cookie 认证 (quka-auth)
		if cookieToken, err := c.Cookie("quka-auth"); err == nil && cookieToken != "" {
			passed, authErr := ParseAuthToken(c, cookieToken, core)
			if authErr != nil {
				response.APIError(c, errors.Trace("middleware.FlexibleAuth.ParseCookieToken", authErr))
				return
			}

			if passed {
				return
			}
		}

		// 6. 尝试查询参数认证
		tokenValue := c.Query("token")
		tokenType := c.Query("token-type")

		if tokenValue != "" {
			var passed bool
			var authErr error

			if tokenType == "authorization" {
				passed, authErr = ParseAuthToken(c, tokenValue, core)
			} else {
				passed, authErr = ParseAccessToken(c, tokenValue, core)
			}

			if authErr != nil {
				response.APIError(c, errors.Trace("middleware.FlexibleAuth.ParseQueryToken", authErr))
				return
			}

			if passed {
				return
			}
		}

		response.APIError(c, errors.New("middleware.FlexibleAuth", i18n.ERROR_UNAUTHORIZED, nil).Code(http.StatusUnauthorized))
	}
}

func PaymentRequired(c *gin.Context) {
	tokenClaim, exist := c.Get(v1.TOKEN_CONTEXT_KEY)
	if !exist {
		response.APIError(c, errors.New("middleware.PaymentRequired.GetToken", i18n.ERROR_UNAUTHORIZED, nil).Code(http.StatusUnauthorized))
		return
	}

	tc, ok := tokenClaim.(security.TokenClaims)
	if !ok {
		response.APIError(c, errors.New("middleware.PaymentRequired.TokenClaims", i18n.ERROR_UNAUTHORIZED, nil).Code(http.StatusUnauthorized))
		return
	}

	if tc.PlanID() == "" {
		response.APIError(c, errors.New("middleware.PaymentRequired.Check.Plan", i18n.ERROR_PAYMENT_REQUIRED, nil).Code(http.StatusPaymentRequired))
		return
	}
}

func ParseAuthToken(c *gin.Context, tokenValue string, core *core.Core) (bool, error) {
	if tokenValue == "" {
		return false, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	tokenMeta, err := auth.ValidateTokenFromCache(ctx, tokenValue, core.Plugins.Cache())
	if err != nil {
		return false, errors.Trace("ParseAuthToken.ValidateTokenFromCache.GetUser", err)
	}

	user, err := core.Store().UserStore().GetUser(ctx, tokenMeta.Appid, tokenMeta.UserID)
	if err != nil {
		return false, errors.New("ParseAuthToken.UserStore.GetUser", i18n.ERROR_INTERNAL, err)
	}

	c.Set(v1.TOKEN_CONTEXT_KEY, security.NewTokenClaims(tokenMeta.Appid, types.DEFAULT_APPID, tokenMeta.UserID, user.PlanID, "", tokenMeta.ExpireAt))

	core.Plugins.Cache().Expire(ctx, fmt.Sprintf("user:token:%s", utils.MD5(tokenValue)), time.Hour*24*7)

	return true, nil
}

func VerifySpaceIDPermission(core *core.Core, permission string) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		spaceID, _ := ctx.Params.Get("spaceid")

		claims, _ := v1.InjectTokenClaim(ctx)

		result, err := core.Store().UserSpaceStore().GetUserSpaceRole(ctx, claims.User, spaceID)
		if err != nil && err != sql.ErrNoRows {
			response.APIError(ctx, errors.New("middleware.VerifySpaceIDPermission.UserSpaceStore.GetUserSpaceRole", i18n.ERROR_INTERNAL, err))
			return
		}

		if result == nil {
			response.APIError(ctx, errors.New("middleware.VerifySpaceIDPermission.UserSpaceStore.GetUserSpaceRole.nil", i18n.ERROR_PERMISSION_DENIED, nil).Code(http.StatusForbidden))
			return
		}

		claims.Fields["role"] = result.Role

		if !core.Srv().RBAC().CheckPermission(result.Role, permission) {
			response.APIError(ctx, errors.New("middleware.VerifySpaceIDPermission.CheckPermission", i18n.ERROR_PERMISSION_DENIED, nil).Code(http.StatusForbidden))
			return
		}

		ctx.Set(v1.SPACEID_CONTEXT_KEY, spaceID)
	}
}

func Cors(c *gin.Context) {
	method := c.Request.Method
	origin := c.Request.Header.Get("Origin")
	if origin != "" {
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE, UPDATE")
		c.Header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept, Authorization, X-Access-Token, X-Authorization, X-Appid")
		c.Header("Access-Control-Expose-Headers", "Content-Length, Access-Control-Allow-Origin, Access-Control-Allow-Headers, Cache-Control, Content-Language, Content-Type")
		c.Header("Access-Control-Allow-Credentials", "true")
	}
	if method == "OPTIONS" {
		c.AbortWithStatus(http.StatusNoContent)
	}
	c.Next()
}

type LimiterFunc func(key string, opts ...core.LimitOption) gin.HandlerFunc

func UseLimit(appCore *core.Core, operation string, genKeyFunc func(c *gin.Context) string, opts ...core.LimitOption) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !appCore.UseLimiter(c, genKeyFunc(c), operation, opts...).Allow() {
			response.APIError(c, errors.New("middleware.limiter", i18n.ERROR_TOO_MANY_REQUESTS, nil).Code(http.StatusTooManyRequests))
		}
	}
}

// VerifyUserRole 验证用户是否拥有指定角色的通用中间件
func VerifyUserRole(core *core.Core, requiredRoles ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		claims, exists := c.Get(v1.TOKEN_CONTEXT_KEY)
		if !exists {
			response.APIError(c, errors.New("middleware.VerifyUserRole.GetToken", i18n.ERROR_UNAUTHORIZED, nil).Code(http.StatusUnauthorized))
			c.Abort()
			return
		}

		tokenClaims, ok := claims.(security.TokenClaims)
		if !ok {
			response.APIError(c, errors.New("middleware.VerifyUserRole.TokenClaims", i18n.ERROR_UNAUTHORIZED, nil).Code(http.StatusUnauthorized))
			c.Abort()
			return
		}

		// 获取用户信息
		user, err := core.Store().UserStore().GetUser(c, tokenClaims.Appid, tokenClaims.User)
		if err != nil {
			response.APIError(c, errors.New("middleware.VerifyUserRole.GetUser", i18n.ERROR_INTERNAL, err))
			c.Abort()
			return
		}

		// 获取用户的全局角色
		userRole, err := getUserGlobalRole(core, user)
		if err != nil {
			response.APIError(c, errors.New("middleware.VerifyUserRole.GetGlobalRole", i18n.ERROR_INTERNAL, err))
			c.Abort()
			return
		}

		// 检查用户角色是否匹配任意一个要求的角色
		hasPermission := false
		for _, requiredRole := range requiredRoles {
			if userRole == requiredRole {
				hasPermission = true
				break
			}
		}

		if !hasPermission {
			response.APIError(c, errors.New("middleware.VerifyUserRole.Check", i18n.ERROR_PERMISSION_DENIED, nil).Code(http.StatusForbidden))
			c.Abort()
			return
		}

		c.Next()
	}
}

// VerifyAdminPermission 验证管理员权限（admin或chief角色）
func VerifyAdminPermission(core *core.Core) gin.HandlerFunc {
	return VerifyUserRole(core, types.GlobalRoleAdmin, types.GlobalRoleChief)
}

// getUserGlobalRole 获取用户的全局角色
func getUserGlobalRole(core *core.Core, user *types.User) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()

	// 首先查询用户全局角色表
	globalRole, err := core.Store().UserGlobalRoleStore().GetUserRole(ctx, user.Appid, user.ID)
	if err != nil {
		return "", err
	}

	// 如果找到全局角色记录，直接返回
	if globalRole == nil {
		return types.GlobalRoleMember, nil
	}

	return globalRole.Role, nil
}

// createUserGlobalRole 创建用户全局角色记录（辅助函数）
func createUserGlobalRole(core *core.Core, appid, userID, role string) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()

	globalRole := types.UserGlobalRole{
		UserID:    userID,
		Appid:     appid,
		Role:      role,
		CreatedAt: time.Now().Unix(),
		UpdatedAt: time.Now().Unix(),
	}

	return core.Store().UserGlobalRoleStore().Create(ctx, globalRole)
}

// ParseAuth0Token 解析并验证 Auth0 access token
// 如果用户不存在，会自动创建用户 (懒加载)
func ParseAuth0Token(c *gin.Context, token string, core *core.Core) (bool, error) {
	if token == "" {
		return false, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	// 验证 Auth0 token
	auth0Claims, err := core.Auth0Validator().ValidateAccessToken(ctx, token)
	if err != nil {
		return false, errors.New("ParseAuth0Token.ValidateAccessToken", i18n.ERROR_UNAUTHORIZED, err).Code(http.StatusUnauthorized)
	}

	// 懒加载: 获取或创建用户
	user, err := getOrCreateAuth0User(ctx, core, auth0Claims)
	if err != nil {
		return false, errors.New("ParseAuth0Token.getOrCreateAuth0User", i18n.ERROR_INTERNAL, err)
	}

	c.Set(v1.TOKEN_CONTEXT_KEY, security.NewTokenClaims(user.Appid, types.DEFAULT_APPID, user.ID, user.PlanID, "", time.Now().Add(24*time.Hour).Unix()))
	return true, nil
}

// ParseSharedSessionCookie 解析共享 session cookie (来自 .scimigo.com)
// 读取 Math-Agents 创建的 session，从中提取 Auth0 ID token 进行验证
func ParseSharedSessionCookie(c *gin.Context, sessionID string, core *core.Core) (bool, error) {
	if sessionID == "" {
		return false, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	// 从 Redis 获取共享 session
	session, err := core.SessionService().GetSharedSession(ctx, sessionID)
	if err != nil {
		return false, errors.New("ParseSharedSessionCookie.GetSharedSession", i18n.ERROR_UNAUTHORIZED, err).Code(http.StatusUnauthorized)
	}

	// 解析 ID token 获取 auth0 claims
	auth0Claims, err := core.Auth0Validator().ParseIDToken(ctx, session.IDToken)
	if err != nil {
		return false, errors.New("ParseSharedSessionCookie.ParseIDToken", i18n.ERROR_UNAUTHORIZED, err).Code(http.StatusUnauthorized)
	}

	// 懒加载: 获取或创建用户
	user, err := getOrCreateAuth0User(ctx, core, auth0Claims)
	if err != nil {
		return false, errors.New("ParseSharedSessionCookie.getOrCreateAuth0User", i18n.ERROR_INTERNAL, err)
	}

	c.Set(v1.TOKEN_CONTEXT_KEY, security.NewTokenClaims(user.Appid, types.DEFAULT_APPID, user.ID, user.PlanID, "", time.Now().Add(24*time.Hour).Unix()))
	return true, nil
}

// getOrCreateAuth0User 根据 Auth0 Claims 获取或创建用户
// 这是懒加载的核心逻辑: 首次登录时自动创建 QukaAI 用户
func getOrCreateAuth0User(ctx context.Context, core *core.Core, auth0Claims *auth.Auth0Claims) (*types.User, error) {
	appid := core.DefaultAppid()

	// 1. 尝试通过 auth0_id 查找现有用户
	user, err := core.Store().UserStore().GetByAuth0ID(ctx, appid, auth0Claims.Sub)
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
		avatar = core.Cfg().Site.DefaultAvatar
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
	err = core.Store().Transaction(ctx, func(txCtx context.Context) error {
		// 创建默认 plan
		defaultPlan, err := core.Plugins.CreateUserDefaultPlan(txCtx, appid, userID)
		if err != nil {
			return fmt.Errorf("failed to create default plan: %w", err)
		}
		newUser.PlanID = defaultPlan

		// 创建用户
		if err := core.Store().UserStore().Create(txCtx, newUser); err != nil {
			return fmt.Errorf("failed to create user: %w", err)
		}

		// 创建默认 workspace
		spaceID := utils.GenRandomID()
		spaceName := fmt.Sprintf("%s's Knowledge Base", userName)
		if err := core.Store().SpaceStore().Create(txCtx, types.Space{
			SpaceID:     spaceID,
			Title:       spaceName,
			Description: "default space",
			CreatedAt:   now,
		}); err != nil {
			return fmt.Errorf("failed to create space: %w", err)
		}

		// 关联用户和 workspace
		if err := core.Store().UserSpaceStore().Create(txCtx, types.UserSpace{
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
