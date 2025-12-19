# QukaAI Auth0 Integration Plan

## 概述

将 QukaAI 部署到 US 市场 (kb.scimigo.com)，与现有的 Scimigo Math Agent (app.scimigo.com) 共享 Auth0 认证系统。

## 目标架构

```
                         ┌─────────────────┐
                         │     Auth0       │
                         │ (scimigo tenant)│
                         └────────┬────────┘
                                  │
                    ┌─────────────┴─────────────┐
                    │      .scimigo.com         │
                    │   Shared Session Cookie   │
                    └─────────────┬─────────────┘
                                  │
            ┌─────────────────────┴─────────────────────┐
            │                                           │
            ▼                                           ▼
┌─────────────────────────┐              ┌─────────────────────────┐
│   app.scimigo.com       │              │   kb.scimigo.com        │
│   (Math Agent)          │              │   (QukaAI RAG)          │
│                         │              │                         │
│   Python/FastAPI        │              │   Go/Gin                │
│   PostgreSQL (users)    │              │   PostgreSQL (quka_user)│
└─────────────────────────┘              └─────────────────────────┘
```

## 设计决策

| 决策项 | 选择 | 原因 |
|--------|------|------|
| 域名 | kb.scimigo.com | 清晰表达知识库功能 |
| 用户创建 | 懒加载 (Lazy) | 首次访问时创建，减少数据冗余 |
| Session | 共享 SSO | 单次登录，两个应用都可访问 |

## 实施步骤

### Phase 1: 数据库变更

#### 1.1 添加 auth0_id 字段到 quka_user 表

```sql
-- 新增字段
ALTER TABLE quka_user ADD COLUMN auth0_id VARCHAR(255);

-- 添加索引 (auth0_id 在 appid 范围内唯一)
CREATE UNIQUE INDEX idx_user_appid_auth0_id ON quka_user(appid, auth0_id) WHERE auth0_id IS NOT NULL;

-- 允许 password 和 salt 为空 (Auth0 用户不需要)
ALTER TABLE quka_user ALTER COLUMN password DROP NOT NULL;
ALTER TABLE quka_user ALTER COLUMN salt DROP NOT NULL;
```

#### 1.2 相关文件修改

- `app/store/sqlstore/user.sql` - 添加迁移脚本
- `pkg/types/user.go` - User struct 添加 Auth0ID 字段

```go
type User struct {
    ID        string
    Appid     string
    Auth0ID   string  // 新增: Auth0 subject identifier
    Name      string
    Avatar    string
    Email     string
    Password  string  // 可为空 (Auth0 用户)
    Salt      string  // 可为空 (Auth0 用户)
    Source    string  // 标记来源: "auth0", "local"
    PlanID    string
    UpdatedAt int64
    CreatedAt int64
}
```

---

### Phase 2: Auth0 认证集成

#### 2.1 新增 Auth0 配置

**配置文件 (service-default.toml):**

```toml
[auth0]
enabled = true
domain = "scimigo.auth0.com"  # 与 math-agents 共享
client_id = "xxx"
client_secret = "xxx"
audience = "https://api.scimigo.com"
callback_url = "https://kb.scimigo.com/api/v1/auth/callback"
```

**Go 配置结构:**

```go
// app/core/config.go
type Auth0Config struct {
    Enabled      bool   `mapstructure:"enabled"`
    Domain       string `mapstructure:"domain"`
    ClientID     string `mapstructure:"client_id"`
    ClientSecret string `mapstructure:"client_secret"`
    Audience     string `mapstructure:"audience"`
    CallbackURL  string `mapstructure:"callback_url"`
}
```

#### 2.2 新增 Auth0 认证包

创建 `pkg/auth/auth0.go`:

```go
package auth

import (
    "github.com/golang-jwt/jwt/v5"
    "github.com/lestrrat-go/jwx/v2/jwk"
)

type Auth0Validator struct {
    domain   string
    audience string
    jwks     jwk.Set
}

func NewAuth0Validator(domain, audience string) (*Auth0Validator, error) {
    // 获取 JWKS
    jwksURL := fmt.Sprintf("https://%s/.well-known/jwks.json", domain)
    jwks, err := jwk.Fetch(context.Background(), jwksURL)
    if err != nil {
        return nil, err
    }
    return &Auth0Validator{domain: domain, audience: audience, jwks: jwks}, nil
}

func (v *Auth0Validator) ValidateToken(tokenString string) (*Auth0Claims, error) {
    // 解析并验证 JWT
    token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
        kid := token.Header["kid"].(string)
        key, ok := v.jwks.LookupKeyID(kid)
        if !ok {
            return nil, errors.New("key not found")
        }
        var pubKey interface{}
        key.Raw(&pubKey)
        return pubKey, nil
    })

    if err != nil || !token.Valid {
        return nil, err
    }

    claims := token.Claims.(jwt.MapClaims)
    return &Auth0Claims{
        Sub:   claims["sub"].(string),
        Email: claims["email"].(string),
        Name:  claims["name"].(string),
    }, nil
}
```

#### 2.3 修改认证中间件

修改 `cmd/service/middleware/middleware.go`:

```go
func Authorization(core *core.Core) gin.HandlerFunc {
    return func(c *gin.Context) {
        var claims *security.TokenClaims
        var err error

        // 1. 优先检查 Auth0 JWT (Authorization: Bearer xxx)
        if authHeader := c.GetHeader("Authorization"); strings.HasPrefix(authHeader, "Bearer ") {
            token := strings.TrimPrefix(authHeader, "Bearer ")
            claims, err = validateAuth0Token(core, token, c)
            if err == nil {
                c.Set(TOKEN_CONTEXT_KEY, claims)
                c.Next()
                return
            }
        }

        // 2. 检查共享 session cookie (.scimigo.com)
        if sessionID, err := c.Cookie("session_id"); err == nil {
            claims, err = validateSessionCookie(core, sessionID, c)
            if err == nil {
                c.Set(TOKEN_CONTEXT_KEY, claims)
                c.Next()
                return
            }
        }

        // 3. 回退到现有的 X-Access-Token / X-Authorization
        // ... 保持现有逻辑 ...
    }
}

func validateAuth0Token(core *core.Core, token string, c *gin.Context) (*security.TokenClaims, error) {
    auth0Claims, err := core.Auth0Validator.ValidateToken(token)
    if err != nil {
        return nil, err
    }

    // 懒加载: 如果用户不存在则创建
    user, err := getOrCreateAuth0User(core, auth0Claims)
    if err != nil {
        return nil, err
    }

    return &security.TokenClaims{
        Appid: core.DefaultAppid(),
        User:  user.ID,
        // ...
    }, nil
}
```

---

### Phase 3: 共享 Session (SSO)

#### 3.1 Session 结构 (与 Math-Agents 兼容)

Math-Agents 的 session 存储在 Redis:
- Key: `authsession:{session_id}`
- Value: `{"user_id": "...", "access_token": "...", "id_token": "...", "refresh_token": "..."}`
- TTL: 7 days

QukaAI 需要能读取这个 session:

```go
// pkg/auth/session.go
type SharedSession struct {
    UserID       string `json:"user_id"`       // Math-Agents 的 UUID
    AccessToken  string `json:"access_token"`  // Auth0 access token
    IDToken      string `json:"id_token"`      // Auth0 ID token
    RefreshToken string `json:"refresh_token"` // Auth0 refresh token
}

func (s *SessionService) GetSharedSession(sessionID string) (*SharedSession, error) {
    key := fmt.Sprintf("authsession:%s", sessionID)
    data, err := s.redis.Get(context.Background(), key).Bytes()
    if err != nil {
        return nil, err
    }

    var session SharedSession
    if err := json.Unmarshal(data, &session); err != nil {
        return nil, err
    }
    return &session, nil
}
```

#### 3.2 从 Session 获取/创建 QukaAI 用户

```go
func validateSessionCookie(core *core.Core, sessionID string, c *gin.Context) (*security.TokenClaims, error) {
    // 1. 从 Redis 获取共享 session
    session, err := core.SessionService.GetSharedSession(sessionID)
    if err != nil {
        return nil, err
    }

    // 2. 解析 ID token 获取 auth0_id
    auth0Claims, err := core.Auth0Validator.ParseIDToken(session.IDToken)
    if err != nil {
        return nil, err
    }

    // 3. 懒加载: 获取或创建 QukaAI 用户
    user, err := getOrCreateAuth0User(core, auth0Claims)
    if err != nil {
        return nil, err
    }

    return &security.TokenClaims{
        Appid: core.DefaultAppid(),
        User:  user.ID,
    }, nil
}
```

---

### Phase 4: 用户懒加载逻辑

#### 4.1 新增 UserLogic 方法

```go
// app/logic/v1/user.go

// GetOrCreateByAuth0ID 根据 Auth0 ID 获取或创建用户
func (l *UserLogic) GetOrCreateByAuth0ID(appid string, auth0Claims *auth.Auth0Claims) (*types.User, error) {
    // 1. 尝试通过 auth0_id 查找现有用户
    user, err := l.core.Store.User().GetByAuth0ID(appid, auth0Claims.Sub)
    if err == nil {
        return user, nil
    }

    if !errors.Is(err, sql.ErrNoRows) {
        return nil, err
    }

    // 2. 用户不存在，创建新用户
    userID := utils.GenUniqIDStr()

    newUser := &types.User{
        ID:      userID,
        Appid:   appid,
        Auth0ID: auth0Claims.Sub,
        Email:   auth0Claims.Email,
        Name:    auth0Claims.Name,
        Avatar:  auth0Claims.Picture,
        Source:  "auth0",
        // Password 和 Salt 留空
    }

    // 3. 事务: 创建用户 + 默认 workspace
    err = l.core.Store.Transaction(func(tx *sqlx.Tx) error {
        if err := l.core.Store.User().CreateWithTx(tx, newUser); err != nil {
            return err
        }

        // 创建默认 workspace
        spaceID := utils.GenUniqIDStr()
        space := &types.Space{
            SpaceID: spaceID,
            Appid:   appid,
            Title:   fmt.Sprintf("%s's Knowledge Base", auth0Claims.Name),
        }
        if err := l.core.Store.Space().CreateWithTx(tx, space); err != nil {
            return err
        }

        // 关联用户和 workspace
        return l.core.Store.UserSpace().CreateWithTx(tx, &types.UserSpace{
            UserID:  userID,
            SpaceID: spaceID,
            Role:    "chief",
        })
    })

    if err != nil {
        return nil, err
    }

    return newUser, nil
}
```

#### 4.2 新增 UserStore 方法

```go
// app/store/sqlstore/user.go

func (s *UserStore) GetByAuth0ID(appid, auth0ID string) (*types.User, error) {
    query := `SELECT * FROM quka_user WHERE appid = $1 AND auth0_id = $2`
    var user types.User
    err := s.db.Get(&user, query, appid, auth0ID)
    return &user, err
}
```

---

### Phase 5: API 端点

#### 5.1 新增 Auth 路由

```go
// cmd/service/router.go

func SetupRoutes(r *gin.Engine, core *core.Core) {
    v1 := r.Group("/api/v1")

    // Auth0 相关端点
    auth := v1.Group("/auth")
    {
        auth.GET("/login", handler.Auth0Login(core))       // 重定向到 Auth0
        auth.GET("/callback", handler.Auth0Callback(core)) // Auth0 回调
        auth.POST("/logout", handler.Auth0Logout(core))    // 登出
        auth.GET("/me", middleware.Authorization(core), handler.GetCurrentUser(core))
    }

    // ... 其他路由 ...
}
```

#### 5.2 Auth Handler 实现

```go
// cmd/service/handler/auth.go

func Auth0Login(core *core.Core) gin.HandlerFunc {
    return func(c *gin.Context) {
        redirectURI := c.Query("redirect_uri")
        if redirectURI == "" {
            redirectURI = "https://kb.scimigo.com"
        }

        state := base64.URLEncoding.EncodeToString([]byte(redirectURI))

        authURL := fmt.Sprintf(
            "https://%s/authorize?client_id=%s&response_type=code&scope=openid profile email&redirect_uri=%s&audience=%s&state=%s",
            core.Config.Auth0.Domain,
            core.Config.Auth0.ClientID,
            url.QueryEscape(core.Config.Auth0.CallbackURL),
            url.QueryEscape(core.Config.Auth0.Audience),
            state,
        )

        c.Redirect(http.StatusFound, authURL)
    }
}

func Auth0Callback(core *core.Core) gin.HandlerFunc {
    return func(c *gin.Context) {
        code := c.Query("code")
        state := c.Query("state")

        // 1. 用 code 换 tokens
        tokens, err := exchangeCodeForTokens(core, code)
        if err != nil {
            c.JSON(500, gin.H{"error": "token exchange failed"})
            return
        }

        // 2. 解析 ID token
        auth0Claims, err := core.Auth0Validator.ParseIDToken(tokens.IDToken)
        if err != nil {
            c.JSON(500, gin.H{"error": "invalid id token"})
            return
        }

        // 3. 获取或创建用户
        user, err := core.Logic.User().GetOrCreateByAuth0ID(core.DefaultAppid(), auth0Claims)
        if err != nil {
            c.JSON(500, gin.H{"error": "user creation failed"})
            return
        }

        // 4. 创建/更新共享 session (写入 Redis，与 Math-Agents 格式兼容)
        sessionID := uuid.New().String()
        sessionData := map[string]interface{}{
            "user_id":       user.ID,  // 注意: 这里存 QukaAI 的 user ID
            "access_token":  tokens.AccessToken,
            "id_token":      tokens.IDToken,
            "refresh_token": tokens.RefreshToken,
        }
        core.Redis.SetEx(c, "authsession:"+sessionID, sessionData, 7*24*time.Hour)

        // 5. 设置 cookie (domain: .scimigo.com)
        c.SetCookie(
            "session_id",
            sessionID,
            604800,           // 7 days
            "/",
            ".scimigo.com",   // 共享 cookie domain
            true,             // secure
            true,             // httponly
        )

        // 6. 重定向到原始页面
        redirectURI, _ := base64.URLEncoding.DecodeString(state)
        c.Redirect(http.StatusFound, string(redirectURI))
    }
}
```

---

### Phase 6: 前端集成 (如适用)

如果 QukaAI 有前端，需要:

1. 登录按钮链接到 `/api/v1/auth/login`
2. 处理登录后的重定向
3. 调用 API 时携带 cookie (credentials: 'include')

---

## 文件修改清单

| 文件 | 修改类型 | 说明 |
|------|----------|------|
| `app/core/config.go` | 修改 | 添加 Auth0Config |
| `app/core/core.go` | 修改 | 初始化 Auth0Validator |
| `pkg/types/user.go` | 修改 | User struct 添加 Auth0ID |
| `pkg/auth/auth0.go` | 新增 | Auth0 JWT 验证 |
| `pkg/auth/session.go` | 新增 | 共享 session 处理 |
| `app/store/sqlstore/user.go` | 修改 | 添加 GetByAuth0ID 方法 |
| `app/store/sqlstore/user.sql` | 修改 | 添加迁移脚本 |
| `app/logic/v1/user.go` | 修改 | 添加 GetOrCreateByAuth0ID |
| `cmd/service/handler/auth.go` | 新增 | Auth0 endpoints |
| `cmd/service/middleware/middleware.go` | 修改 | 支持 Auth0 + session cookie |
| `cmd/service/router.go` | 修改 | 添加 auth 路由 |
| `cmd/service/etc/service-default.toml` | 修改 | 添加 Auth0 配置 |

---

## 依赖添加

```bash
go get github.com/golang-jwt/jwt/v5
go get github.com/lestrrat-go/jwx/v2/jwk
go get github.com/google/uuid
```

---

## 部署配置

### 环境变量 / 配置

```toml
[auth0]
enabled = true
domain = "scimigo.auth0.com"
client_id = "${AUTH0_CLIENT_ID}"
client_secret = "${AUTH0_CLIENT_SECRET}"
audience = "https://api.scimigo.com"
callback_url = "https://kb.scimigo.com/api/v1/auth/callback"
```

### Auth0 Dashboard 配置

1. **Allowed Callback URLs**: 添加 `https://kb.scimigo.com/api/v1/auth/callback`
2. **Allowed Logout URLs**: 添加 `https://kb.scimigo.com`
3. **Allowed Web Origins**: 添加 `https://kb.scimigo.com`

### Nginx / 负载均衡

确保 cookie domain `.scimigo.com` 在所有子域名间共享。

---

## 测试计划

1. **单元测试**: Auth0 token 验证逻辑
2. **集成测试**:
   - Auth0 登录流程
   - 用户懒加载创建
   - 共享 session 读取
3. **端到端测试**:
   - 在 app.scimigo.com 登录 → 访问 kb.scimigo.com → 自动认证
   - 在 kb.scimigo.com 登录 → 访问 app.scimigo.com → 自动认证

---

## 风险与缓解

| 风险 | 缓解措施 |
|------|----------|
| Session 格式不兼容 | 两端使用相同的 JSON 结构 |
| Cookie 跨域问题 | 使用 `.scimigo.com` 作为 cookie domain |
| Auth0 rate limits | 缓存 JWKS，使用合理的刷新间隔 |
| 用户 ID 冲突 | QukaAI 用 snowflake ID，Math-Agents 用 UUID，通过 auth0_id 关联 |

---

## 时间线

- [x] Phase 1: 数据库变更
- [x] Phase 2: Auth0 认证集成
- [x] Phase 3: 共享 Session (中间件)
- [x] Phase 4: 用户懒加载
- [x] Phase 5: API 端点
- [ ] Phase 6: 测试与部署

---

## 待确认问题

1. **Auth0 tenant 信息**: 需要从 math-agents 获取 Auth0 配置
2. **Redis 实例**: QukaAI 和 Math-Agents 是否共享同一个 Redis?
3. **订阅计划**: QukaAI 的 plan 是否独立于 Math-Agents 的 subscription_tier?
