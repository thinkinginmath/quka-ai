# TODO: Launch kb.scimigo.com

## Build Errors to Fix

### 1. cmd/migrate/command.go - Database config field name
```
cmd/migrate/command.go:70:37: cfg.Database undefined
cmd/migrate/command.go:129:37: cfg.Database undefined
```
**Fix:** Change `cfg.Database` to `cfg.Postgres` (the actual field name in CoreConfig)

### 2. cmd/service/middleware/middleware.go - Missing GetByAuth0ID method
```
cmd/service/middleware/middleware.go:522:40: store.UserStore has no field or method GetByAuth0ID
```
**Fix:** Add `GetByAuth0ID` to the `store.UserStore` interface in `app/store/user.go`

### 3. cmd/service/handler/auth0.go - Missing i18n error codes
```
cmd/service/handler/auth0.go:48:54: undefined: i18n.ERROR_NOT_IMPLEMENTED
cmd/service/handler/auth0.go:84:53: undefined: i18n.ERROR_NOT_IMPLEMENTED
cmd/service/handler/auth0.go:100:68: undefined: i18n.ERROR_INVALID_PARAM
cmd/service/handler/auth0.go:174:53: undefined: i18n.ERROR_NOT_IMPLEMENTED
```
**Fix:** Add missing error codes to `pkg/i18n/` error definitions

### 4. cmd/service/handler/auth0.go - Missing GetByAuth0ID method
```
cmd/service/handler/auth0.go:301:43: store.UserStore has no field or method GetByAuth0ID
```
**Fix:** Same as #2 above

---

## Remaining Setup Tasks

### Infrastructure
- [ ] Create RDS database for QukaAI (or reuse existing)
- [ ] Verify Redis access (shared with math-agents for SSO)
- [ ] Create S3 bucket for file storage
- [ ] Set up DNS record: kb.scimigo.com → ALB

### AWS Secrets Manager
- [ ] Run `deploy/create-secrets.sh` to create secrets:
  - `prod/quka/db-url`
  - `prod/quka/auth0-client-id`
  - `prod/quka/auth0-client-secret`
  - `prod/quka/encrypt-key`
  - `prod/quka/redis-url`

### Auth0 Configuration
- [ ] Add callback URL: `https://kb.scimigo.com/api/v1/auth/callback`
- [ ] Add logout URL: `https://kb.scimigo.com`
- [ ] Add web origin: `https://kb.scimigo.com`

### Database Migration
- [ ] Run migration: `./quka migrate -c config.toml`
- [ ] Verify `quka_user.auth0_id` column exists

### Deployment
- [ ] Build and push Docker image
- [ ] Deploy ECS service: `./deploy/deploy-backend.sh`
- [ ] Verify health check passes

### Testing
- [ ] Test Auth0 login flow on kb.scimigo.com
- [ ] Test SSO: login on app.scimigo.com → auto-login on kb.scimigo.com
- [ ] Test user lazy creation on first login

---

## Files Modified (Uncommitted)

```
modified:   .gitignore                    # Added deploy/*.local.toml, notes.txt
modified:   app/core/config.go            # Added env var substitution
modified:   deploy/service-production.toml # Uses ${VAR} syntax for secrets
new file:   deploy/docker-entrypoint.sh   # Fetches secrets from AWS SM
```

## Commits Made

1. `ee4b17e` - feat: add Auth0 SSO integration for kb.scimigo.com deployment
2. `30ae113` - feat: add database migration CLI command

---

## Quick Fix Commands

```bash
# After fixing build errors, test build:
go build -o /tmp/quka ./cmd/

# Run migrations (after deploy):
./quka migrate -c /path/to/config.toml

# Check migration status:
./quka migrate status -c /path/to/config.toml
```
