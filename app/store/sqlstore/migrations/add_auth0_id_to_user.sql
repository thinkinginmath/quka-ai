-- Migration: Add auth0_id field to quka_user table for Auth0 SSO integration
-- Date: 2024-12
-- Purpose: Enable shared authentication with scimigo.com via Auth0

-- 1. Add auth0_id column (nullable, as existing users won't have it)
ALTER TABLE quka_user ADD COLUMN IF NOT EXISTS auth0_id VARCHAR(255);

-- 2. Add comment for the new column
COMMENT ON COLUMN quka_user.auth0_id IS 'Auth0 subject identifier for SSO (e.g., auth0|xxx or google-oauth2|xxx)';

-- 3. Create unique index on (appid, auth0_id) for fast lookup
-- Only index non-null values to allow multiple NULL entries
CREATE UNIQUE INDEX IF NOT EXISTS idx_user_appid_auth0_id
ON quka_user (appid, auth0_id)
WHERE auth0_id IS NOT NULL;

-- 4. Make password and salt nullable for Auth0 users (who don't need local passwords)
-- Note: These columns were NOT NULL, so we need to alter them
ALTER TABLE quka_user ALTER COLUMN password DROP NOT NULL;
ALTER TABLE quka_user ALTER COLUMN salt DROP NOT NULL;

-- 5. Update existing users to have source = 'local' if not set
UPDATE quka_user SET source = 'local' WHERE source = '' OR source IS NULL;
