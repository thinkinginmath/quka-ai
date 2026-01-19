#!/bin/bash
set -e

# Docker entrypoint script for Quka AI
# Fetches secrets from AWS Secrets Manager and sets them as environment variables

AWS_REGION=${AWS_REGION:-us-east-1}

# Function to fetch a secret from AWS Secrets Manager
fetch_secret() {
    local secret_name="$1"
    local env_var="$2"

    if [ -z "${!env_var}" ]; then
        value=$(aws secretsmanager get-secret-value \
            --secret-id "$secret_name" \
            --query 'SecretString' \
            --output text \
            --region "$AWS_REGION" 2>/dev/null || echo "")

        if [ -n "$value" ]; then
            export "$env_var"="$value"
            echo "✅ Loaded $env_var from Secrets Manager"
        fi
    else
        echo "ℹ️  $env_var already set, skipping Secrets Manager"
    fi
}

echo "🔐 Loading secrets from AWS Secrets Manager..."

# Fetch secrets (only if not already set as env vars)
fetch_secret "prod/quka/db-url" "QUKA_DB_DSN"
fetch_secret "prod/quka/auth0-client-id" "QUKA_AUTH0_CLIENT_ID"
fetch_secret "prod/quka/auth0-client-secret" "QUKA_AUTH0_CLIENT_SECRET"
fetch_secret "prod/quka/encrypt-key" "QUKA_ENCRYPT_KEY"
fetch_secret "prod/quka/redis-url" "QUKA_REDIS_URL"
fetch_secret "prod/quka/s3-access-key" "QUKA_S3_ACCESS_KEY"
fetch_secret "prod/quka/s3-secret-key" "QUKA_S3_SECRET_KEY"

echo "🚀 Starting Quka AI..."

# Execute the main command
exec "$@"
