#!/bin/bash
set -e

# Create AWS Secrets Manager secrets for Quka AI
# Run this BEFORE deploy-backend.sh

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

# Load infrastructure configuration
if [ -f "$SCRIPT_DIR/infrastructure-config.env" ]; then
    export $(grep -v '^#' "$SCRIPT_DIR/infrastructure-config.env" | xargs)
fi

AWS_REGION=${AWS_REGION:-us-east-1}

echo "🔐 Creating Quka AI secrets in AWS Secrets Manager"
echo "📍 Region: $AWS_REGION"
echo ""

# Function to create or update a secret
create_secret() {
    local name="$1"
    local description="$2"
    local value="$3"

    if aws secretsmanager describe-secret --secret-id "$name" --region "$AWS_REGION" >/dev/null 2>&1; then
        echo "   Updating existing secret: $name"
        aws secretsmanager update-secret \
            --secret-id "$name" \
            --secret-string "$value" \
            --region "$AWS_REGION" >/dev/null
    else
        echo "   Creating new secret: $name"
        aws secretsmanager create-secret \
            --name "$name" \
            --description "$description" \
            --secret-string "$value" \
            --region "$AWS_REGION" >/dev/null
    fi
}

echo "📝 Enter the following values (press Enter to skip):"
echo ""

# Database URL
read -p "PostgreSQL DSN (postgresql://user:pass@host:5432/db): " DB_DSN
if [ -n "$DB_DSN" ]; then
    create_secret "prod/quka/db-url" "Quka AI database connection string" "$DB_DSN"
    echo "✅ Database secret created"
fi

# Auth0 Client ID (may be same as math-agents or different)
read -p "Auth0 Client ID for kb.scimigo.com: " AUTH0_CLIENT_ID
if [ -n "$AUTH0_CLIENT_ID" ]; then
    create_secret "prod/quka/auth0-client-id" "Quka AI Auth0 Client ID" "$AUTH0_CLIENT_ID"
    echo "✅ Auth0 Client ID secret created"
fi

# Auth0 Client Secret
read -p "Auth0 Client Secret: " AUTH0_CLIENT_SECRET
if [ -n "$AUTH0_CLIENT_SECRET" ]; then
    create_secret "prod/quka/auth0-client-secret" "Quka AI Auth0 Client Secret" "$AUTH0_CLIENT_SECRET"
    echo "✅ Auth0 Client Secret secret created"
fi

# S3 Access Key (for object storage)
read -p "S3 Access Key ID: " S3_ACCESS_KEY
if [ -n "$S3_ACCESS_KEY" ]; then
    create_secret "prod/quka/s3-access-key" "Quka AI S3 Access Key" "$S3_ACCESS_KEY"
    echo "✅ S3 Access Key secret created"
fi

# S3 Secret Key
read -p "S3 Secret Access Key: " S3_SECRET_KEY
if [ -n "$S3_SECRET_KEY" ]; then
    create_secret "prod/quka/s3-secret-key" "Quka AI S3 Secret Key" "$S3_SECRET_KEY"
    echo "✅ S3 Secret Key secret created"
fi

# Encryption Key (16 bytes for AES)
ENCRYPT_KEY=$(openssl rand -hex 8)  # 16 characters
create_secret "prod/quka/encrypt-key" "Quka AI data encryption key" "$ENCRYPT_KEY"
echo "✅ Encryption key secret created (auto-generated)"

echo ""
echo "🎉 Secrets setup complete!"
echo ""
echo "📋 Created secrets:"
aws secretsmanager list-secrets \
    --filter Key="name",Values="prod/quka" \
    --query 'SecretList[].Name' \
    --output table \
    --region "$AWS_REGION"
echo ""
echo "⚠️  Note: You still need to create the full config TOML and store it as base64:"
echo "   1. Edit deploy/service-production.toml with your values"
echo "   2. base64 encode it: cat service-production.toml | base64"
echo "   3. Store in secret: aws secretsmanager update-secret --secret-id prod/quka/config --secret-string '<base64>' --region $AWS_REGION"
