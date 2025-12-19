#!/bin/bash
set -e

# Quka AI Backend Deployment Script for AWS ECS
# Deploys kb.scimigo.com alongside api.scimigo.com (math-agents)
# Shares infrastructure: VPC, ALB, Redis (for SSO), Security Groups

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
PROJECT_ROOT="$SCRIPT_DIR/.."

# Load infrastructure configuration
if [ -f "$SCRIPT_DIR/infrastructure-config.env" ]; then
    export $(grep -v '^#' "$SCRIPT_DIR/infrastructure-config.env" | xargs)
fi

# Load production secrets (optional local override)
if [ -f "$PROJECT_ROOT/.env.production" ]; then
    export $(grep -v '^#' "$PROJECT_ROOT/.env.production" | xargs)
fi

echo "🚀 Starting Quka AI (kb.scimigo.com) backend deployment"
echo "📍 Region: $AWS_REGION"
echo "🏗️ ECR Repository: $ECR_REPOSITORY_BACKEND"

# Validate required environment variables
REQUIRED_VARS=(
    "AWS_REGION"
    "AWS_ACCOUNT_ID"
    "ECR_REPOSITORY_BACKEND"
    "ECS_CLUSTER"
    "ECS_SERVICE_BACKEND"
    "SUBNET_PUBLIC_1"
    "SUBNET_PUBLIC_2"
    "SG_ECS"
    "SSL_CERTIFICATE_ARN"
    "ALB_ARN"
)

for var in "${REQUIRED_VARS[@]}"; do
    if [ -z "${!var}" ]; then
        echo "❌ ERROR: $var environment variable is not set"
        exit 1
    fi
done

# 1. Create ECR repository if it doesn't exist
echo "📦 Setting up ECR repository..."
aws ecr create-repository \
    --repository-name "$ECR_REPOSITORY_BACKEND" \
    --region "$AWS_REGION" 2>/dev/null || echo "Repository already exists"

# Get ECR login
echo "🔐 Logging into ECR..."
aws ecr get-login-password --region "$AWS_REGION" | \
    docker login --username AWS --password-stdin "$AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com"

# 2. Build and push Docker image
echo "🐳 Building Docker image..."
cd "$PROJECT_ROOT"

# Build for x86_64 (ECS Fargate requirement)
docker build --platform linux/amd64 -t "$ECR_REPOSITORY_BACKEND:latest" .

# Tag and push to ECR
ECR_URI="$AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com/$ECR_REPOSITORY_BACKEND"
docker tag "$ECR_REPOSITORY_BACKEND:latest" "$ECR_URI:latest"

echo "📤 Pushing image to ECR..."
docker push "$ECR_URI:latest"
echo "✅ Image pushed successfully"

# 3. Get Redis endpoint (shared with math-agents for SSO)
echo "🔍 Getting Redis endpoint..."
REDIS_ENDPOINT=$(aws elasticache describe-cache-clusters \
    --cache-cluster-id "$CACHE_CLUSTER_ID" \
    --show-cache-node-info \
    --query 'CacheClusters[0].CacheNodes[0].Endpoint.Address' \
    --output text \
    --region "$AWS_REGION" 2>/dev/null || echo "")

if [ -z "$REDIS_ENDPOINT" ] || [ "$REDIS_ENDPOINT" = "None" ]; then
    echo "❌ ERROR: Redis cluster not found. SSO requires shared Redis with math-agents!"
    exit 1
fi
echo "✅ Redis endpoint: $REDIS_ENDPOINT"

# 4. Create CloudWatch Log Group
echo "📊 Creating CloudWatch log group..."
aws logs create-log-group \
    --log-group-name "/ecs/quka-ai-backend" \
    --region "$AWS_REGION" 2>/dev/null || echo "Log group already exists"

# 5. Create Target Group for kb.scimigo.com
echo "🎯 Setting up Target Group..."
TARGET_GROUP_ARN=$(aws elbv2 describe-target-groups \
    --names "quka-ai-backend-tg" \
    --query 'TargetGroups[0].TargetGroupArn' \
    --output text \
    --region "$AWS_REGION" 2>/dev/null || echo "")

if [ -z "$TARGET_GROUP_ARN" ] || [ "$TARGET_GROUP_ARN" = "None" ]; then
    echo "Creating new target group..."
    TARGET_GROUP_ARN=$(aws elbv2 create-target-group \
        --name "quka-ai-backend-tg" \
        --protocol HTTP \
        --port 33033 \
        --vpc-id "$VPC_ID" \
        --target-type ip \
        --health-check-enabled \
        --health-check-path "/api/v1/mode" \
        --health-check-interval-seconds 30 \
        --health-check-timeout-seconds 5 \
        --healthy-threshold-count 2 \
        --unhealthy-threshold-count 3 \
        --query 'TargetGroups[0].TargetGroupArn' \
        --output text \
        --region "$AWS_REGION")
    echo "✅ Target group created: $TARGET_GROUP_ARN"
else
    echo "✅ Target group exists: $TARGET_GROUP_ARN"
fi

export TARGET_GROUP_ARN

# 6. Add listener rule for kb.scimigo.com on existing ALB
echo "🔗 Setting up ALB listener rule for kb.scimigo.com..."

# Get HTTPS listener ARN
HTTPS_LISTENER_ARN=$(aws elbv2 describe-listeners \
    --load-balancer-arn "$ALB_ARN" \
    --query 'Listeners[?Port==`443`].ListenerArn' \
    --output text \
    --region "$AWS_REGION")

if [ -n "$HTTPS_LISTENER_ARN" ]; then
    # Check if rule already exists
    RULE_EXISTS=$(aws elbv2 describe-rules \
        --listener-arn "$HTTPS_LISTENER_ARN" \
        --query "Rules[?Conditions[?Field=='host-header' && Values[?contains(@, 'kb.scimigo.com')]]].RuleArn" \
        --output text \
        --region "$AWS_REGION" 2>/dev/null || echo "")

    if [ -z "$RULE_EXISTS" ] || [ "$RULE_EXISTS" = "None" ]; then
        echo "Creating listener rule for kb.scimigo.com..."
        # Find the next available priority
        NEXT_PRIORITY=$(aws elbv2 describe-rules \
            --listener-arn "$HTTPS_LISTENER_ARN" \
            --query 'max(Rules[?Priority!=`default`].Priority)' \
            --output text \
            --region "$AWS_REGION")

        if [ "$NEXT_PRIORITY" = "None" ] || [ -z "$NEXT_PRIORITY" ]; then
            NEXT_PRIORITY=100
        else
            NEXT_PRIORITY=$((NEXT_PRIORITY + 10))
        fi

        aws elbv2 create-rule \
            --listener-arn "$HTTPS_LISTENER_ARN" \
            --priority "$NEXT_PRIORITY" \
            --conditions "Field=host-header,Values=kb.scimigo.com" \
            --actions "Type=forward,TargetGroupArn=$TARGET_GROUP_ARN" \
            --region "$AWS_REGION"
        echo "✅ Listener rule created for kb.scimigo.com (priority: $NEXT_PRIORITY)"
    else
        echo "✅ Listener rule already exists for kb.scimigo.com"
    fi
fi

# 7. Create/update config secret in Secrets Manager
echo "🔐 Setting up configuration secret..."

# Generate config TOML
CONFIG_TOML=$(cat << EOF
addr = ":33033"

[log]
level = "info"
path = ""

[postgres]
dsn = "POSTGRES_DSN_PLACEHOLDER"

[site]
default_avatar = "/image/default_avatar.png"

[site.share]
site_title = "Quka.AI Knowledge Base"
site_description = "Quka.AI - Build your second brain"

[object_storage]
static_domain = "https://kb.scimigo.com"
driver = "s3"

[object_storage.s3]
bucket = "${S3_BUCKET:-quka-ai-storage}"
region = "${AWS_REGION}"
endpoint = ""
access_key = ""
secret_key = ""
use_path_style = false

[custom_config]
encrypt_key = "ENCRYPT_KEY_PLACEHOLDER"

[auth0]
enabled = true
domain = "${AUTH0_DOMAIN}"
client_id = "AUTH0_CLIENT_ID_PLACEHOLDER"
client_secret = "AUTH0_CLIENT_SECRET_PLACEHOLDER"
audience = "${AUTH0_AUDIENCE}"
callback_url = "https://kb.scimigo.com/api/v1/auth/callback"
redis_url = "redis://${REDIS_ENDPOINT}:6379/0"
EOF
)

# Note: This creates a placeholder config. You need to manually update the secret
# with actual values for DATABASE_URL, AUTH0 credentials, etc.
echo "⚠️  IMPORTANT: Update the config secret with actual values:"
echo "   aws secretsmanager get-secret-value --secret-id prod/quka/config --region $AWS_REGION"
echo ""

# Create secret if it doesn't exist
aws secretsmanager create-secret \
    --name "prod/quka/config" \
    --description "Quka AI production configuration (TOML, base64 encoded)" \
    --secret-string "$(echo "$CONFIG_TOML" | base64)" \
    --region "$AWS_REGION" 2>/dev/null || echo "Config secret already exists"

# 8. Prepare and register task definition
echo "📋 Preparing task definition..."
export REDIS_ENDPOINT
envsubst < "$SCRIPT_DIR/task-definition-backend.json" > /tmp/task-definition-quka.json

TASK_DEFINITION_ARN=$(aws ecs register-task-definition \
    --cli-input-json file:///tmp/task-definition-quka.json \
    --query 'taskDefinition.taskDefinitionArn' \
    --output text \
    --region "$AWS_REGION")

echo "✅ Task definition registered: $TASK_DEFINITION_ARN"

# 9. Create or update ECS service
echo "🚀 Deploying ECS service..."

SERVICE_EXISTS=$(aws ecs describe-services \
    --cluster "$ECS_CLUSTER" \
    --services "$ECS_SERVICE_BACKEND" \
    --query 'services[0].serviceName' \
    --output text \
    --region "$AWS_REGION" 2>/dev/null || echo "None")

if [ "$SERVICE_EXISTS" = "None" ] || [ "$SERVICE_EXISTS" = "" ]; then
    echo "Creating new ECS service..."
    aws ecs create-service \
        --cluster "$ECS_CLUSTER" \
        --service-name "$ECS_SERVICE_BACKEND" \
        --task-definition "$TASK_DEFINITION_ARN" \
        --desired-count 1 \
        --launch-type "FARGATE" \
        --network-configuration "awsvpcConfiguration={subnets=[$SUBNET_PUBLIC_1,$SUBNET_PUBLIC_2],securityGroups=[$SG_ECS],assignPublicIp=ENABLED}" \
        --load-balancers "targetGroupArn=$TARGET_GROUP_ARN,containerName=quka-ai-backend,containerPort=33033" \
        --region "$AWS_REGION"
else
    echo "Updating existing ECS service..."
    aws ecs update-service \
        --cluster "$ECS_CLUSTER" \
        --service "$ECS_SERVICE_BACKEND" \
        --task-definition "$TASK_DEFINITION_ARN" \
        --force-new-deployment \
        --region "$AWS_REGION"
fi

echo "✅ ECS service deployed"

# 10. Wait for service to be stable
echo "⏳ Waiting for service deployment to complete..."
aws ecs wait services-stable \
    --cluster "$ECS_CLUSTER" \
    --services "$ECS_SERVICE_BACKEND" \
    --region "$AWS_REGION"

# Cleanup
rm -f /tmp/task-definition-quka.json

echo ""
echo "🎉 Quka AI (kb.scimigo.com) deployment completed!"
echo ""
echo "📋 Deployment summary:"
echo "   🏗️  ECS Cluster: $ECS_CLUSTER"
echo "   🚀 Service: $ECS_SERVICE_BACKEND"
echo "   📦 Image: $ECR_URI:latest"
echo "   🎯 Target Group: $TARGET_GROUP_ARN"
echo "   🔗 Domain: kb.scimigo.com"
echo "   🔐 Shared Redis: $REDIS_ENDPOINT (SSO with app.scimigo.com)"
echo ""
echo "⚠️  NEXT STEPS:"
echo "   1. Update DNS: Create A/ALIAS record for kb.scimigo.com → ALB"
echo "   2. Update config secret with actual database and Auth0 credentials:"
echo "      aws secretsmanager update-secret --secret-id prod/quka/config --secret-string '<base64-encoded-toml>' --region $AWS_REGION"
echo "   3. Add kb.scimigo.com callback URL in Auth0 Dashboard"
echo ""
echo "🔍 Check service status:"
echo "   aws ecs describe-services --cluster $ECS_CLUSTER --services $ECS_SERVICE_BACKEND --region $AWS_REGION"
echo ""
echo "📊 View logs:"
echo "   aws logs tail /ecs/quka-ai-backend --follow --region $AWS_REGION"
