# Quka AI (kb.scimigo.com) Deployment Guide

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                         User Traffic                             │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
        ┌─────────────────────────────────────────────┐
        │           Shared ALB (math-agents-alb)      │
        │                                             │
        │  api.scimigo.com → math-agents-backend-tg   │
        │  kb.scimigo.com  → quka-ai-backend-tg       │
        │                                             │
        └─────────────────────────────────────────────┘
                              │
                ┌─────────────┴─────────────┐
                │                           │
                ▼                           ▼
        ┌───────────────┐           ┌───────────────┐
        │  Math-Agents  │           │   Quka AI     │
        │  Backend ECS  │           │  Backend ECS  │
        │  (Python)     │           │  (Go)         │
        └───────────────┘           └───────────────┘
                │                           │
                └───────────┬───────────────┘
                            │
                            ▼
                    ┌───────────────┐
                    │  Shared Redis │  ← SSO Sessions
                    │ (ElastiCache) │    authsession:*
                    └───────────────┘
```

## Prerequisites

1. **AWS CLI** configured with appropriate permissions
2. **Docker** installed for building images
3. **Access to existing infrastructure** (VPC, ALB, Redis from math-agents)

## Deployment Steps

### Step 1: Create AWS Secrets

```bash
cd deploy
./create-secrets.sh
```

This will prompt for:
- PostgreSQL connection string
- Auth0 Client ID and Secret
- S3 credentials (if using dedicated bucket)

### Step 2: Create Production Config

1. Copy the template:
```bash
cp service-production.toml service-production.local.toml
```

2. Edit with actual values:
```bash
vim service-production.local.toml
```

3. Store in Secrets Manager:
```bash
# Base64 encode and store
aws secretsmanager update-secret \
  --secret-id prod/quka/config \
  --secret-string "$(cat service-production.local.toml | base64)" \
  --region us-east-1
```

### Step 3: Deploy to ECS

```bash
./deploy-backend.sh
```

This script will:
1. Create ECR repository (if needed)
2. Build and push Docker image
3. Create Target Group for kb.scimigo.com
4. Add ALB listener rule
5. Register ECS task definition
6. Create/update ECS service

### Step 4: Configure DNS

Add Route53 A record (alias) for kb.scimigo.com pointing to the ALB:

```bash
# Get ALB DNS name
aws elbv2 describe-load-balancers \
  --load-balancer-arns arn:aws:elasticloadbalancing:us-east-1:204338471371:loadbalancer/app/math-agents-alb/d53ee0378da28c87 \
  --query 'LoadBalancers[0].DNSName' \
  --output text
```

In Route53:
- Name: `kb.scimigo.com`
- Type: A - Alias
- Target: Application Load Balancer → math-agents-alb

### Step 5: Configure Auth0

In Auth0 Dashboard (https://manage.auth0.com):

1. **Application Settings** (Regular Web Application):
   - Add Callback URL: `https://kb.scimigo.com/api/v1/auth/callback`
   - Add Logout URL: `https://kb.scimigo.com`
   - Add Web Origins: `https://kb.scimigo.com`

2. **API Settings** (if using same API as math-agents):
   - Audience should be: `https://api.scimigo.com`

## SSO Flow

1. User visits `kb.scimigo.com`
2. Not logged in → Redirect to Auth0 (`/api/v1/auth/login`)
3. Auth0 authenticates user
4. Callback to `kb.scimigo.com/api/v1/auth/callback`
5. QukaAI creates/fetches user, creates session in Redis
6. Sets `session_id` cookie on `.scimigo.com` domain
7. User is logged in

**Cross-app SSO:**
- If user already logged into `app.scimigo.com`, they have a `session_id` cookie
- When visiting `kb.scimigo.com`, middleware reads the cookie
- Validates session from shared Redis
- User is automatically authenticated

## Monitoring

### View Logs
```bash
aws logs tail /ecs/quka-ai-backend --follow --region us-east-1
```

### Check Service Status
```bash
aws ecs describe-services \
  --cluster math-agents-cluster \
  --services quka-ai-backend-service \
  --region us-east-1
```

### Health Check
```bash
curl https://kb.scimigo.com/api/v1/mode
```

## Troubleshooting

### Service not starting
1. Check CloudWatch logs for errors
2. Verify secrets are set correctly
3. Check security group allows traffic from ALB

### SSO not working
1. Verify Redis connectivity from both services
2. Check cookie domain is `.scimigo.com`
3. Ensure both apps use same Auth0 tenant

### Database connection issues
1. Verify RDS security group allows ECS security group
2. Check DSN format in config
3. Ensure database exists and user has permissions

## Cost Estimate

| Resource | Monthly Cost |
|----------|-------------|
| ECS Fargate (512 CPU, 1GB) | ~$15 |
| Target Group | ~$0.50 |
| CloudWatch Logs | ~$1-5 |
| **Total Additional** | ~$17-21/month |

*Note: ALB, Redis, and VPC are shared with math-agents (no additional cost)*

## Files Reference

```
deploy/
├── DEPLOYMENT_GUIDE.md      # This file
├── deploy-backend.sh        # Main deployment script
├── create-secrets.sh        # AWS Secrets Manager setup
├── infrastructure-config.env # AWS resource IDs
├── service-production.toml  # Config template
└── task-definition-backend.json # ECS task definition
```
