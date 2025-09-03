#!/bin/bash

# Sample login script for production environment
# Replace with your actual AWS login commands

echo "Logging into production AWS account..."

# Example: Using AWS SSO login
# aws sso login --profile production

# Example: Using AWS credentials
# export AWS_ACCESS_KEY_ID="your-access-key"
# export AWS_SECRET_ACCESS_KEY="your-secret-key"
# export AWS_SESSION_TOKEN="your-session-token"
# export AWS_REGION="us-east-1"

# Example: Using AWS assume role
# ROLE_ARN="arn:aws:iam::123456789012:role/YourRole"
# SESSION_NAME="eks-infra-scan-session"
# 
# CREDENTIALS=$(aws sts assume-role \
#     --role-arn "$ROLE_ARN" \
#     --role-session-name "$SESSION_NAME" \
#     --query 'Credentials' \
#     --output json)
# 
# export AWS_ACCESS_KEY_ID=$(echo $CREDENTIALS | jq -r '.AccessKeyId')
# export AWS_SECRET_ACCESS_KEY=$(echo $CREDENTIALS | jq -r '.SecretAccessKey')
# export AWS_SESSION_TOKEN=$(echo $CREDENTIALS | jq -r '.SessionToken')

# For demonstration purposes, we'll just set dummy environment variables
export AWS_PROFILE="production"
export AWS_REGION="us-east-1"

echo "Successfully logged into production AWS account"
echo "AWS_PROFILE: $AWS_PROFILE"
echo "AWS_REGION: $AWS_REGION"
