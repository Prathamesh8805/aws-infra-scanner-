#!/bin/bash

# Colors for terminal output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}AWS Infrastructure Scanner - GitHub Repository Setup${NC}"
echo "This script will create a new GitHub repository and push your code."
echo ""

# Get GitHub username
USERNAME="prathameshinnovapptive"
REPO_NAME="aws-infra-scanner"

echo -e "${YELLOW}Step 1: Creating GitHub repository...${NC}"
echo "Please enter your GitHub personal access token (with 'repo' permissions):"
read -s TOKEN

# Create GitHub repository
echo "Creating repository $REPO_NAME..."
RESPONSE=$(curl -s -X POST \
  -H "Authorization: token $TOKEN" \
  -H "Accept: application/vnd.github.v3+json" \
  https://api.github.com/user/repos \
  -d "{\"name\":\"$REPO_NAME\",\"description\":\"AWS Infrastructure Scanner - Security, Compliance, and Cost Optimization Tool\",\"private\":false}")

if [[ $RESPONSE == *"name already exists"* ]]; then
  echo -e "${RED}Error: Repository name already exists.${NC}"
  exit 1
elif [[ $RESPONSE == *"Bad credentials"* ]]; then
  echo -e "${RED}Error: Invalid GitHub token.${NC}"
  exit 1
elif [[ $RESPONSE == *"html_url"* ]]; then
  REPO_URL=$(echo $RESPONSE | grep -o 'https://github.com/[^"]*')
  echo -e "${GREEN}Repository created successfully: $REPO_URL${NC}"
else
  echo -e "${RED}Error creating repository: $RESPONSE${NC}"
  exit 1
fi

echo -e "${YELLOW}Step 2: Initializing local Git repository...${NC}"
git init
git add .
git commit -m "Initial commit: AWS Infrastructure Scanner"

echo -e "${YELLOW}Step 3: Pushing to GitHub...${NC}"
git remote add origin https://github.com/$USERNAME/$REPO_NAME.git
git branch -M main
git push -u origin main

if [ $? -eq 0 ]; then
  echo -e "${GREEN}Success! Your code has been pushed to GitHub.${NC}"
  echo "Repository URL: https://github.com/$USERNAME/$REPO_NAME"
else
  echo -e "${RED}Error pushing to GitHub. Please check your credentials and try again.${NC}"
  echo "You can try pushing manually with:"
  echo "git push -u origin main"
fi
