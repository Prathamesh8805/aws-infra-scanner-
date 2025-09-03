#!/bin/bash

# Colors for terminal output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}AWS Infrastructure Scanner - GitHub Repository Setup${NC}"
echo "This script will push your code to an existing GitHub repository."
echo ""

# Set GitHub username
USERNAME="prathameshinnovapptive"
REPO_NAME="aws-infra-scanner"
REPO_URL="https://github.com/$USERNAME/$REPO_NAME.git"

echo -e "${YELLOW}Step 1: Before continuing, make sure you've created the repository at:${NC}"
echo "https://github.com/new"
echo ""
echo "Repository name: $REPO_NAME"
echo "Description: AWS Infrastructure Scanner - Security, Compliance, and Cost Optimization Tool"
echo "Visibility: Public"
echo "DO NOT initialize with README, .gitignore, or license"
echo ""
read -p "Have you created the repository? (y/n): " created_repo

if [[ $created_repo != "y" && $created_repo != "Y" ]]; then
  echo "Please create the repository first and then run this script again."
  exit 1
fi

echo -e "${YELLOW}Step 2: Initializing local Git repository...${NC}"
git init
git add .
git commit -m "Initial commit: AWS Infrastructure Scanner"

echo -e "${YELLOW}Step 3: Pushing to GitHub...${NC}"
echo "You'll be prompted for your GitHub username and password."
echo "Note: If you have 2FA enabled, you'll need to use a personal access token instead of your password."
echo ""

git remote add origin $REPO_URL
git branch -M main
git push -u origin main

if [ $? -eq 0 ]; then
  echo -e "${GREEN}Success! Your code has been pushed to GitHub.${NC}"
  echo "Repository URL: $REPO_URL"
else
  echo "Error pushing to GitHub."
  echo ""
  echo "Alternative method:"
  echo "1. Create a personal access token at: https://github.com/settings/tokens"
  echo "2. Use the token as your password when prompted"
  echo ""
  echo "Or try GitHub Desktop: https://desktop.github.com/"
fi
