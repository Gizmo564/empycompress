#!/bin/bash
set -e

cd "$(dirname "$0")"

echo "Step 1: Initialising git..."
git init -b main
git add .
git commit -m "empycompress v3.4.0 - Empyrean Secure Compression"

echo "Step 2: Creating GitHub repository..."
gh repo create empycompress --public --description "Empyrean Secure Compression" --source=. --remote=origin

echo "Step 3: Pushing main branch with workflow file..."
git push origin main

echo "Step 4: Waiting 5 seconds for GitHub to register the workflow..."
sleep 5

echo "Step 5: Tagging and pushing to trigger the build..."
git tag v3.4.0
git push origin v3.4.0

echo ""
echo "Build running at:"
echo "https://github.com/$(gh api user --jq .login)/empycompress/actions"
