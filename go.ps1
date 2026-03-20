Set-Location $PSScriptRoot

Write-Host "Step 1: Initialising git..."
git init -b main
git add .
git commit -m "empycompress v3.4.0 - Empyrean Secure Compression"

Write-Host "Step 2: Creating GitHub repository..."
gh repo create empycompress --public --description "Empyrean Secure Compression" --source=. --remote=origin

Write-Host "Step 3: Pushing main branch with workflow file..."
git push origin main

Write-Host "Step 4: Waiting 5 seconds for GitHub to register the workflow..."
Start-Sleep -Seconds 5

Write-Host "Step 5: Tagging and pushing to trigger the build..."
git tag v3.4.0
git push origin v3.4.0

$user = gh api user --jq .login
Write-Host ""
Write-Host "Build running at:"
Write-Host "https://github.com/$user/empycompress/actions"
