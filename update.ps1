Set-Location $PSScriptRoot
git add .
git commit -m "empycompress v3.5.0 — fix type annotations, GUI version display, icon paths"
git tag v3.5.0
git push origin main
git push origin v3.5.0
$user = gh api user --jq .login
Write-Host ""
Write-Host "Build running at:"
Write-Host "https://github.com/$user/empycompress/actions"
