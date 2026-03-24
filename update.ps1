Set-Location $PSScriptRoot

# Use Python to read and bump the version
$newVersion = python3 -c @"
import re, sys
text = open('empy.py').read()
m = re.search(r'PROG_VERSION = \"(\d+)\.(\d+)\.(\d+)\"', text)
if not m:
    sys.exit('ERROR: could not find PROG_VERSION in empy.py')
major, minor, patch = m.group(1), m.group(2), str(int(m.group(3)) + 1)
new_ver = f'{major}.{minor}.{patch}'
new_text = re.sub(r'PROG_VERSION = \"\d+\.\d+\.\d+\"', f'PROG_VERSION = \"{new_ver}\"', text)
open('empy.py', 'w').write(new_text)
print(new_ver)
"@

Write-Host "Version bumped to $newVersion"

git add .

# Commit only if there is something staged
$staged = git diff --cached --quiet
if ($LASTEXITCODE -eq 0) {
    Write-Host "Nothing new to commit — tagging and pushing existing state."
} else {
    git commit -m "empycompress v$newVersion"
}

git tag "v$newVersion"
git push origin main
git push origin "v$newVersion"

$user = gh api user --jq .login
Write-Host ""
Write-Host "Build running at:"
Write-Host "https://github.com/$user/empycompress/actions"
