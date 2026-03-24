Set-Location $PSScriptRoot

# Read current version from empy.py
$current = (Select-String 'PROG_VERSION = "(.+)"' empy.py).Matches[0].Groups[1].Value

# Split into major.minor.patch and increment patch
$parts     = $current.Split('.')
$major     = $parts[0]
$minor     = $parts[1]
$newPatch  = [int]$parts[2] + 1
$newVersion = "$major.$minor.$newPatch"

Write-Host "Bumping version: $current -> $newVersion"

# Write new version back into empy.py
(Get-Content empy.py) -replace "PROG_VERSION = `"$current`"", "PROG_VERSION = `"$newVersion`"" |
    Set-Content empy.py

git add .
git commit -m "empycompress v$newVersion"
git tag "v$newVersion"
git push origin main
git push origin "v$newVersion"

$user = gh api user --jq .login
Write-Host ""
Write-Host "Build running at:"
Write-Host "https://github.com/$user/empycompress/actions"
