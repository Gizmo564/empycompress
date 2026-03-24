#!/bin/bash
set -e
cd "$(dirname "$0")"

# Read current version from empy.py
CURRENT=$(grep 'PROG_VERSION = ' empy.py | sed 's/PROG_VERSION = "//;s/"//')

# Split into major.minor.patch and increment patch
MAJOR=$(echo "$CURRENT" | cut -d. -f1)
MINOR=$(echo "$CURRENT" | cut -d. -f2)
PATCH=$(echo "$CURRENT" | cut -d. -f3)
NEW_PATCH=$((PATCH + 1))
NEW_VERSION="$MAJOR.$MINOR.$NEW_PATCH"

echo "Bumping version: $CURRENT → $NEW_VERSION"

# Write new version back into empy.py
sed -i.bak "s/PROG_VERSION = \"$CURRENT\"/PROG_VERSION = \"$NEW_VERSION\"/" empy.py
rm -f empy.py.bak

git add .
git commit -m "empycompress v$NEW_VERSION"
git tag "v$NEW_VERSION"
git push origin main
git push origin "v$NEW_VERSION"

echo ""
echo "Build running at:"
echo "https://github.com/$(gh api user --jq .login)/empycompress/actions"
