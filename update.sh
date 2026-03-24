#!/bin/bash
set -e
cd "$(dirname "$0")"

# Use Python to read and bump the version — more reliable than sed across platforms
NEW_VERSION=$(python3 - <<'PYEOF'
import re, sys
text = open("empy.py").read()
m = re.search(r'PROG_VERSION = "(\d+)\.(\d+)\.(\d+)"', text)
if not m:
    sys.exit("ERROR: could not find PROG_VERSION in empy.py")
major, minor, patch = m.group(1), m.group(2), str(int(m.group(3)) + 1)
new_ver = f"{major}.{minor}.{patch}"
new_text = re.sub(r'PROG_VERSION = "\d+\.\d+\.\d+"', f'PROG_VERSION = "{new_ver}"', text)
open("empy.py", "w").write(new_text)
print(new_ver)
PYEOF
)

echo "Version bumped to $NEW_VERSION"

git add .

# Commit only if there is something staged
if git diff --cached --quiet; then
    echo "Nothing new to commit — tagging and pushing existing state."
else
    git commit -m "empycompress v$NEW_VERSION"
fi

git tag "v$NEW_VERSION"
git push origin main
git push origin "v$NEW_VERSION"

echo ""
echo "Build running at:"
echo "https://github.com/$(gh api user --jq .login)/empycompress/actions"
