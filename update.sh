#!/bin/bash
set -e
cd "$(dirname "$0")"
git add .
git commit -m "empycompress v3.5.0 — fix type annotations, GUI version display, icon paths"
git tag v3.5.0
git push origin main
git push origin v3.5.0
echo ""
echo "Build running at:"
echo "https://github.com/$(gh api user --jq .login)/empycompress/actions"
