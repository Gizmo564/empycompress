#!/bin/bash
# empy — macOS install helper
# Run this once after downloading: bash install.sh
set -e
BINARY="empy-macos-arm64"

if [ ! -f "$BINARY" ]; then
  echo "Error: '$BINARY' not found in the current directory."
  echo "Make sure you run this script from the same folder as the binary."
  exit 1
fi

echo "Setting up empy..."

chmod +x "$BINARY"
echo "  ✓  Marked as executable"

if xattr -d com.apple.quarantine "$BINARY" 2>/dev/null; then
  echo "  ✓  Quarantine removed (Gatekeeper will no longer block it)"
else
  echo "  ✓  No quarantine flag present"
fi

echo ""
echo "Done. You can now run empy:"
echo "  ./$BINARY              (launch GUI in browser)"
echo "  ./$BINARY --help       (CLI help)"
echo ""
echo "To install system-wide (optional):"
echo "  sudo mv $BINARY /usr/local/bin/empy"
echo "  empy"
