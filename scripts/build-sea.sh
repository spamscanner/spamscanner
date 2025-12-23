#!/bin/bash
# Build and test SEA (Single Executable Application) binary locally
# This script builds a standalone binary for the current platform

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_DIR"

# Detect platform
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"

case "$ARCH" in
  x86_64) ARCH="x64" ;;
  aarch64|arm64) ARCH="arm64" ;;
esac

case "$OS" in
  darwin) PLATFORM="darwin-$ARCH" ;;
  linux) PLATFORM="linux-$ARCH" ;;
  mingw*|msys*|cygwin*) PLATFORM="win-x64" ;;
  *) echo "Unsupported platform: $OS"; exit 1 ;;
esac

BINARY_NAME="spamscanner-$PLATFORM"
if [[ "$OS" == mingw* ]] || [[ "$OS" == msys* ]] || [[ "$OS" == cygwin* ]]; then
  BINARY_NAME="$BINARY_NAME.exe"
fi

echo "=== Building SpamScanner SEA Binary ==="
echo "Platform: $PLATFORM"
echo "Binary: $BINARY_NAME"
echo ""

# Step 1: Install dependencies if needed
if [ ! -d "node_modules" ]; then
  echo "Installing dependencies..."
  npm install
fi

# Step 2: Build standalone CLI bundle
echo "Building standalone CLI bundle..."
npm run build

# Verify standalone CLI works
echo "Verifying standalone CLI..."
node dist/standalone/cli.cjs --version
echo ""

# Step 3: Create SEA config
echo "Creating SEA config..."
cat > sea-config.json << 'EOF'
{
  "main": "dist/standalone/cli.cjs",
  "output": "sea-prep.blob",
  "disableExperimentalSEAWarning": true,
  "useSnapshot": false,
  "useCodeCache": true
}
EOF

# Step 4: Build SEA blob
echo "Building SEA blob..."
node --experimental-sea-config sea-config.json

# Step 5: Create SEA binary
echo "Creating SEA binary..."
cp "$(which node)" "$BINARY_NAME"

if [[ "$OS" == "darwin" ]]; then
  # macOS: Remove signature, inject blob, re-sign
  codesign --remove-signature "$BINARY_NAME" 2>/dev/null || true
  npx postject "$BINARY_NAME" NODE_SEA_BLOB sea-prep.blob \
    --sentinel-fuse NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2 \
    --macho-segment-name NODE_SEA
  codesign --sign - "$BINARY_NAME" 2>/dev/null || true
else
  # Linux: Just inject blob
  npx postject "$BINARY_NAME" NODE_SEA_BLOB sea-prep.blob \
    --sentinel-fuse NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2
fi

chmod +x "$BINARY_NAME"

# Step 6: Test SEA binary
echo ""
echo "=== Testing SEA Binary ==="
echo "Version:"
./"$BINARY_NAME" --version

echo ""
echo "Help (first 10 lines):"
./"$BINARY_NAME" --help | head -10

echo ""
echo "Scan test:"
echo "From: test@example.com
To: recipient@example.net
Subject: Test Email
Date: Thu, 1 Jan 2024 00:00:00 +0000
Message-ID: <test@example.com>

This is a test email." | ./"$BINARY_NAME" scan - --json --no-update-check | head -20 || echo "Scan completed"

# Cleanup
rm -f sea-config.json sea-prep.blob

echo ""
echo "=== Build Complete ==="
echo "Binary: $PROJECT_DIR/$BINARY_NAME"
echo "Size: $(du -h "$BINARY_NAME" | cut -f1)"
echo ""
echo "To install system-wide:"
echo "  sudo cp $BINARY_NAME /usr/local/bin/spamscanner"
