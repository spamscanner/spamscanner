#!/bin/bash
#
# SpamScanner CLI Installer
# https://github.com/spamscanner/spamscanner
#
# Usage:
#   curl -fsSL https://github.com/spamscanner/spamscanner/releases/latest/download/install.sh | bash
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo ""
echo -e "${BLUE}╔═══════════════════════════════════════╗${NC}"
echo -e "${BLUE}║     ${GREEN}SpamScanner CLI Installer${BLUE}         ║${NC}"
echo -e "${BLUE}╚═══════════════════════════════════════╝${NC}"
echo ""

# Detect OS and architecture
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"

case "$OS" in
    linux*)  PLATFORM="linux" ;;
    darwin*) PLATFORM="darwin" ;;
    *)
        echo -e "${RED}Error: Unsupported operating system: $OS${NC}"
        echo "Please install via npm instead: npm install -g spamscanner"
        exit 1
        ;;
esac

case "$ARCH" in
    x86_64|amd64) ARCH="x64" ;;
    aarch64|arm64) ARCH="arm64" ;;
    *)
        echo -e "${RED}Error: Unsupported architecture: $ARCH${NC}"
        echo "Please install via npm instead: npm install -g spamscanner"
        exit 1
        ;;
esac

ARTIFACT="spamscanner-${PLATFORM}-${ARCH}"
BIN_DIR="${SPAMSCANNER_BIN_DIR:-/usr/local/bin}"

echo -e "Platform: ${GREEN}${PLATFORM}-${ARCH}${NC}"
echo ""

# Get latest release URL
RELEASE_URL="https://github.com/spamscanner/spamscanner/releases/latest/download/${ARTIFACT}"

echo -e "${YELLOW}Downloading ${ARTIFACT}...${NC}"

# Create temp directory
TMP_DIR=$(mktemp -d)
trap "rm -rf $TMP_DIR" EXIT

# Download with progress bar
if command -v curl &> /dev/null; then
    curl -fL --progress-bar "$RELEASE_URL" -o "$TMP_DIR/spamscanner"
elif command -v wget &> /dev/null; then
    wget --show-progress -q "$RELEASE_URL" -O "$TMP_DIR/spamscanner"
else
    echo -e "${RED}Error: curl or wget is required${NC}"
    exit 1
fi

# Make executable
chmod +x "$TMP_DIR/spamscanner"

# Install (may need sudo)
echo ""
echo -e "${YELLOW}Installing to ${BIN_DIR}...${NC}"

if [ -w "$BIN_DIR" ]; then
    mv "$TMP_DIR/spamscanner" "$BIN_DIR/spamscanner"
else
    echo "Requesting sudo access..."
    sudo mv "$TMP_DIR/spamscanner" "$BIN_DIR/spamscanner"
fi

# Verify installation
echo ""
if command -v spamscanner &> /dev/null; then
    VERSION=$(spamscanner --version 2>/dev/null || echo "installed")
    echo -e "${GREEN}╔═══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║  ✓ Successfully installed SpamScanner CLI ${VERSION}${NC}"
    echo -e "${GREEN}╚═══════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "You can now run:"
    echo -e "  ${BLUE}spamscanner --help${NC}          Show help"
    echo -e "  ${BLUE}spamscanner scan email.eml${NC}  Scan an email file"
    echo -e "  ${BLUE}spamscanner scan -${NC}          Scan from stdin"
    echo ""
else
    echo -e "${YELLOW}Installation complete.${NC}"
    echo ""
    if [[ ":$PATH:" != *":$BIN_DIR:"* ]]; then
        echo -e "Add ${BIN_DIR} to your PATH:"
        echo -e "  export PATH=\"${BIN_DIR}:\$PATH\""
        echo ""
    fi
    echo "Then run: spamscanner --help"
fi
