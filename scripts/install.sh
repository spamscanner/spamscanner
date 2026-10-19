#!/bin/bash
#
# SpamScanner CLI Installer
# https://github.com/spamscanner/spamscanner
#
# Usage:
#   curl -fsSL https://github.com/spamscanner/spamscanner/releases/latest/download/install.sh | bash
#
# Environment:
#   SPAMSCANNER_BIN_DIR       where to install (default /usr/local/bin)
#   SPAMSCANNER_RELEASES_URL  where to download from, e.g.
#                             https://github.com/spamscanner/spamscanner/releases/download/vX.Y.Z
#                             for a specific release (default: the latest release;
#                             v7.0.3 and earlier have no SHA256SUMS to check against)
#
# The binary is checked against SHA256SUMS from the same release before it is
# installed. Everything runs from main(), called on the last line, so a
# download cut short runs nothing.

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

RELEASES_URL="${SPAMSCANNER_RELEASES_URL:-https://github.com/spamscanner/spamscanner/releases/latest/download}"

fail() {
    echo -e "${RED}Error: $1${NC}" >&2
    if [ -n "$2" ]; then
        echo "$2" >&2
    fi
    exit 1
}

# download <url> <file>
download() {
    if command -v curl &> /dev/null; then
        curl -fL --progress-bar "$1" -o "$2"
    elif command -v wget &> /dev/null; then
        wget --show-progress -q "$1" -O "$2"
    else
        fail "curl or wget is required"
    fi
}

main() {
    echo ""
    echo -e "${BLUE}╔═══════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║     ${GREEN}SpamScanner CLI Installer${BLUE}         ║${NC}"
    echo -e "${BLUE}╚═══════════════════════════════════════╝${NC}"
    echo ""

    # Detect OS and architecture
    local os arch platform
    os="$(uname -s | tr '[:upper:]' '[:lower:]')"
    arch="$(uname -m)"

    case "$os" in
        linux*)  platform="linux" ;;
        darwin*) platform="darwin" ;;
        *)
            fail "Unsupported operating system: $os" "Please install via npm instead: npm install -g spamscanner"
            ;;
    esac

    case "$arch" in
        x86_64|amd64) arch="x64" ;;
        aarch64|arm64) arch="arm64" ;;
        *)
            fail "Unsupported architecture: $arch" "Please install via npm instead: npm install -g spamscanner"
            ;;
    esac

    # The Linux binaries are built against glibc and do not run on musl
    # (Alpine and similar).
    if [ "$platform" = "linux" ]; then
        if ls /lib/ld-musl-* &> /dev/null || { command -v ldd &> /dev/null && ldd --version 2>&1 | grep -qi musl; }; then
            fail "This system uses musl libc; the Linux binaries need glibc." "Please install via npm instead: npm install -g spamscanner"
        fi
    fi

    local artifact="spamscanner-${platform}-${arch}"
    local bin_dir="${SPAMSCANNER_BIN_DIR:-/usr/local/bin}"

    echo -e "Platform: ${GREEN}${platform}-${arch}${NC}"
    echo ""

    # The checksum tool, chosen before anything is downloaded.
    local sha256
    if command -v sha256sum &> /dev/null; then
        sha256="sha256sum"
    elif command -v shasum &> /dev/null; then
        sha256="shasum -a 256"
    else
        fail "sha256sum or shasum is required to verify the download"
    fi

    TMP_DIR="$(mktemp -d)"
    trap 'rm -rf "$TMP_DIR"' EXIT

    echo -e "${YELLOW}Downloading ${artifact}...${NC}"
    if ! download "${RELEASES_URL}/${artifact}" "$TMP_DIR/$artifact"; then
        fail "Could not download ${artifact} from ${RELEASES_URL}" "If a release was just published, its binaries may still be building: try again in a few minutes, or install via npm: npm install -g spamscanner"
    fi

    echo -e "${YELLOW}Verifying checksum...${NC}"
    if ! download "${RELEASES_URL}/SHA256SUMS" "$TMP_DIR/SHA256SUMS"; then
        fail "Could not download SHA256SUMS from ${RELEASES_URL}, so ${artifact} cannot be verified" "Try again in a few minutes, or install via npm: npm install -g spamscanner"
    fi

    awk -v name="$artifact" '$2 == name || $2 == "*" name' "$TMP_DIR/SHA256SUMS" > "$TMP_DIR/expected"
    if [ ! -s "$TMP_DIR/expected" ]; then
        fail "SHA256SUMS has no checksum for ${artifact}"
    fi

    # $sha256 is unquoted on purpose: "shasum -a 256" is a command and its options.
    if ! (cd "$TMP_DIR" && $sha256 -c expected); then
        fail "Checksum mismatch for ${artifact}: the download is corrupt or was tampered with" "Nothing was installed."
    fi

    # Install (may need sudo)
    echo ""
    echo -e "${YELLOW}Installing to ${bin_dir}...${NC}"

    # The directory is created when it does not exist yet (with sudo when
    # its parent is not writable either). "install" copies the binary as a
    # new file, executable by all and, under sudo, owned by root: one moved
    # with "mv" would keep the downloading user as its owner, who could then
    # change the program root and others run.
    if mkdir -p "$bin_dir" 2> /dev/null && [ -w "$bin_dir" ]; then
        install -m 0755 "$TMP_DIR/$artifact" "$bin_dir/spamscanner"
    else
        echo "Requesting sudo access..."
        sudo mkdir -p "$bin_dir"
        sudo install -m 0755 "$TMP_DIR/$artifact" "$bin_dir/spamscanner"
    fi

    # Verify installation
    echo ""
    local version
    if ! version="$("$bin_dir/spamscanner" --version 2>&1)"; then
        echo "$version" >&2
        fail "${bin_dir}/spamscanner was installed but does not run" "Please report this at https://github.com/spamscanner/spamscanner/issues, or install via npm instead: npm install -g spamscanner"
    fi

    echo -e "${GREEN}╔═══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║  ✓ Successfully installed ${version}${NC}"
    echo -e "${GREEN}╚═══════════════════════════════════════════════════════════╝${NC}"
    echo ""

    if [[ ":$PATH:" != *":$bin_dir:"* ]]; then
        echo -e "Add ${bin_dir} to your PATH:"
        echo -e "  export PATH=\"${bin_dir}:\$PATH\""
        echo ""
    fi

    echo -e "You can now run:"
    echo -e "  ${BLUE}spamscanner --help${NC}          Show help"
    echo -e "  ${BLUE}spamscanner scan email.eml${NC}  Scan an email file"
    echo -e "  ${BLUE}spamscanner scan -${NC}          Scan from stdin"
    echo ""
}

main "$@"
