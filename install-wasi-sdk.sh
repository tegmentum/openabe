#!/bin/bash
#
# Install WASI-SDK for OpenABE WASM builds
#
# This script downloads and installs WASI-SDK to /opt/wasi-sdk
# Supports macOS (Intel and Apple Silicon) and Linux
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

info() { echo -e "${GREEN}[INFO]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

# Configuration
WASI_SDK_VERSION="${WASI_SDK_VERSION:-27}"
WASI_SDK_VERSION_FULL="${WASI_SDK_VERSION}.0"
INSTALL_DIR="${WASI_SDK_INSTALL_DIR:-$HOME/.local/wasi-sdk}"

# Detect platform
detect_platform() {
    local os="$(uname -s)"
    local arch="$(uname -m)"

    case "$os" in
        Darwin)
            if [ "$arch" = "arm64" ]; then
                PLATFORM="arm64-macos"
                info "Detected: macOS Apple Silicon (ARM64)"
            elif [ "$arch" = "x86_64" ]; then
                PLATFORM="x86_64-macos"
                info "Detected: macOS Intel (x86_64)"
            else
                error "Unsupported macOS architecture: $arch"
            fi
            ;;
        Linux)
            if [ "$arch" = "x86_64" ]; then
                PLATFORM="x86_64-linux"
                info "Detected: Linux x86_64"
            elif [ "$arch" = "aarch64" ]; then
                PLATFORM="arm64-linux"
                info "Detected: Linux ARM64"
            else
                error "Unsupported Linux architecture: $arch"
            fi
            ;;
        *)
            error "Unsupported operating system: $os"
            ;;
    esac
}

# Check if already installed
check_existing() {
    if [ -d "$INSTALL_DIR" ]; then
        if [ -f "$INSTALL_DIR/bin/clang" ]; then
            warn "WASI-SDK already installed at $INSTALL_DIR"
            read -p "Reinstall? (y/N) " -n 1 -r
            echo
            if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                info "Using existing installation"
                exit 0
            fi
            info "Removing existing installation..."
            sudo rm -rf "$INSTALL_DIR"
        fi
    fi
}

# Download WASI-SDK
download_wasi_sdk() {
    local filename="wasi-sdk-${WASI_SDK_VERSION_FULL}-${PLATFORM}.tar.gz"
    local url="https://github.com/WebAssembly/wasi-sdk/releases/download/wasi-sdk-${WASI_SDK_VERSION}/${filename}"
    local temp_dir="/tmp/wasi-sdk-install-$$"

    mkdir -p "$temp_dir"
    cd "$temp_dir"

    info "Downloading WASI-SDK ${WASI_SDK_VERSION} for ${PLATFORM}..."
    info "URL: $url"

    if command -v curl &> /dev/null; then
        curl -L -o "$filename" "$url" || error "Failed to download WASI-SDK"
    elif command -v wget &> /dev/null; then
        wget -O "$filename" "$url" || error "Failed to download WASI-SDK"
    else
        error "Neither curl nor wget found. Please install one of them."
    fi

    local file_size=$(ls -lh "$filename" | awk '{print $5}')
    info "Downloaded $filename ($file_size)"

    # Extract
    info "Extracting WASI-SDK..."
    tar xzf "$filename" || error "Failed to extract WASI-SDK"

    local extracted_dir="wasi-sdk-${WASI_SDK_VERSION_FULL}"
    if [ ! -d "$extracted_dir" ]; then
        # Try with platform suffix
        extracted_dir="wasi-sdk-${WASI_SDK_VERSION_FULL}-${PLATFORM}"
        if [ ! -d "$extracted_dir" ]; then
            # List what we got
            ls -la | head -10
            error "Extracted directory not found. Expected: wasi-sdk-${WASI_SDK_VERSION_FULL}"
        fi
    fi

    # Install
    info "Installing to $INSTALL_DIR..."

    # Create parent directory if needed
    mkdir -p "$(dirname "$INSTALL_DIR")"

    # Move to installation directory
    mv "$extracted_dir" "$INSTALL_DIR" || error "Failed to install WASI-SDK"

    # Cleanup
    cd /
    rm -rf "$temp_dir"

    info "✓ WASI-SDK installed successfully"
}

# Verify installation
verify_installation() {
    info "Verifying installation..."

    if [ ! -f "$INSTALL_DIR/bin/clang" ]; then
        error "Verification failed: clang not found at $INSTALL_DIR/bin/clang"
    fi

    if [ ! -f "$INSTALL_DIR/bin/wasm-ld" ]; then
        error "Verification failed: wasm-ld not found"
    fi

    # Test compilation
    local version=$("$INSTALL_DIR/bin/clang" --version | head -1)
    info "✓ WASI-SDK clang: $version"

    local sysroot="$INSTALL_DIR/share/wasi-sysroot"
    if [ -d "$sysroot" ]; then
        info "✓ WASI sysroot: $sysroot"
    else
        warn "WASI sysroot not found at expected location"
    fi
}

# Print usage instructions
print_instructions() {
    echo ""
    echo -e "${BLUE}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║           WASI-SDK Installation Complete!                 ║${NC}"
    echo -e "${BLUE}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${GREEN}Installation directory:${NC} $INSTALL_DIR"
    echo ""
    echo -e "${GREEN}To use WASI-SDK:${NC}"
    echo ""
    echo "  export WASI_SDK_PATH=\"$INSTALL_DIR\""
    echo "  export CC=\"\$WASI_SDK_PATH/bin/clang\""
    echo "  export CXX=\"\$WASI_SDK_PATH/bin/clang++\""
    echo ""
    echo -e "${GREEN}Next steps:${NC}"
    echo ""
    echo "  1. Build MCL with LLVM IR:"
    echo "     WASI_SDK_PATH=\"$INSTALL_DIR\" ./build-mcl-llvm-wasm.sh"
    echo ""
    echo "  2. Build OpenABE library:"
    echo "     ./build-openabe-wasm.sh"
    echo ""
    echo "  3. Build CLI tools:"
    echo "     ./build-cli-wasm.sh"
    echo ""
}

# Main execution
main() {
    echo ""
    echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}           WASI-SDK Installer for OpenABE                  ${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
    echo ""

    detect_platform
    check_existing
    download_wasi_sdk
    verify_installation
    print_instructions

    echo -e "${GREEN}✓ Installation complete!${NC}"
    echo ""
}

# Handle Ctrl+C gracefully
trap 'echo ""; error "Installation cancelled by user"' INT TERM

# Run main function
main "$@"
