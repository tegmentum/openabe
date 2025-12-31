#!/bin/bash
# Install MCL headers and libraries for WASM builds
# This ensures MCL dependencies are in the expected location for WASM compilation

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WASM_INSTALL_DIR="$SCRIPT_DIR/build-wasm/install"
WASM_MCL_DIR="$SCRIPT_DIR/deps/root-wasm"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info() { echo -e "${GREEN}[INFO]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }

info "Installing WASM MCL dependencies..."

# Check if WASM MCL headers and library exist
if [ ! -d "$WASM_MCL_DIR/include" ]; then
    warn "WASM MCL headers not found at $WASM_MCL_DIR/include"
    warn "Please build WASM dependencies first with: ./build-deps-wasm.sh"
    exit 1
fi

if [ ! -f "$WASM_MCL_DIR/lib/libmcl.a" ]; then
    warn "WASM MCL library not found at $WASM_MCL_DIR/lib/libmcl.a"
    warn "Please build WASM dependencies first with: ./build-deps-wasm.sh"
    exit 1
fi

# Create WASM install directories
mkdir -p "$WASM_INSTALL_DIR/include"
mkdir -p "$WASM_INSTALL_DIR/lib"

# Copy headers from WASM build (these are configured for WASM)
info "Copying MCL WASM headers from $WASM_MCL_DIR/include"
cp -r "$WASM_MCL_DIR/include"/* "$WASM_INSTALL_DIR/include/"

# Copy MCL WASM libraries from deps/root-wasm
info "Copying MCL WASM libraries from $WASM_MCL_DIR/lib"
cp -r "$WASM_MCL_DIR/lib"/* "$WASM_INSTALL_DIR/lib/"

info "WASM MCL dependencies installed successfully"
info "Headers: $WASM_INSTALL_DIR/include"
ls "$WASM_INSTALL_DIR/include"
echo ""
info "Libraries: $WASM_INSTALL_DIR/lib"
ls -lh "$WASM_INSTALL_DIR/lib"
