#!/bin/bash
# Master build script for OpenABE WebAssembly
# This script builds everything needed for WASM in the correct order

set -e

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

info() { echo -e "${GREEN}[INFO]${NC} $1"; }
step() { echo -e "${BLUE}[STEP]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }

ZROOT="$(pwd)"

info "Building OpenABE for WebAssembly"
info "================================="
echo ""

# Step 1: Build dependencies (includes WASI SDK download)
step "1/3 Building dependencies (GMP, OpenSSL, RELIC)..."
./build-deps-wasm.sh
echo ""

# Step 2: Build OpenABE library
step "2/3 Building OpenABE library..."
./build-openabe-wasm.sh
echo ""

# Step 3: Build CLI tools
step "3/3 Building CLI tools..."
./build-cli-wasm.sh
echo ""

info "Build complete!"
info "WASM modules are in: $ZROOT/cli-wasm/"
echo ""

# List built modules
if [ -d "$ZROOT/cli-wasm" ]; then
    info "Built WASM modules:"
    ls -lh "$ZROOT/cli-wasm/"*.wasm 2>/dev/null || true
fi

echo ""
info "To test the WASM modules, use wasmtime:"
echo "  wasmtime cli-wasm/oabe_setup.wasm -s CP -p test"
