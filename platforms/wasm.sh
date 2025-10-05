#!/bin/bash
#
# Build script for WebAssembly/WASI target
#
# This script provides a convenient wrapper for building OpenABE for WebAssembly
# using the WASI-SDK toolchain.
#
# Requirements:
#   - WASI-SDK (https://github.com/WebAssembly/wasi-sdk)
#   - wasmtime runtime for testing (optional)
#
# Usage:
#   ./platforms/wasm.sh [deps|lib|cli|all|clean]
#

set -e

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

info() { echo -e "${GREEN}[INFO]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

# Check for WASI-SDK
check_wasi_sdk() {
    if [ -z "$WASI_SDK_PATH" ]; then
        if [ -d "/opt/wasi-sdk" ]; then
            export WASI_SDK_PATH="/opt/wasi-sdk"
            info "Using WASI-SDK at $WASI_SDK_PATH"
        else
            error "WASI-SDK not found. Please install WASI-SDK and set WASI_SDK_PATH"
        fi
    else
        info "Using WASI-SDK at $WASI_SDK_PATH"
    fi

    if [ ! -f "$WASI_SDK_PATH/bin/clang" ]; then
        error "WASI-SDK clang not found at $WASI_SDK_PATH/bin/clang"
    fi
}

# Build dependencies (GMP, OpenSSL, RELIC)
build_deps() {
    info "Building OpenABE dependencies for WebAssembly..."
    check_wasi_sdk
    ./build-deps-wasm.sh
}

# Build OpenABE library
build_lib() {
    info "Building OpenABE library for WebAssembly..."
    check_wasi_sdk
    ./build-openabe-wasm.sh
}

# Build CLI tools
build_cli() {
    info "Building OpenABE CLI tools for WebAssembly..."
    check_wasi_sdk
    ./build-cli-wasm.sh
}

# Clean WASM build artifacts
clean_wasm() {
    info "Cleaning WebAssembly build artifacts..."
    rm -rf build-wasm
    rm -rf cli-wasm/*.wasm cli-wasm/*.o
    info "Clean complete"
}

# Main command dispatcher
case "${1:-all}" in
    deps)
        build_deps
        ;;
    lib)
        build_lib
        ;;
    cli)
        build_cli
        ;;
    all)
        build_deps
        build_lib
        build_cli
        info "WebAssembly build complete!"
        info "WASM modules:"
        ls -lh cli-wasm/*.wasm 2>/dev/null || warn "No .wasm files generated"
        ;;
    clean)
        clean_wasm
        ;;
    *)
        echo "Usage: $0 [deps|lib|cli|all|clean]"
        echo ""
        echo "Commands:"
        echo "  deps  - Build dependencies (GMP, OpenSSL, RELIC) for WASM"
        echo "  lib   - Build OpenABE library for WASM"
        echo "  cli   - Build CLI tools for WASM"
        echo "  all   - Build everything (default)"
        echo "  clean - Clean WASM build artifacts"
        exit 1
        ;;
esac
