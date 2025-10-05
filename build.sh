#!/bin/bash
# OpenABE Universal Build Script
# Build for native platforms or WebAssembly

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m'

error() { echo -e "${RED}[ERROR]${NC} $1" >&2; }
info() { echo -e "${GREEN}[INFO]${NC} $1"; }
step() { echo -e "${BLUE}[STEP]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }

show_usage() {
    cat << EOF
${BOLD}OpenABE Build Script${NC}

${BOLD}USAGE:${NC}
    $0 [OPTIONS] <target>

${BOLD}TARGETS:${NC}
    ${BOLD}native${NC}          Build for native platform (current OS/architecture)
    ${BOLD}wasm${NC}            Build for WebAssembly (WASI)
    ${BOLD}all${NC}             Build for all targets (native + wasm)
    ${BOLD}clean${NC}           Clean build artifacts
    ${BOLD}test${NC}            Run tests (native only)

${BOLD}OPTIONS:${NC}
    -h, --help       Show this help message
    -v, --verbose    Enable verbose output
    -j, --jobs N     Number of parallel jobs (default: auto-detect)
    --deps-only      Build dependencies only
    --lib-only       Build library only (skip CLI tools)
    --no-examples    Skip building examples (native only)

${BOLD}EXAMPLES:${NC}
    # Build for current platform
    $0 native

    # Build for WebAssembly
    $0 wasm

    # Build for all platforms
    $0 all

    # Build with 8 parallel jobs
    $0 -j 8 native

    # Build only dependencies
    $0 --deps-only native

    # Clean and rebuild
    $0 clean && $0 native

${BOLD}ENVIRONMENT VARIABLES:${NC}
    ZROOT            OpenABE root directory (auto-detected)
    WASI_SDK_PATH    Path to WASI SDK (default: \$HOME/wasi-sdk)
    WASI_SDK_VERSION WASI SDK version to download (default: 24)
    CC, CXX          C/C++ compilers for native build

${BOLD}PLATFORM SUPPORT:${NC}
    Native:  macOS (x86_64, ARM64), Linux (x86_64, ARM64)
    WASM:    Universal (runs on any platform with wasmtime)

EOF
}

# Parse command line arguments
VERBOSE=false
JOBS=""
DEPS_ONLY=false
LIB_ONLY=false
NO_EXAMPLES=false
TARGET=""

while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            show_usage
            exit 0
            ;;
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        -j|--jobs)
            JOBS="$2"
            shift 2
            ;;
        --deps-only)
            DEPS_ONLY=true
            shift
            ;;
        --lib-only)
            LIB_ONLY=true
            shift
            ;;
        --no-examples)
            NO_EXAMPLES=true
            shift
            ;;
        native|wasm|all|clean|test)
            TARGET="$1"
            shift
            ;;
        *)
            error "Unknown option: $1"
            echo ""
            show_usage
            exit 1
            ;;
    esac
done

# Validate target
if [ -z "$TARGET" ]; then
    error "No target specified"
    echo ""
    show_usage
    exit 1
fi

# Detect number of CPU cores
if [ -z "$JOBS" ]; then
    if command -v nproc &> /dev/null; then
        JOBS=$(nproc)
    elif command -v sysctl &> /dev/null; then
        JOBS=$(sysctl -n hw.ncpu 2>/dev/null || echo 4)
    else
        JOBS=4
    fi
fi

# Set ZROOT
export ZROOT="${ZROOT:-$(pwd)}"

# Platform detection
detect_platform() {
    local os=$(uname -s | tr '[:upper:]' '[:lower:]')
    local arch=$(uname -m)

    case "$os" in
        darwin) OS_TYPE="macos" ;;
        linux) OS_TYPE="linux" ;;
        *) error "Unsupported OS: $os"; exit 1 ;;
    esac

    case "$arch" in
        x86_64|amd64) ARCH_TYPE="x86_64" ;;
        arm64|aarch64) ARCH_TYPE="arm64" ;;
        *) error "Unsupported architecture: $arch"; exit 1 ;;
    esac

    info "Platform: $OS_TYPE ($ARCH_TYPE)"
}

# Build for native platform
build_native() {
    info "Building OpenABE for native platform..."
    echo ""

    detect_platform

    # Check environment
    if [ ! -f "$ZROOT/env" ]; then
        error "Environment file not found. Please ensure you're in the OpenABE directory."
        exit 1
    fi

    # Source environment
    step "Setting up environment..."
    source "$ZROOT/env"

    # Build dependencies
    if [ "$DEPS_ONLY" = true ] || [ "$LIB_ONLY" = false ]; then
        step "Building dependencies..."
        make -j"$JOBS" deps
        echo ""
    fi

    if [ "$DEPS_ONLY" = false ]; then
        # Build library
        step "Building OpenABE library..."
        make -j"$JOBS" src
        echo ""

        # Build CLI tools
        if [ "$LIB_ONLY" = false ]; then
            step "Building CLI tools..."
            make -j"$JOBS" cli
            echo ""
        fi

        # Build examples
        if [ "$NO_EXAMPLES" = false ] && [ "$LIB_ONLY" = false ]; then
            step "Building examples..."
            make -j"$JOBS" examples || warn "Examples build failed (non-critical)"
            echo ""
        fi
    fi

    info "Native build complete!"
    info "Binaries: $ZROOT/cli/"
    info "Library: $ZROOT/root/lib/"
}

# Build for WebAssembly
build_wasm() {
    info "Building OpenABE for WebAssembly..."
    echo ""

    # Build dependencies (includes WASI SDK download)
    if [ "$DEPS_ONLY" = true ] || [ "$LIB_ONLY" = false ]; then
        step "Building WASM dependencies..."
        ./build-deps-wasm.sh
        echo ""
    fi

    if [ "$DEPS_ONLY" = false ]; then
        # Build library
        step "Building OpenABE library for WASM..."
        ./build-openabe-wasm.sh
        echo ""

        # Build CLI tools
        if [ "$LIB_ONLY" = false ]; then
            step "Building WASM CLI tools..."
            ./build-cli-wasm.sh
            echo ""
        fi
    fi

    info "WASM build complete!"
    info "Binaries: $ZROOT/cli-wasm/"
    info "Library: $ZROOT/build-wasm/libopenabe.a"
}

# Clean build artifacts
clean() {
    info "Cleaning build artifacts..."

    # Clean native build
    if [ -f "$ZROOT/env" ]; then
        source "$ZROOT/env" 2>/dev/null || true
        make clean 2>/dev/null || true
    fi

    # Clean WASM build
    rm -rf build-wasm cli-wasm

    # Clean dependencies
    rm -rf deps/gmp/gmp-*/ deps/gmp/tmp*
    rm -rf deps/openssl/openssl-*/ deps/openssl/tmp*
    rm -rf deps/relic/relic-*/ deps/relic/tmp*

    info "Clean complete!"
}

# Run tests
run_tests() {
    info "Running OpenABE tests..."
    echo ""

    if [ ! -f "$ZROOT/env" ]; then
        error "Environment file not found. Please build native first."
        exit 1
    fi

    source "$ZROOT/env"
    make test

    info "Tests complete!"
}

# Build all targets
build_all() {
    info "Building OpenABE for all platforms..."
    echo ""

    step "Building for native platform..."
    build_native
    echo ""

    step "Building for WebAssembly..."
    build_wasm
    echo ""

    info "All builds complete!"
    echo ""
    info "Native binaries: $ZROOT/cli/"
    info "WASM binaries: $ZROOT/cli-wasm/"
}

# Main execution
main() {
    case "$TARGET" in
        native)
            build_native
            ;;
        wasm)
            build_wasm
            ;;
        all)
            build_all
            ;;
        clean)
            clean
            ;;
        test)
            run_tests
            ;;
        *)
            error "Invalid target: $TARGET"
            show_usage
            exit 1
            ;;
    esac

    echo ""
    info "Build script complete!"
}

main
