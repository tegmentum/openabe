#!/bin/bash
# Build OpenABE CLI tools for WebAssembly using WASI-SDK

set -e

# Configuration
WASI_SDK_PATH="${WASI_SDK_PATH:-/opt/wasi-sdk}"
ZROOT="$(pwd)"
WASM_BUILD_DIR="$ZROOT/build-wasm"
WASM_PREFIX="$WASM_BUILD_DIR/install"
CLI_WASM_DIR="$ZROOT/cli-wasm"

# WASI-SDK tools for wasm32-wasi (WASI Preview 1)
# Note: Using wasip1 for now since wasip2 doesn't support C++ exceptions
# which are heavily used in the CLI code
export CC="$WASI_SDK_PATH/bin/clang"
export CXX="$WASI_SDK_PATH/bin/clang++"

# WASM target and sysroot
WASM_SYSROOT="$WASI_SDK_PATH/share/wasi-sysroot"
WASM_TARGET="wasm32-wasi"

# Compiler flags
CFLAGS="--target=$WASM_TARGET --sysroot=$WASM_SYSROOT"
CFLAGS="$CFLAGS -O2 -g"
CFLAGS="$CFLAGS -DSSL_LIB_INIT"
CFLAGS="$CFLAGS -I$ZROOT/src/include"
CFLAGS="$CFLAGS -I$ZROOT/cli"
CFLAGS="$CFLAGS -I$WASM_PREFIX/include"
# Back to SJLJ exceptions (original approach)
CFLAGS="$CFLAGS -mllvm -wasm-enable-sjlj"

CXXFLAGS="$CFLAGS -std=c++11"
CXXFLAGS="$CXXFLAGS -Wall -Wsign-compare -fstrict-overflow"
CXXFLAGS="$CXXFLAGS -D__wasm__ -fexceptions"

# C++ runtime library path (needed for exceptions, RTTI)
WASI_CXX_RT_PATH="$WASI_SDK_PATH/share/wasi-sysroot/lib/wasm32-wasi"

# Linker flags
LDFLAGS="-L$WASM_PREFIX/lib -L$WASI_CXX_RT_PATH"

# Libraries (order matters: OpenABE, then RELIC, then dependencies)
# Note: Static libraries need to be specified as direct file paths for WASM
# Note: GMP is NOT included - RELIC uses its own bignum (causes bn_init symbol conflict with OpenSSL)
LIBS="$WASM_BUILD_DIR/libopenabe.a"
LIBS="$LIBS $WASM_PREFIX/lib/librelic_s.a"
LIBS="$LIBS $WASM_PREFIX/lib/libcrypto.a $WASM_PREFIX/lib/libssl.a"

# C++ runtime libraries (needed for exceptions, RTTI)
# Using direct paths to wasm32-wasi C++ runtime libraries
LIBS="$LIBS $WASI_CXX_RT_PATH/libc++.a $WASI_CXX_RT_PATH/libc++abi.a"

# WASI emulated libraries for missing POSIX functions
LIBS="$LIBS -lwasi-emulated-getpid -lwasi-emulated-signal"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

info() { echo -e "${GREEN}[INFO]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

# Create output directory
mkdir -p "$CLI_WASM_DIR"

# Compile common.cpp
compile_common() {
    info "Compiling common.cpp..."

    cd "$ZROOT/cli"
    $CXX $CXXFLAGS -c common.cpp -o "$CLI_WASM_DIR/common.o" || {
        error "Failed to compile common.cpp"
    }
}

# Build CLI tool
build_cli_tool() {
    local name="$1"
    local source="$2"

    info "Building $name from $source..."

    cd "$ZROOT/cli"
    $CXX $CXXFLAGS $LDFLAGS \
        -o "$CLI_WASM_DIR/${name}.wasm" \
        "$CLI_WASM_DIR/common.o" \
        "$source" \
        $LIBS || {
        warn "Failed to build $name"
        return 1
    }

    info "Successfully built $name ($(du -h $CLI_WASM_DIR/${name}.wasm | cut -f1))"
}

# Main execution
main() {
    info "Building OpenABE CLI tools for WebAssembly (wasm32-wasip2)..."

    # Verify dependencies exist
    if [ ! -f "$WASM_BUILD_DIR/libopenabe.a" ]; then
        error "libopenabe.a not found. Run ./build-openabe-wasm.sh first"
    fi

    if [ ! -f "$WASM_PREFIX/lib/librelic_s.a" ]; then
        error "librelic_s.a not found. Run ./build-deps-wasm.sh first"
    fi

    # Compile common object file
    compile_common

    # Build all CLI tools
    build_cli_tool "oabe_setup" "setup.cpp"
    build_cli_tool "oabe_keygen" "keygen.cpp"
    build_cli_tool "oabe_enc" "encrypt.cpp"
    build_cli_tool "oabe_dec" "decrypt.cpp"

    info "CLI tools build complete!"
    info "Output directory: $CLI_WASM_DIR"
    echo ""
    info "Built WASM modules:"
    ls -lh "$CLI_WASM_DIR"/*.wasm 2>/dev/null || warn "No .wasm files generated"
}

main "$@"
