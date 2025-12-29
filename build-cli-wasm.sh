#!/bin/bash
# Build OpenABE CLI tools for WebAssembly using WASI-SDK

set -e

# Configuration
WASI_SDK_PATH="${WASI_SDK_PATH:-$HOME/wasi-sdk}"
ZROOT="$(pwd)"
WASM_BUILD_DIR="$ZROOT/build-wasm"
WASM_PREFIX="$WASM_BUILD_DIR/install"
CLI_WASM_DIR="$ZROOT/cli-wasm"

# Check if WASI SDK is installed
if [ ! -f "$WASI_SDK_PATH/bin/clang" ]; then
    echo "Error: WASI SDK not found at $WASI_SDK_PATH"
    echo "Please run ./build-deps-wasm.sh first to install WASI SDK and build dependencies"
    exit 1
fi

# WASI-SDK tools for wasm32-wasi (WASI Preview 1)
# Note: Using wasip1 for now since wasip2 doesn't support C++ exceptions
# which are heavily used in the CLI code
export CC="$WASI_SDK_PATH/bin/clang"
export CXX="$WASI_SDK_PATH/bin/clang++"

# WASM target and sysroot
WASM_SYSROOT="$WASI_SDK_PATH/share/wasi-sysroot"
WASM_TARGET="wasm32-wasi"

# Compiler flags
# Allow overriding optimization level via OPT_LEVEL environment variable
OPT_LEVEL="${OPT_LEVEL:--O1}"  # Default to -O1 if not set
CFLAGS="--target=$WASM_TARGET --sysroot=$WASM_SYSROOT"
CFLAGS="$CFLAGS $OPT_LEVEL -g"  # Use configurable optimization level
CFLAGS="$CFLAGS -DBP_WITH_MCL"
CFLAGS="$CFLAGS -DSSL_LIB_INIT"
CFLAGS="$CFLAGS -DEC_WITH_OPENSSL"
CFLAGS="$CFLAGS -DMCL_FP_BIT=384"
CFLAGS="$CFLAGS -DMCL_FR_BIT=256"
CFLAGS="$CFLAGS -I$ZROOT/src/include"
CFLAGS="$CFLAGS -I$ZROOT/cli"
CFLAGS="$CFLAGS -I$WASM_PREFIX/include"
CFLAGS="$CFLAGS -I$ZROOT/deps/tinycbor/src"
# Back to SJLJ exceptions (original approach)
CFLAGS="$CFLAGS -mllvm -wasm-enable-sjlj"

CXXFLAGS="$CFLAGS -std=c++11"
CXXFLAGS="$CXXFLAGS -Wall -Wsign-compare -fstrict-overflow"
CXXFLAGS="$CXXFLAGS -D__wasm__ -fexceptions"

# C++ runtime library path (needed for GMP C++ bindings)
WASI_CXX_RT_PATH="$WASI_SDK_PATH/share/wasi-sysroot/lib/wasm32-wasi"

# Linker flags
LDFLAGS="-L$WASM_PREFIX/lib -L$WASI_CXX_RT_PATH"

# Libraries (order matters: OpenABE, then MCL, then dependencies)
# Note: Static libraries need to be specified as direct file paths for WASM
LIBS="$WASM_BUILD_DIR/libopenabe.a"
LIBS="$LIBS $WASM_PREFIX/lib/libmcl.a"
# Add libmclecdsa.a if it exists (not needed for basic ABE operations)
if [ -f "$WASM_PREFIX/lib/libmclecdsa.a" ]; then
    LIBS="$LIBS $WASM_PREFIX/lib/libmclecdsa.a"
fi
LIBS="$LIBS $WASM_PREFIX/lib/libcrypto.a $WASM_PREFIX/lib/libssl.a"
# Add libtinycbor.a if it exists (needed for CBOR serialization)
if [ -f "$WASM_PREFIX/lib/libtinycbor.a" ]; then
    LIBS="$LIBS $WASM_PREFIX/lib/libtinycbor.a"
fi

# C++ runtime libraries (needed for exceptions, RTTI)
# Using direct paths to wasm32-wasi C++ runtime libraries
LIBS="$LIBS $WASI_CXX_RT_PATH/libc++.a $WASI_CXX_RT_PATH/libc++abi.a"

# WASI emulated libraries for missing POSIX functions
LIBS="$LIBS -lwasi-emulated-getpid -lwasi-emulated-signal"

# setjmp/longjmp library (required for SJLJ exception handling)
LIBS="$LIBS -lsetjmp"

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
        -Wl,--initial-memory=16777216 \
        -Wl,--max-memory=33554432 \
        -Wl,-z,stack-size=1048576 \
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
    info "Building OpenABE CLI tools for WebAssembly with MCL backend..."

    # Install MCL headers and libraries to correct location
    info "Installing MCL WASM dependencies..."
    if [ -f "$ZROOT/install-wasm-headers.sh" ]; then
        "$ZROOT/install-wasm-headers.sh" || error "Failed to install WASM dependencies"
    else
        warn "install-wasm-headers.sh not found, assuming dependencies are in place"
    fi

    # Verify dependencies exist
    if [ ! -f "$WASM_BUILD_DIR/libopenabe.a" ]; then
        error "libopenabe.a not found. Run ./build-openabe-wasm.sh first"
    fi

    if [ ! -f "$WASM_PREFIX/lib/libmcl.a" ]; then
        error "libmcl.a not found. Run ./build-deps-wasm.sh first"
    fi

    if [ ! -f "$WASM_PREFIX/lib/libmclecdsa.a" ]; then
        warn "libmclecdsa.a not found (not required for ABE operations)"
    fi

    # Compile common object file
    compile_common

    # If building a specific tool (passed as $1), build only that
    if [ -n "$1" ]; then
        case "$1" in
            benchmark_comprehensive)
                build_cli_tool "benchmark_comprehensive" "../src/benchmark_comprehensive.cpp"
                ;;
            oabe_setup)
                build_cli_tool "oabe_setup" "setup.cpp"
                ;;
            oabe_keygen)
                build_cli_tool "oabe_keygen" "keygen.cpp"
                ;;
            oabe_enc)
                build_cli_tool "oabe_enc" "encrypt.cpp"
                ;;
            oabe_dec)
                build_cli_tool "oabe_dec" "decrypt.cpp"
                ;;
            cbor_test)
                build_cli_tool "cbor_test" "cbor_test.cpp"
                ;;
            *)
                warn "Unknown tool: $1"
                ;;
        esac
    else
        # Build all CLI tools
        build_cli_tool "oabe_setup" "setup.cpp"
        build_cli_tool "oabe_keygen" "keygen.cpp"
        build_cli_tool "oabe_enc" "encrypt.cpp"
        build_cli_tool "oabe_dec" "decrypt.cpp"
        build_cli_tool "cbor_test" "cbor_test.cpp"
    fi

    info "CLI tools build complete!"
    info "Output directory: $CLI_WASM_DIR"
    echo ""
    info "Built WASM modules:"
    ls -lh "$CLI_WASM_DIR"/*.wasm 2>/dev/null || warn "No .wasm files generated"
}

main "$@"
