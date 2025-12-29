#!/bin/bash
# Build OpenABE library for WebAssembly using WASI-SDK

set -e

# Configuration
WASI_SDK_PATH="${WASI_SDK_PATH:-$HOME/wasi-sdk}"
ZROOT="$(pwd)"
WASM_BUILD_DIR="$ZROOT/build-wasm"
WASM_OBJ_DIR="$WASM_BUILD_DIR/obj"
WASM_PREFIX="$WASM_BUILD_DIR/install"

# Check if WASI SDK is installed
if [ ! -f "$WASI_SDK_PATH/bin/clang" ]; then
    echo "Error: WASI SDK not found at $WASI_SDK_PATH"
    echo "Please run ./build-deps-wasm.sh first to install WASI SDK and build dependencies"
    exit 1
fi

# WASI-SDK tools
export CC="$WASI_SDK_PATH/bin/clang"
export CXX="$WASI_SDK_PATH/bin/clang++"
export AR="$WASI_SDK_PATH/bin/llvm-ar"
export RANLIB="$WASI_SDK_PATH/bin/llvm-ranlib"

# WASM target and sysroot
# Note: Using wasm32-wasi-threads for pthread support
# This matches the MCL build configuration
WASM_SYSROOT="$WASI_SDK_PATH/share/wasi-sysroot"
WASM_TARGET="wasm32-wasi-threads"

# Compiler flags for building static library
# Add setjmp/longjmp support for error handling
# Add pthread support for thread-local storage (__thread) to fix CCA verification
# Add atomics and bulk-memory for pthread shared memory support
# Allow overriding optimization level via OPT_LEVEL environment variable
OPT_LEVEL="${OPT_LEVEL:--O1}"  # Default to -O1 if not set
CFLAGS="--target=$WASM_TARGET --sysroot=$WASM_SYSROOT"
CFLAGS="$CFLAGS $OPT_LEVEL -g"  # Use configurable optimization level
CFLAGS="$CFLAGS -D__wasm__"
CFLAGS="$CFLAGS -DBP_WITH_MCL"
CFLAGS="$CFLAGS -DSSL_LIB_INIT"
CFLAGS="$CFLAGS -DEC_WITH_MCL"  # WASM: Use EC stubs since OpenSSL EC isn't available
CFLAGS="$CFLAGS -DMCL_FP_BIT=384"
CFLAGS="$CFLAGS -DMCL_FR_BIT=256"
# MCL BN requires these to be defined at compile time for BLS12-381 (FP=384 bits, FR=256 bits)
# WASM32 uses 4-byte units, so FP=384 bits requires 12 units (384/32=12)
# However, MCL uses 64-bit unit counting, so FP=384 bits = 6 units (384/64=6)
CFLAGS="$CFLAGS -DMCLBN_FP_UNIT_SIZE=6"  # 384 bits / 64 bits per unit = 6 units
CFLAGS="$CFLAGS -DMCLBN_FR_UNIT_SIZE=4"  # 256 bits / 64 bits per unit = 4 units
CFLAGS="$CFLAGS -I$ZROOT/src/include"
CFLAGS="$CFLAGS -I$WASM_PREFIX/include"
CFLAGS="$CFLAGS -I$WASM_SYSROOT/include"
CFLAGS="$CFLAGS -I$ZROOT/deps/tinycbor/src"
CFLAGS="$CFLAGS -I/Library/Developer/CommandLineTools/usr/include"
CFLAGS="$CFLAGS -fPIC"
CFLAGS="$CFLAGS -mllvm -wasm-enable-sjlj"
CFLAGS="$CFLAGS -pthread -matomics -mbulk-memory"

CXXFLAGS="$CFLAGS -std=c++11"
CXXFLAGS="$CXXFLAGS -Wall -Wsign-compare -fstrict-overflow"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

info() { echo -e "${GREEN}[INFO]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

# Create directories
mkdir -p "$WASM_OBJ_DIR"

# Source files
OABE_ZML_SRC=(
    "zml/zgroup.cpp"
    "zml/zpairing.cpp"
    "zml/zelliptic.cpp"
    "zml/zelement_ec.cpp"
    "zml/zelement_ec_stubs_mcl.cpp"  # WASM: EC stubs for MCL backend
    "zml/zelement_bp.cpp"
    "zml/zelement_mcl.cpp"
)

OABE_KEYS_SRC=(
    "keys/zkdf.cpp"
    "keys/zkey.cpp"
    "keys/zpkey.cpp"
    "keys/zkeystore.cpp"
    "keys/zsymkey.cpp"
)

OABE_LOW_SRC=(
    "ske/zcontextske.cpp"
    "pke/zcontextpke.cpp"
    "pksig/zcontextpksig.cpp"
    "abe/zcontextabe.cpp"
    "abe/zcontextcca.cpp"
    "abe/zcontextcpwaters.cpp"
    "abe/zcontextkpgpsw.cpp"
)

OABE_TOOLS_SRC=(
    "tools/zlsss.cpp"
    "tools/zprng.cpp"
)

OABE_CBOR_SRC=(
    "cbor/zcbor_wrapper.cpp"
    "cbor/zcbor_group_elements.cpp"
    "cbor/zcbor_attributes.cpp"
    "cbor/zcbor_policy.cpp"
)

OABE_UTILS_SRC=(
    "utils/zkeymgr.cpp"
    "utils/zcryptoutils.cpp"
    "utils/zcontainer.cpp"
    "utils/zbenchmark.cpp"
    "utils/zerror.cpp"
    "utils/zciphertext.cpp"
    "utils/zpolicy.cpp"
    "utils/zattributelist.cpp"
    "utils/zdriver.cpp"
    "utils/zfunctioninput.cpp"
    "utils/zcurveinfo.cpp"
)

OABE_CORE_SRC=(
    "zobject.cpp"
    "openabe.cpp"
    "zcontext.cpp"
    "zcrypto_box.cpp"
    "zsymcrypto.cpp"
    "openssl_init.cpp"
    "wasm_exception_stubs.cpp"  # WASM-only: exception runtime stubs
)

# Compile C file (zelement.c)
compile_c_file() {
    local src="$1"
    local obj="$WASM_OBJ_DIR/$(basename ${src%.c}.o)"

    info "Compiling C: $src"
    $CC $CFLAGS -c "$ZROOT/src/$src" -o "$obj"
}

# Compile C++ source files
compile_cpp_file() {
    local src="$1"
    local obj="$WASM_OBJ_DIR/$(basename ${src%.cpp}.o)"

    info "Compiling: $src"
    $CXX $CXXFLAGS -c "$ZROOT/src/$src" -o "$obj" || {
        warn "Failed to compile $src, continuing..."
        return 1
    }
}

# Build parser and scanner (optional - may need bison/flex for WASM)
build_parser() {
    info "Building parser and scanner..."

    if [ -x "$ZROOT/bin/bison" ]; then
        cd "$ZROOT/src"
        $ZROOT/bin/bison -d -v zparser.yy || warn "Bison failed"
        $CXX $CXXFLAGS -c zparser.tab.cc -o "$WASM_OBJ_DIR/zparser.o" || warn "Parser compilation failed"

        flex --outfile=zscanner.cpp zscanner.ll || warn "Flex failed"
        $CXX $CXXFLAGS -c zscanner.cpp -o "$WASM_OBJ_DIR/zscanner.o" || warn "Scanner compilation failed"
    else
        warn "Bison not found, skipping parser generation"
    fi
}

# Build parser and scanner
build_parser() {
    info "Building parser and scanner..."

    cd "$ZROOT/src"

    # Check if bison and flex are available
    if ! command -v bison &> /dev/null; then
        warn "Bison not found, skipping parser generation"
        return 1
    fi

    if ! command -v flex &> /dev/null; then
        warn "Flex not found, skipping scanner generation"
        return 1
    fi

    # Generate parser
    info "Running bison on zparser.yy..."
    bison -d -v zparser.yy || {
        warn "Bison failed"
        return 1
    }

    # Copy parser headers to include directory for zscanner.h
    mkdir -p "$ZROOT/src/include/openabe"
    cp zparser.tab.hh "$ZROOT/src/include/openabe/" || {
        warn "Failed to copy parser header"
    }
    # Also copy location.hh and other generated headers if they exist
    for header in location.hh position.hh stack.hh; do
        [ -f "$header" ] && cp "$header" "$ZROOT/src/include/openabe/"
    done

    # Generate scanner
    info "Running flex on zscanner.ll..."
    flex --outfile=zscanner.cpp zscanner.ll || {
        warn "Flex failed"
        return 1
    }

    # Compile parser
    info "Compiling parser..."
    $CXX $CXXFLAGS -c zparser.tab.cc -o "$WASM_OBJ_DIR/zparser.o" || {
        warn "Parser compilation failed"
        return 1
    }

    # Compile scanner
    info "Compiling scanner..."
    $CXX $CXXFLAGS -c zscanner.cpp -o "$WASM_OBJ_DIR/zscanner.o" || {
        warn "Scanner compilation failed"
        return 1
    }

    info "Parser and scanner built successfully"
    return 0
}

# Compile all sources
compile_sources() {
    info "Compiling OpenABE sources for WebAssembly..."

    # Compile all C++ and C sources
    for src in "${OABE_ZML_SRC[@]}" "${OABE_KEYS_SRC[@]}" "${OABE_LOW_SRC[@]}" \
               "${OABE_TOOLS_SRC[@]}" "${OABE_CBOR_SRC[@]}" "${OABE_UTILS_SRC[@]}" "${OABE_CORE_SRC[@]}"; do
        if [[ "$src" == *.c ]]; then
            compile_c_file "$src" || true
        else
            compile_cpp_file "$src" || true
        fi
    done

    # Build parser/scanner
    build_parser || warn "Parser/scanner build skipped - some features may not work"
}

# Create static library
create_library() {
    info "Creating static library..."

    # Collect all object files
    OBJ_FILES=($WASM_OBJ_DIR/*.o)

    if [ ${#OBJ_FILES[@]} -eq 0 ]; then
        error "No object files found!"
    fi

    # Create static library
    $AR rcs "$WASM_BUILD_DIR/libopenabe.a" "${OBJ_FILES[@]}"

    info "Static library created: $WASM_BUILD_DIR/libopenabe.a"
}

# Create WASM module
create_wasm_module() {
    info "Creating WebAssembly module..."

    # Link into a WASM module
    $CXX $CXXFLAGS \
        -o "$WASM_BUILD_DIR/openabe.wasm" \
        -Wl,--no-entry \
        -Wl,--export-dynamic \
        -Wl,--allow-undefined \
        "$WASM_BUILD_DIR/libopenabe.a" \
        -L"$WASM_PREFIX/lib" \
        "$WASM_PREFIX/lib/libmcl.a" "$WASM_PREFIX/lib/libmclecdsa.a" \
        -lcrypto -lssl

    info "WebAssembly module created: $WASM_BUILD_DIR/openabe.wasm"
}

# Main execution
main() {
    info "Building OpenABE for WebAssembly with MCL backend..."

    # Install MCL headers and libraries to correct location for repeatability
    info "Installing MCL WASM dependencies..."
    if [ -f "$ZROOT/install-wasm-headers.sh" ]; then
        "$ZROOT/install-wasm-headers.sh" || {
            error "Failed to install WASM dependencies"
        }
    else
        warn "install-wasm-headers.sh not found, assuming dependencies are in place"
    fi

    compile_sources
    create_library
    # create_wasm_module

    info "OpenABE WebAssembly build complete!"
    info "Output directory: $WASM_BUILD_DIR"
}

main "$@"
