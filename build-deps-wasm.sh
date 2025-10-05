#!/bin/bash
# Build OpenABE dependencies for WebAssembly using WASI-SDK

set -e

# Configuration
WASI_SDK_VERSION="${WASI_SDK_VERSION:-24}"
WASI_SDK_PATH="${WASI_SDK_PATH:-$HOME/wasi-sdk}"
ZROOT="$(pwd)"
WASM_BUILD_DIR="$ZROOT/build-wasm"
WASM_DEPS_DIR="$WASM_BUILD_DIR/deps"
WASM_PREFIX="$WASM_BUILD_DIR/install"

# WASI-SDK tools
export CC="$WASI_SDK_PATH/bin/clang"
export CXX="$WASI_SDK_PATH/bin/clang++"
export AR="$WASI_SDK_PATH/bin/llvm-ar"
export RANLIB="$WASI_SDK_PATH/bin/llvm-ranlib"
export NM="$WASI_SDK_PATH/bin/llvm-nm"

# WASM target and sysroot
# Note: Using wasm32-wasi for dependencies since they are static libraries
# The final CLI executables will use wasm32-wasip2 (configured in cli-wasm/Makefile)
# Static libraries are target-agnostic - the wasip1/wasip2 choice matters only at final link time
WASM_SYSROOT="$WASI_SDK_PATH/share/wasi-sysroot"
WASM_TARGET="wasm32-wasi"

# Compiler flags for building static libraries
# Add signal emulation for GMP compatibility
export CFLAGS="--target=$WASM_TARGET --sysroot=$WASM_SYSROOT -O2 -D_WASI_EMULATED_SIGNAL -D_WASI_EMULATED_GETPID"
export CXXFLAGS="$CFLAGS -std=c++11 -fno-exceptions -fno-rtti"
export LDFLAGS="--target=$WASM_TARGET --sysroot=$WASM_SYSROOT -lwasi-emulated-signal -lwasi-emulated-getpid"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

info() { echo -e "${GREEN}[INFO]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Detect OS and architecture
detect_platform() {
    local os=$(uname -s | tr '[:upper:]' '[:lower:]')
    local arch=$(uname -m)

    case "$os" in
        darwin)
            OS_TYPE="macos"
            ;;
        linux)
            OS_TYPE="linux"
            ;;
        *)
            error "Unsupported OS: $os"
            exit 1
            ;;
    esac

    case "$arch" in
        x86_64|amd64)
            ARCH_TYPE="x86_64"
            ;;
        arm64|aarch64)
            ARCH_TYPE="arm64"
            ;;
        *)
            error "Unsupported architecture: $arch"
            exit 1
            ;;
    esac
}

# Download and install WASI SDK
install_wasi_sdk() {
    if [ -f "$WASI_SDK_PATH/bin/clang" ]; then
        info "WASI SDK already installed at $WASI_SDK_PATH"
        return 0
    fi

    info "WASI SDK not found. Downloading WASI SDK $WASI_SDK_VERSION..."

    detect_platform

    # Construct download URL based on platform
    # Format: wasi-sdk-{VERSION}.0-{ARCH}-{OS}.tar.gz
    local wasi_sdk_name="wasi-sdk-${WASI_SDK_VERSION}.0"
    local platform_arch="${ARCH_TYPE}-${OS_TYPE}"
    local archive_name="${wasi_sdk_name}-${platform_arch}.tar.gz"
    local download_url="https://github.com/WebAssembly/wasi-sdk/releases/download/wasi-sdk-${WASI_SDK_VERSION}/${archive_name}"
    local temp_dir=$(mktemp -d)
    local archive="$temp_dir/wasi-sdk.tar.gz"

    info "Downloading from: $download_url"

    if ! curl -L -f -o "$archive" "$download_url"; then
        error "Failed to download WASI SDK"
        rm -rf "$temp_dir"
        exit 1
    fi

    info "Extracting WASI SDK to $WASI_SDK_PATH..."
    mkdir -p "$(dirname "$WASI_SDK_PATH")"
    tar -xzf "$archive" -C "$(dirname "$WASI_SDK_PATH")"

    # The archive extracts to wasi-sdk-{VERSION}.0-{ARCH}-{OS}
    local extracted_dir="$(dirname "$WASI_SDK_PATH")/${wasi_sdk_name}-${platform_arch}"
    if [ -d "$extracted_dir" ] && [ "$extracted_dir" != "$WASI_SDK_PATH" ]; then
        # Remove existing installation if present
        [ -d "$WASI_SDK_PATH" ] && rm -rf "$WASI_SDK_PATH"
        mv "$extracted_dir" "$WASI_SDK_PATH"
    fi

    rm -rf "$temp_dir"

    if [ -f "$WASI_SDK_PATH/bin/clang" ]; then
        info "WASI SDK installed successfully"
    else
        error "WASI SDK installation failed"
        exit 1
    fi
}

# Install WASI SDK if needed
install_wasi_sdk

# Create directories
mkdir -p "$WASM_BUILD_DIR"
mkdir -p "$WASM_DEPS_DIR"
mkdir -p "$WASM_PREFIX"

# Build GMP for WASM
build_gmp() {
    info "Building GMP for WebAssembly..."

    cd "$WASM_DEPS_DIR"

    if [ ! -f "gmp-6.2.1.tar.xz" ]; then
        # Try multiple mirrors for faster download
        info "Downloading GMP 6.2.1..."

        # Try each mirror with short timeout
        for mirror in \
            "https://mirrors.kernel.org/gnu/gmp/gmp-6.2.1.tar.xz" \
            "https://gmplib.org/download/gmp/gmp-6.2.1.tar.xz" \
            "https://ftp.gnu.org/gnu/gmp/gmp-6.2.1.tar.xz"
        do
            info "Trying mirror: $mirror"
            if curl -L --connect-timeout 10 --max-time 120 -o gmp-6.2.1.tar.xz "$mirror"; then
                info "Successfully downloaded from $mirror"
                break
            else
                warn "Failed to download from $mirror, trying next..."
                rm -f gmp-6.2.1.tar.xz
            fi
        done

        if [ ! -f "gmp-6.2.1.tar.xz" ]; then
            error "Failed to download GMP from all mirrors"
            exit 1
        fi
    fi

    if [ ! -d "gmp-6.2.1" ]; then
        info "Extracting GMP 6.2.1..."
        tar xf gmp-6.2.1.tar.xz || { error "Failed to extract GMP tarball"; exit 1; }
    fi

    cd gmp-6.2.1

    # Patch GMP to disable signal-dependent code for WASM
    info "Patching GMP for WASM compatibility..."

    # Create minimal invalid.c that doesn't use signals
    cat > invalid.c << 'EOF'
/* Minimal invalid.c for WASM - signals not supported */
#include "gmp-impl.h"
#include <stdlib.h>

void __gmp_invalid_operation (void)
{
    /* In WASM, we can't raise signals, so just abort */
    abort();
}
EOF

    # Create minimal errno.c that doesn't use signals
    cat > errno.c << 'EOF'
/* Minimal errno.c for WASM - signals not supported */
#include "gmp-impl.h"

extern const int __gmp_0 = 0;
EOF

    # Configure GMP for WASM with C++ support
    ./configure \
        --prefix="$WASM_PREFIX" \
        --host=wasm32-wasi \
        --disable-assembly \
        --disable-shared \
        --enable-static \
        --enable-cxx \
        CC="$CC" \
        CXX="$CXX" \
        CFLAGS="$CFLAGS" \
        CXXFLAGS="$CFLAGS -std=c++11" \
        AR="$AR" \
        RANLIB="$RANLIB"

    make -j$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)
    make install

    info "GMP build complete"
}

# Build OpenSSL crypto for WASM (using pre-built openssl-wasm)
build_openssl() {
    info "Building OpenSSL for WebAssembly..."

    cd "$WASM_DEPS_DIR"

    # Use jedisct1/openssl-wasm - a pre-built OpenSSL for WASM
    if [ ! -d "openssl-wasm" ]; then
        info "Cloning openssl-wasm from jedisct1/openssl-wasm..."
        git clone --depth 1 https://github.com/jedisct1/openssl-wasm.git
    fi

    cd openssl-wasm

    # This repo provides pre-built static libraries for WASM in precompiled/
    # Copy the libraries and headers to our install prefix
    if [ -d "precompiled/lib" ] && [ -d "precompiled/include" ]; then
        info "Installing pre-built OpenSSL WASM libraries..."
        cp -r precompiled/lib/* "$WASM_PREFIX/lib/" || warn "Failed to copy OpenSSL libraries"
        cp -r precompiled/include/* "$WASM_PREFIX/include/" || warn "Failed to copy OpenSSL headers"

        # Verify libraries were copied
        if [ -f "$WASM_PREFIX/lib/libcrypto.a" ] && [ -f "$WASM_PREFIX/lib/libssl.a" ]; then
            info "OpenSSL WASM installed successfully (libcrypto.a: $(du -h $WASM_PREFIX/lib/libcrypto.a | cut -f1), libssl.a: $(du -h $WASM_PREFIX/lib/libssl.a | cut -f1))"
        else
            warn "OpenSSL libraries not found after copy"
        fi
    else
        warn "openssl-wasm precompiled directory not found, may need to build"
    fi
}

# Build RELIC for WASM
build_relic() {
    info "Building RELIC for WebAssembly..."

    cd "$WASM_DEPS_DIR"

    # Check if already extracted
    if [ ! -d "relic-toolkit-0.5.0" ]; then
        if [ -f "$ZROOT/deps/relic/relic-toolkit-0.5.0.tar.gz" ]; then
            cp "$ZROOT/deps/relic/relic-toolkit-0.5.0.tar.gz" .
            tar xzf relic-toolkit-0.5.0.tar.gz
        else
            curl -LO https://github.com/relic-toolkit/relic/releases/download/0.5.0/relic-toolkit-0.5.0.tar.gz
            tar xzf relic-toolkit-0.5.0.tar.gz
        fi
    fi

    cd relic-toolkit-0.5.0

    # Patch CMakeLists.txt to use compatible CMake version
    sed -i.bak 's/cmake_minimum_required(VERSION 3.1)/cmake_minimum_required(VERSION 3.5)/' CMakeLists.txt

    # Patch BLAKE2 to disable 64-byte alignment for WASM (alignment must divide element size)
    sed -i.bak 's/ALIGNME( 64 )//' src/md/blake2.h

    # Rename bn_* symbols to relic_bn_* to avoid conflicts with OpenSSL
    # Using Perl to rename ALL bn_* identifiers (comprehensive approach)
    info "Patching RELIC to rename bn_* symbols..."
    find include src -type f \( -name "*.h" -o -name "*.c" \) -exec perl -pi -e '
        # Rename all bn_ identifiers to relic_bn_ except when inside comments or strings
        # This matches: bn_<anything> where <anything> is alphanumeric or underscore
        s/\bbn_([a-zA-Z0-9_]+)\b/relic_bn_$1/g;
    ' {} \;

    mkdir -p build-wasm
    cd build-wasm

    # Configure RELIC for WASM using CMake
    # Add setjmp/longjmp support for RELIC's error handling
    # RELIC's CMakeLists.txt uses $ENV{COMP} environment variable for compiler flags
    export COMP="$CFLAGS -mllvm -wasm-enable-sjlj"

    cmake .. \
        -DCMAKE_TOOLCHAIN_FILE="$WASI_SDK_PATH/share/cmake/wasi-sdk.cmake" \
        -DCMAKE_INSTALL_PREFIX="$WASM_PREFIX" \
        -DCMAKE_BUILD_TYPE=Release \
        -DSTATIC=on \
        -DSHLIB=off \
        -DARITH=easy \
        -DFP_PRIME=254 \
        -DWITH="BN;MD;DV;FP;EP;FPX;EPX;PP;PC" \
        -DBP_WITH_OPENSSL=on \
        -DSEED=ZERO \
        -DRAND=CALL \
        -DCHECK=off \
        -DTESTS=0 \
        -DBENCH=0 \
        -DFP_METHD="BASIC;COMBA;COMBA;MONTY;LOWER;SLIDE" \
        -DFPX_METHD="INTEG;INTEG;LAZYR" \
        -DPP_METHD="LAZYR;OATEP" \
        -DEP_METHD="PROJC;LWNAF;COMBS;INTER"

    make -j$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)
    make install

    info "RELIC build complete"
}

# Main execution
main() {
    info "Building OpenABE dependencies for WebAssembly..."

    build_gmp
    build_openssl
    build_relic

    info "All dependencies built successfully!"
    info "Install prefix: $WASM_PREFIX"
}

main "$@"
