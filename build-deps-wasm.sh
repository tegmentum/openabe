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
# Note: Using wasm32-wasi-threads for pthread support
# This uses a special sysroot with libraries compiled with atomics+bulk-memory
WASM_SYSROOT="$WASI_SDK_PATH/share/wasi-sysroot"
WASM_TARGET="wasm32-wasi-threads"

# Compiler flags for building static libraries
# Add signal emulation for GMP compatibility
# Add atomics and bulk-memory for pthread support (required for --shared-memory)
# -pthread is added automatically by wasi-sdk-pthread.cmake toolchain
export CFLAGS="--target=$WASM_TARGET --sysroot=$WASM_SYSROOT -O2 -D_WASI_EMULATED_SIGNAL -D_WASI_EMULATED_GETPID -matomics -mbulk-memory"
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

# Build MCL for WASM using C API
build_mcl() {
    info "Building MCL for WebAssembly using C API..."

    cd "$WASM_DEPS_DIR"

    # Download MCL if not present
    local MCL_VERSION="3.04"
    local MCL_ARCHIVE="mcl-${MCL_VERSION}.tar.gz"
    local MCL_DIR="mcl-${MCL_VERSION}"

    if [ ! -f "$MCL_ARCHIVE" ]; then
        info "Downloading MCL ${MCL_VERSION}..."
        curl -L "https://github.com/herumi/mcl/archive/refs/tags/v${MCL_VERSION}.tar.gz" -o "$MCL_ARCHIVE"
    fi

    if [ ! -d "$MCL_DIR" ]; then
        info "Extracting MCL ${MCL_VERSION}..."
        tar -xzf "$MCL_ARCHIVE"
    fi

    cd "$MCL_DIR"

    # Generate MCL config header for WASM
    mkdir -p include/mcl
    cat > include/mcl/config.hpp << 'EOF'
#pragma once
#define MCL_FP_BIT 384
#define MCL_FR_BIT 256
#define MCL_USE_LLVM 0
#define MCL_USE_GMP 0
#define MCL_USE_OPENSSL 0
#define MCL_MAX_FP_BIT_SIZE 384
#define MCL_MAX_FR_BIT_SIZE 256
#define MCL_SIZEOF_UNIT 8
#define MCL_USE_XBYAK 0
#define MCL_DONT_USE_XBYAK
#define CYBOZU_DONT_USE_EXCEPTION
#define CYBOZU_DONT_USE_STRING
#define MCL_NO_AUTOLINK
#define MCL_DLL_API
EOF

    # Install MCL headers
    info "Installing MCL headers to $WASM_PREFIX..."
    mkdir -p "$WASM_PREFIX/include/mcl"
    mkdir -p "$WASM_PREFIX/include/cybozu"
    mkdir -p "$WASM_PREFIX/lib"

    # Copy C headers (not C++ headers - zelement_mcl.cpp uses C API for WASM)
    cp -r include/mcl/*.h "$WASM_PREFIX/include/mcl/" 2>/dev/null || warn "No .h files found"
    # Also copy .hpp for native builds (zelement_mcl.cpp conditionally includes)
    cp -r include/mcl/*.hpp "$WASM_PREFIX/include/mcl/" 2>/dev/null || warn "No .hpp files found"
    cp -r include/cybozu/*.hpp "$WASM_PREFIX/include/cybozu/" 2>/dev/null || warn "Failed to copy cybozu headers"

    # Build MCL C implementation for WASM
    info "Compiling MCL C implementation for WASM..."
    mkdir -p lib/wasm

    # MCL C API implementation - compile our custom WASM version
    local MCL_CXXFLAGS="$CXXFLAGS"
    MCL_CXXFLAGS="$MCL_CXXFLAGS -I./include"
    MCL_CXXFLAGS="$MCL_CXXFLAGS -I./src"
    MCL_CXXFLAGS="$MCL_CXXFLAGS -DMCL_FP_BIT=384"
    MCL_CXXFLAGS="$MCL_CXXFLAGS -DMCL_FR_BIT=256"
    MCL_CXXFLAGS="$MCL_CXXFLAGS -DMCLBN_FP_UNIT_SIZE=6"
    MCL_CXXFLAGS="$MCL_CXXFLAGS -DMCLBN_FR_UNIT_SIZE=4"
    MCL_CXXFLAGS="$MCL_CXXFLAGS -DMCL_MAX_BIT_SIZE=384"
    MCL_CXXFLAGS="$MCL_CXXFLAGS -DMCL_DONT_USE_XBYAK"
    MCL_CXXFLAGS="$MCL_CXXFLAGS -DMCL_USE_LLVM=0"
    MCL_CXXFLAGS="$MCL_CXXFLAGS -DMCL_USE_GMP=0"
    MCL_CXXFLAGS="$MCL_CXXFLAGS -DCYBOZU_DONT_USE_EXCEPTION"
    MCL_CXXFLAGS="$MCL_CXXFLAGS -DCYBOZU_DONT_USE_STRING"
    MCL_CXXFLAGS="$MCL_CXXFLAGS -DMCL_NO_AUTOLINK"

    # Compile our custom bn_c384_256_wasm.cpp which includes C++ API
    if [ -f "src/bn_c384_256_wasm.cpp" ]; then
        info "Compiling bn_c384_256_wasm.cpp with C++ templates..."
        $CXX $MCL_CXXFLAGS -c src/bn_c384_256_wasm.cpp -o lib/wasm/bn_c384_256_wasm.o 2>&1 | tee /tmp/mcl_build.log || {
            error "Failed to compile MCL C API implementation"
            warn "Error log:"
            tail -50 /tmp/mcl_build.log | grep -E "error:|warning:" | head -20
            exit 1
        }

        # Create library from object file
        $AR rcs lib/libmcl.a lib/wasm/bn_c384_256_wasm.o
        info "Created libmcl.a from bn_c384_256_wasm.o"
    else
        error "bn_c384_256_wasm.cpp not found!"
        exit 1
    fi

    # Create stub libmclecdsa.a (not needed for pairing operations)
    touch lib/wasm/stub.c
    $CC $CFLAGS -c lib/wasm/stub.c -o lib/wasm/stub.o 2>/dev/null || true
    $AR rcs lib/libmclecdsa.a lib/wasm/stub.o 2>/dev/null || $AR rcs lib/libmclecdsa.a lib/wasm/bn_c384_256_wasm.o

    # Copy libraries
    cp lib/libmcl.a "$WASM_PREFIX/lib/"
    cp lib/libmclecdsa.a "$WASM_PREFIX/lib/"

    if [ -f "$WASM_PREFIX/lib/libmcl.a" ]; then
        info "MCL WASM build complete (size: $(du -h $WASM_PREFIX/lib/libmcl.a | cut -f1))"
    else
        error "MCL library not created"
        exit 1
    fi
}

# Main execution
main() {
    info "Building OpenABE dependencies for WebAssembly..."

    build_gmp
    build_openssl
    build_mcl

    info "All dependencies built successfully!"
    info "Install prefix: $WASM_PREFIX"
}

main "$@"
