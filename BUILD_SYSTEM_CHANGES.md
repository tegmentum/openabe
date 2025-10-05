# Build System Changes

This document summarizes the enhancements made to the OpenABE build system.

## Overview

The OpenABE build system has been enhanced with:
1. **Unified build script** supporting multiple target architectures
2. **Automatic WASI SDK download** for WebAssembly builds
3. **Comprehensive documentation** for all build scenarios

## New Files

### Build Scripts

1. **`build.sh`** - Universal build script
   - Supports native and WASM targets
   - Auto-detects platform (macOS/Linux, x86_64/ARM64)
   - Configurable parallel builds
   - Multiple build modes (deps-only, lib-only, etc.)

2. **`build-wasm.sh`** - WASM master build script
   - Orchestrates complete WASM build
   - Calls deps → library → CLI in sequence

3. **`build-deps-wasm.sh`** - WASM dependencies
   - **Auto-downloads WASI SDK** from GitHub
   - Builds GMP, OpenSSL, RELIC for WASM
   - Platform detection (macOS/Linux, x86_64/ARM64)

4. **`build-openabe-wasm.sh`** - WASM library build
   - Compiles OpenABE library for WASM
   - Validates WASI SDK installation

5. **`build-cli-wasm.sh`** - WASM CLI tools
   - Builds oabe_setup, oabe_keygen, oabe_enc, oabe_dec
   - Generates .wasm executables

### Documentation

1. **`BUILD.md`** - Comprehensive build guide
   - Quick start instructions
   - All build targets explained
   - Platform support matrix
   - Build options reference
   - Troubleshooting guide

2. **`WASM_BUILD.md`** - WebAssembly build details
   - WASM-specific configuration
   - Architecture details
   - RNG implementation notes
   - File I/O limitations

3. **`BUILD_SYSTEM_CHANGES.md`** - This file
   - Summary of all changes
   - Migration guide

### Support Files

1. **`build-wasm/wasi-toolchain.cmake`** - CMake toolchain for WASM
   - WASI SDK configuration
   - Cross-compilation settings
   - Environment variable support

## Key Features

### 1. Automatic WASI SDK Download

The build system automatically downloads and installs WASI SDK if not present:

```bash
./build.sh wasm  # Downloads WASI SDK 24 (~103 MB) if needed
```

**Supported platforms:**
- macOS: x86_64, ARM64
- Linux: x86_64, ARM64

**Configuration:**
```bash
export WASI_SDK_PATH=/custom/path    # Default: $HOME/wasi-sdk
export WASI_SDK_VERSION=25           # Default: 24
```

### 2. Unified Build Interface

Single command for any target:

```bash
./build.sh native      # Native build
./build.sh wasm        # WebAssembly build
./build.sh all         # Both targets
./build.sh clean       # Clean all
./build.sh test        # Run tests
```

### 3. Build Options

```bash
-j, --jobs N         # Parallel jobs (default: auto-detect)
--deps-only          # Build dependencies only
--lib-only           # Library without CLI tools
--no-examples        # Skip examples (native)
-v, --verbose        # Verbose output
```

### 4. Cross-Platform Support

| Platform | Arch | Native | WASM |
|----------|------|--------|------|
| macOS | x86_64 | ✓ | ✓ |
| macOS | ARM64 | ✓ | ✓ |
| Linux | x86_64 | ✓ | ✓ |
| Linux | ARM64 | ✓ | ✓ |

## Implementation Details

### WASI SDK Download

**Function:** `install_wasi_sdk()` in `build-deps-wasm.sh`

1. **Platform Detection:**
   ```bash
   detect_platform()  # Detects OS and architecture
   ```

2. **URL Construction:**
   ```
   Format: wasi-sdk-{VERSION}.0-{ARCH}-{OS}.tar.gz
   Example: wasi-sdk-24.0-arm64-macos.tar.gz
   ```

3. **Download & Extract:**
   - Downloads from GitHub releases
   - Extracts to `$WASI_SDK_PATH`
   - Validates installation

4. **Error Handling:**
   - Retry on failure
   - Cleanup on error
   - Clear error messages

### RELIC RNG Configuration

**Critical Fix for WASM:**

RELIC is configured with:
- `SEED=ZERO` - No /dev/urandom dependency
- `RAND=CALL` - Callback-based RNG

**Implementation** (`src/zml/zelement.c`):
```c
#ifdef __wasm__
static void wasm_rng_callback(uint8_t *buf, int size, void *args) {
    RAND_bytes(buf, size);  // Use OpenSSL
}

void zml_init() {
    core_init();
    rand_seed(wasm_rng_callback, NULL);
}
#endif
```

### Build Flow

**Native:**
```
env → deps → src → cli → examples
```

**WASM:**
```
WASI SDK → deps (GMP/OpenSSL/RELIC) → library → CLI tools
```

## Migration Guide

### From Old Build System

**Old way:**
```bash
# Native
. ./env
make
make test

# WASM (manual)
# Install WASI SDK manually
# Build each dependency manually
```

**New way:**
```bash
# Native
./build.sh native
./build.sh test

# WASM (automatic)
./build.sh wasm  # Everything automatic!
```

### Environment Variables

**Native (unchanged):**
```bash
export ZROOT=$(pwd)
export CC=clang
export CXX=clang++
```

**WASM (new):**
```bash
export WASI_SDK_PATH=$HOME/wasi-sdk      # Auto-downloads if missing
export WASI_SDK_VERSION=24               # SDK version
```

### Build Outputs

**Native:**
- Binaries: `cli/oabe_*`
- Library: `root/lib/libopenabe.*`

**WASM:**
- Binaries: `cli-wasm/oabe_*.wasm`
- Library: `build-wasm/libopenabe.a`

## Testing

### Native
```bash
./build.sh native
./build.sh test
```

### WASM
```bash
./build.sh wasm

# Test with wasmtime
wasmtime cli-wasm/oabe_setup.wasm -s CP -p test
```

## Troubleshooting

### WASI SDK Issues

**Problem:** WASI SDK download fails

**Solutions:**
1. Check internet connection
2. Manually download from GitHub releases
3. Extract to `$HOME/wasi-sdk` or set `WASI_SDK_PATH`

### Build Failures

**Problem:** Compilation errors

**Solutions:**
1. Clean build: `./build.sh clean`
2. Check dependencies: `./build.sh --deps-only <target>`
3. Rebuild: `./build.sh <target>`

### RNG Errors in WASM

**Problem:** FATAL ERROR in relic_rand_*

**Solutions:**
1. Ensure using latest build scripts
2. Verify RELIC configured with `SEED=ZERO RAND=CALL`
3. Check `zelement.c` has WASM RNG callback

## Future Enhancements

Potential improvements:
1. **Docker support** - Containerized builds
2. **Windows WASM** - Add Windows WASI SDK support
3. **Prebuilt binaries** - GitHub releases with artifacts
4. **CI/CD integration** - Automated testing across platforms
5. **Android/iOS** - Mobile platform support

## Credits

WASM build system enhancements include:
- WASI SDK auto-download
- RELIC RNG callback for WASM
- Symbol renaming compatibility layer
- Threading/mutex guards for WASM
- Comprehensive documentation

## Version History

- **v1.7** - Added unified build system and WASM support
- **v1.0** - Original build system

## Additional Resources

- [BUILD.md](BUILD.md) - Main build guide
- [WASM_BUILD.md](WASM_BUILD.md) - WASM details
- [README.md](README.md) - Project overview
- [WASI SDK Releases](https://github.com/WebAssembly/wasi-sdk/releases)
