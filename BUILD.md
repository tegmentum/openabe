# OpenABE Build Guide

Comprehensive guide for building OpenABE on different platforms and architectures.

## Table of Contents

- [Quick Start](#quick-start)
- [Build Targets](#build-targets)
- [Platform Support](#platform-support)
- [Build Options](#build-options)
- [Advanced Usage](#advanced-usage)
- [Troubleshooting](#troubleshooting)

## Quick Start

### One-Command Build

```bash
# Build for your current platform
./build.sh native

# Build for WebAssembly
./build.sh wasm

# Build for all platforms
./build.sh all
```

### Prerequisites

**Native Build:**
- C/C++ compiler (GCC/Clang)
- Make
- Bison, Flex
- Development libraries: OpenSSL, GMP

**WebAssembly Build:**
- curl (for downloading WASI SDK)
- tar, gzip
- No manual WASI SDK installation needed!

## Build Targets

### Native
Build for the current platform (macOS or Linux).

```bash
./build.sh native
```

Output:
- CLI tools: `cli/oabe_setup`, `cli/oabe_keygen`, `cli/oabe_enc`, `cli/oabe_dec`
- Library: `root/lib/libopenabe.{a,dylib,so}`
- Headers: `root/include/openabe/`

### WebAssembly (WASM)
Build for WebAssembly using WASI SDK.

```bash
./build.sh wasm
```

Output:
- CLI tools: `cli-wasm/oabe_setup.wasm`, `cli-wasm/oabe_keygen.wasm`, etc.
- Library: `build-wasm/libopenabe.a`

**First-time build:** WASI SDK (~103 MB) will be automatically downloaded to `$HOME/wasi-sdk`

### All
Build for both native and WASM.

```bash
./build.sh all
```

### Clean
Remove all build artifacts.

```bash
./build.sh clean
```

### Test
Run test suite (native only).

```bash
./build.sh test
```

## Platform Support

| Platform | Architecture | Native | WASM |
|----------|-------------|---------|------|
| macOS | x86_64 | ✓ | ✓ |
| macOS | ARM64 (Apple Silicon) | ✓ | ✓ |
| Linux | x86_64 | ✓ | ✓ |
| Linux | ARM64 | ✓ | ✓ |

WASM binaries are platform-independent and run on any system with [wasmtime](https://wasmtime.dev).

## Build Options

### Parallel Jobs
Control build parallelism:

```bash
# Use 8 parallel jobs
./build.sh -j 8 native

# Auto-detect (default)
./build.sh native
```

### Dependencies Only
Build only dependencies (useful for debugging):

```bash
./build.sh --deps-only native
./build.sh --deps-only wasm
```

### Library Only
Build library without CLI tools:

```bash
./build.sh --lib-only native
```

### Skip Examples
Skip building examples (native only):

```bash
./build.sh --no-examples native
```

### Verbose Output
Enable verbose build output:

```bash
./build.sh -v native
```

## Advanced Usage

### Cross-Platform Development

Build native and WASM in one command:

```bash
./build.sh all
```

### Environment Variables

**All Builds:**
```bash
export ZROOT=/path/to/openabe  # Auto-detected if not set
```

**Native Build:**
```bash
export CC=clang
export CXX=clang++
export INSTALL_PREFIX=/usr/local
```

**WASM Build:**
```bash
export WASI_SDK_PATH=/custom/path/to/wasi-sdk  # Default: $HOME/wasi-sdk
export WASI_SDK_VERSION=25                      # Default: 24
```

### Custom Configurations

**Native build with custom compiler:**
```bash
CC=gcc-12 CXX=g++-12 ./build.sh native
```

**WASM build with custom WASI SDK:**
```bash
WASI_SDK_PATH=/opt/wasi-sdk-25 ./build.sh wasm
```

### Incremental Builds

The build system supports incremental builds:

```bash
# Initial build
./build.sh native

# Modify source files
# ...

# Rebuild (only changed files)
./build.sh native
```

### Testing WASM Binaries

Install wasmtime:

```bash
# macOS
brew install wasmtime

# Linux
curl https://wasmtime.dev/install.sh -sSf | bash
```

Run WASM tools:

```bash
# Show usage
wasmtime cli-wasm/oabe_setup.wasm

# CP-ABE setup
wasmtime cli-wasm/oabe_setup.wasm -s CP -p test

# With file system access
wasmtime --dir=/tmp cli-wasm/oabe_setup.wasm -s CP -p /tmp/test
```

## Manual Build Steps

If you prefer manual control:

### Native Build

```bash
# 1. Set up environment
source env

# 2. Build dependencies
make -j$(nproc) deps

# 3. Build library
make -j$(nproc) src

# 4. Build CLI tools
make -j$(nproc) cli

# 5. (Optional) Build examples
make -j$(nproc) examples
```

### WASM Build

```bash
# 1. Build dependencies (downloads WASI SDK automatically)
./build-deps-wasm.sh

# 2. Build library
./build-openabe-wasm.sh

# 3. Build CLI tools
./build-cli-wasm.sh
```

## Troubleshooting

### Native Build Issues

**Missing dependencies:**
```bash
# macOS
brew install openssl gmp bison flex

# Ubuntu/Debian
sudo apt-get install libssl-dev libgmp-dev bison flex build-essential

# Fedora/RHEL
sudo dnf install openssl-devel gmp-devel bison flex gcc-c++
```

**Environment not set:**
```bash
source env
```

### WASM Build Issues

**WASI SDK download fails:**

Manually download from: https://github.com/WebAssembly/wasi-sdk/releases

Extract to `$HOME/wasi-sdk` or set `WASI_SDK_PATH`.

**RNG errors in WASM:**

Ensure you're using the latest build scripts. RELIC should be configured with `SEED=ZERO` and `RAND=CALL`.

**File I/O errors:**

WASM has limited file system access. Use wasmtime's `--dir` flag:
```bash
wasmtime --dir=/tmp cli-wasm/oabe_setup.wasm -s CP -p /tmp/test
```

### Clean and Rebuild

If you encounter persistent issues:

```bash
# Clean everything
./build.sh clean

# Remove WASI SDK (optional)
rm -rf $HOME/wasi-sdk

# Rebuild
./build.sh all
```

## Installation

Install native build to system:

```bash
# Build
./build.sh native

# Install (requires sudo)
source env
sudo make install

# Default prefix: /usr/local
# Custom prefix:
sudo make install INSTALL_PREFIX=/opt/openabe
```

## Performance Tips

1. **Parallel builds**: Use `-j` with number of CPU cores
   ```bash
   ./build.sh -j $(nproc) native
   ```

2. **Dependencies-only rebuilds**: When debugging dependencies
   ```bash
   ./build.sh clean
   ./build.sh --deps-only native
   ./build.sh native  # Reuses deps
   ```

3. **Incremental builds**: Modify source and rebuild without clean
   ```bash
   # Edit source files
   ./build.sh native  # Only rebuilds changed files
   ```

## Build Script Options Reference

```
./build.sh [OPTIONS] <target>

Targets:
  native          Build for native platform
  wasm            Build for WebAssembly
  all             Build for all targets
  clean           Clean build artifacts
  test            Run tests (native only)

Options:
  -h, --help       Show help message
  -v, --verbose    Enable verbose output
  -j, --jobs N     Number of parallel jobs
  --deps-only      Build dependencies only
  --lib-only       Build library only
  --no-examples    Skip examples (native)
```

## Additional Resources

- [WASM Build Details](WASM_BUILD.md) - Detailed WebAssembly build documentation
- [Main README](README.md) - OpenABE overview and usage
- [Examples](examples/) - Usage examples

## Getting Help

If you encounter issues:

1. Check this guide's [Troubleshooting](#troubleshooting) section
2. Review the error messages carefully
3. Try a clean rebuild: `./build.sh clean && ./build.sh <target>`
4. Open an issue on GitHub with:
   - Platform and architecture
   - Build command used
   - Complete error output
   - Build script version
