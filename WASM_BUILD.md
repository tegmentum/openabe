# Building OpenABE for WebAssembly

This guide explains how to build OpenABE for WebAssembly (WASM) using WASI SDK.

## Prerequisites

- **macOS or Linux** (x86_64 or ARM64/Apple Silicon)
- **curl** (for downloading WASI SDK)
- **Basic build tools** (make, tar, etc.)

**No manual setup required!** The build scripts will automatically download and install WASI SDK 24 to `$HOME/wasi-sdk` if not already present (~103 MB download).

## Quick Start

To build everything in one command:

```bash
./build-wasm.sh
```

This master script will:
1. Download and install WASI SDK (if needed)
2. Build dependencies (GMP, OpenSSL, RELIC)
3. Build OpenABE library
4. Build CLI tools

## Step-by-Step Build

### 1. Build Dependencies

```bash
./build-deps-wasm.sh
```

This will:
- Download WASI SDK 24 to `$HOME/wasi-sdk` (if not already installed)
- Build GMP 6.2.1 for WASM
- Build OpenSSL 1.1.1 for WASM
- Build RELIC 0.5.0 for WASM with proper RNG configuration

### 2. Build OpenABE Library

```bash
./build-openabe-wasm.sh
```

This compiles the OpenABE library sources into a static library (`libopenabe.a`).

### 3. Build CLI Tools

```bash
./build-cli-wasm.sh
```

This builds the WASM executables:
- `cli-wasm/oabe_setup.wasm` - System setup utility
- `cli-wasm/oabe_keygen.wasm` - Key generation utility
- `cli-wasm/oabe_enc.wasm` - Encryption utility
- `cli-wasm/oabe_dec.wasm` - Decryption utility

## Configuration

### WASI SDK Location

By default, WASI SDK is installed to `$HOME/wasi-sdk`. You can override this:

```bash
export WASI_SDK_PATH=/custom/path/to/wasi-sdk
./build-deps-wasm.sh
```

### WASI SDK Version

To use a different WASI SDK version:

```bash
export WASI_SDK_VERSION=25
./build-deps-wasm.sh
```

## Testing WASM Modules

Install wasmtime:

```bash
# macOS
brew install wasmtime

# Linux
curl https://wasmtime.dev/install.sh -sSf | bash
```

Test the modules:

**IMPORTANT**: WASM file I/O requires the `--dir` flag to grant directory access.

```bash
# Show usage (no file I/O needed)
wasmtime cli-wasm/oabe_setup.wasm

# CP-ABE setup (with file I/O)
cd /tmp
wasmtime --dir=. cli-wasm/oabe_setup.wasm -s CP -p test

# Generate key (with file I/O)
wasmtime --dir=. cli-wasm/oabe_keygen.wasm -s CP -p test -i "dept:IT|role:admin" -o admin.key

# Encrypt data (with file I/O)
echo "Secret message" > data.txt
wasmtime --dir=. cli-wasm/oabe_enc.wasm -s CP -p test -e "(dept:IT and role:admin)" -i data.txt -o data.cpabe
```

**Best Practice**: Always use `--dir=.` when working with files, and use relative paths within that directory.

## Architecture Details

### WASM-Specific Changes

1. **RNG Configuration**: RELIC is built with `SEED=ZERO` and `RAND=CALL`, using a callback that delegates to OpenSSL's `RAND_bytes()` for entropy.

2. **Threading**: Mutex operations are disabled in WASM builds using `#ifndef __wasm__` guards.

3. **Symbol Renaming**: RELIC's `bn_*` symbols are renamed to `relic_bn_*` to avoid conflicts with OpenSSL.

4. **Exception Handling**: Uses SJLJ (setjmp/longjmp) based exceptions via `-mllvm -wasm-enable-sjlj`.

### Build Outputs

- Dependencies: `build-wasm/install/`
- OpenABE library: `build-wasm/libopenabe.a`
- CLI tools: `cli-wasm/*.wasm`

### File I/O Limitations

WASM modules running in wasmtime have restricted file system access by default for security. You **must** use wasmtime's `--dir` flag to grant access to directories:

```bash
# Grant access to /tmp
wasmtime --dir=/tmp cli-wasm/oabe_setup.wasm -s CP -p /tmp/test

# Grant access to current directory (recommended)
cd /path/to/workdir
wasmtime --dir=. cli-wasm/oabe_setup.wasm -s CP -p test
```

**Key Points**:
- Without `--dir`, file operations will fail silently or crash
- Use `--dir=.` to grant access to the current directory
- Use relative paths when using `--dir=.`
- You can specify multiple `--dir` flags for different directories

## Troubleshooting

### WASI SDK Download Fails

If the automatic download fails, manually download WASI SDK from:
https://github.com/WebAssembly/wasi-sdk/releases

Extract to `$HOME/wasi-sdk` or set `WASI_SDK_PATH`.

### Build Errors

1. Clean build artifacts:
   ```bash
   rm -rf build-wasm cli-wasm
   ```

2. Rebuild from scratch:
   ```bash
   ./build-wasm.sh
   ```

### RNG Errors in WASM

If you see errors about `/dev/urandom`, ensure:
- RELIC was built with `SEED=ZERO` and `RAND=CALL`
- The WASM RNG callback is registered in `zelement.c:zml_init()`

## Platform Support

- **macOS**: x86_64, ARM64 (Apple Silicon)
- **Linux**: x86_64, ARM64

The WASM output is platform-independent and can run on any system with wasmtime.
