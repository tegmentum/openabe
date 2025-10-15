# OpenABE Performance Comparison Guide

**Date**: 2025-01-15
**Version**: 1.0

---

## Overview

This guide describes the comprehensive performance comparison tools for OpenABE, allowing you to benchmark and compare performance across different platforms and cryptographic backends.

## Available Benchmark Scripts

### 1. `run-native-benchmarks.sh` (Recommended for Quick Testing)

**Purpose**: Compare RELIC vs MCL performance on native platform
**Duration**: ~10-20 minutes (with default 50 iterations)
**Tests**: Native + RELIC, Native + MCL

**Usage**:
```bash
./run-native-benchmarks.sh
./run-native-benchmarks.sh -n 100    # More iterations for accuracy
./run-native-benchmarks.sh --help    # Show options
```

**Output**:
- Results in `benchmark-results-native-YYYYMMDD_HHMMSS/`
- Comparison report in `COMPARISON_REPORT.md`
- Detailed build logs for debugging

### 2. `run-cross-platform-benchmarks.sh` (Full Testing)

**Purpose**: Comprehensive comparison across all platforms and backends
**Duration**: ~30-60 minutes (depending on whether WASM is available)
**Tests**: Native + RELIC, Native + MCL, WASM + RELIC*, WASM + MCL*

*WASM tests require `wasmtime` to be installed

**Usage**:
```bash
./run-cross-platform-benchmarks.sh
./run-cross-platform-benchmarks.sh -n 100    # More iterations
```

**Output**:
- Results in `benchmark-results-YYYYMMDD_HHMMSS/`
- Comprehensive comparison report
- Platform-specific build logs

### 3. Manual Benchmark (Direct Binary)

**Purpose**: Fine-grained control over individual benchmarks
**Prerequisites**: Library already built

**Usage**:
```bash
# Build the benchmark first
cd src
make benchmark_comprehensive

# Run with options
DYLD_LIBRARY_PATH=../cli ./benchmark_comprehensive --help

# Examples:
DYLD_LIBRARY_PATH=../cli ./benchmark_comprehensive -s cpabe -c BLS12_381 -n 50
DYLD_LIBRARY_PATH=../cli ./benchmark_comprehensive -s pke -e NIST_P384
DYLD_LIBRARY_PATH=../cli ./benchmark_comprehensive -s all --all-curves
```

**Options**:
- `-s, --scheme`: cpabe, pke, pksig, or all
- `-c, --curve`: BLS12_381, BN254, BN462, BLS12_461
- `-e, --ec-curve`: NIST_P256, NIST_P384, NIST_P521
- `-n, --iterations`: Number of iterations (default: 100)
- `-a, --all-curves`: Benchmark all supported curves

---

## Tested Configurations

### Valid Platform/Library Combinations

| Platform | Backend | Supported Curves | Notes |
|----------|---------|------------------|-------|
| **Native + RELIC** | RELIC 0.7.0 | BLS12_381, BN254, BN462, BLS12_461 | Default, most curves |
| **Native + MCL** | MCL 1.97+ | BLS12_381, BN254 | Modern C++, no GMP |
| **WASM + RELIC** | RELIC 0.7.0 | BLS12_381, BN254, BN462, BLS12_461 | Portable, needs wasmtime |
| **WASM + MCL** | MCL 1.97+ | BLS12_381, BN254 | Portable, needs wasmtime |

### Curve Characteristics

| Curve | Security Level | Performance | Standardization |
|-------|---------------|-------------|-----------------|
| **BLS12_381** | ~128-bit | Good | ✅ IETF standard |
| **BN254** | ~100-bit | Fastest | ⚠️ Weakened |
| **BN462** | ~128-bit | Slower | Academic |
| **BLS12_461** | ~128-bit | Slower | Academic |

**Recommendation**: Use BLS12_381 for new projects (standardized, secure, good performance)

---

## Benchmark Categories

### 1. CP-ABE (Ciphertext-Policy Attribute-Based Encryption)

**Operations Tested**:
- **Setup**: Parameter generation for ABE system
- **KeyGen**: User key generation with 3 attributes
- **Encrypt (simple)**: Single attribute policy
- **Encrypt (complex)**: Multi-attribute policy with AND/OR
- **Decrypt (matching)**: Successful decryption
- **Decrypt (non-matching)**: Policy mismatch detection

**Metrics**:
- Mean time (ms)
- Standard deviation
- Min/Max times
- Ciphertext size

### 2. PKE (Public Key Encryption)

**Operations Tested**:
- **KeyGen**: EC key pair generation
- **Encrypt**: ECIES encryption
- **Decrypt**: ECIES decryption

**Curves Tested**: NIST_P256, NIST_P384, NIST_P521

### 3. PKSIG (Digital Signatures)

**Operations Tested**:
- **KeyGen**: EC key pair generation
- **Sign**: ECDSA signature generation
- **Verify**: ECDSA signature verification

**Curves Tested**: NIST_P256, NIST_P384, NIST_P521

---

## Performance Factors

### Platform Impact (Native vs WASM)

**Native**:
- ✅ Direct hardware execution
- ✅ Full compiler optimizations
- ✅ Fastest performance
- ❌ Platform-specific binaries

**WASM**:
- ✅ Portable across platforms
- ✅ Sandboxed execution
- ❌ Virtualization overhead (~1.5-3x slower typical)
- ❌ Limited SIMD support

### Backend Impact (RELIC vs MCL)

**RELIC**:
- ✅ Mature, battle-tested (10+ years)
- ✅ Supports 4 curves (BLS12_381, BN254, BN462, BLS12_461)
- ✅ C-based, highly optimized
- ❌ Requires GMP dependency
- ❌ More complex build

**MCL**:
- ✅ Modern C++ (2015+)
- ✅ No GMP dependency
- ✅ Simpler build process
- ✅ Good BLS12_381 performance
- ❌ Only 2 curves (BLS12_381, BN254)
- ❌ Less mature ecosystem

---

## Interpreting Results

### Sample Output Format

```
=== Benchmark Results Summary ===
Operation                             Mean (ms)   StdDev      Min         Max
-----------------------------------------------------------------------------------
Setup (generateParams)                   15.23      1.45      13.20      18.50
Key Generation (3 attrs)                  8.34      0.67       7.50       9.80
Encryption (1 attr)                      12.45      0.89      11.20      14.10
Encryption (complex policy)              18.76      1.23      17.10      21.30
Decryption (matching)                    14.56      1.01      13.20      16.40
Decryption (non-matching)                 2.34      0.34       1.90       3.10

Ciphertext size: 1024 bytes
```

### What to Look For

1. **Mean Time**: Primary performance metric
   - Lower is better
   - Compare across configurations

2. **Standard Deviation**: Consistency
   - Lower is more predictable
   - High stddev may indicate system load

3. **Min/Max Range**: Performance bounds
   - Wide range may indicate GC, cache misses
   - Narrow range indicates consistent performance

4. **Ciphertext Size**: Storage overhead
   - Same across backends for given curve
   - Larger for complex policies

---

## Recommendations by Use Case

### For Production Deployment

**Recommended**: Native + RELIC + BLS12_381
- Most mature and tested
- Standardized curve
- Good performance/security balance

```bash
# Build for production
export ZML_LIB=""
cd deps && make -j4 && cd ../src && make -j4
```

### For Web/Browser Deployment

**Recommended**: WASM + RELIC + BLS12_381
- Portable across browsers
- Standardized curve
- Accept ~2x slowdown for portability

```bash
# Build for WASM
./build-wasm.sh
```

### For Simplified Dependencies

**Recommended**: Native + MCL + BLS12_381
- No GMP dependency
- Simpler build
- Good BLS12_381 performance

```bash
# Build with MCL
export ZML_LIB=with_mcl
cd deps && make -j4 && cd ../src && make -j4 ZML_LIB=with_mcl
```

### For Maximum Performance (if security allows)

**Recommended**: Native + RELIC + BN254
- Fastest curve operations
- Note: BN254 security weakened (use only for non-critical data)

```bash
# Build and test
./run-native-benchmarks.sh
# Then check BN254 results
```

---

## Quick Start Examples

### 1. Quick Native Comparison (RELIC vs MCL)

```bash
# Takes ~15 minutes, 50 iterations each
./run-native-benchmarks.sh

# View results
cat benchmark-results-native-*/COMPARISON_REPORT.md
```

### 2. Detailed Native Comparison

```bash
# Takes ~30 minutes, 100 iterations each
./run-native-benchmarks.sh -n 100

# View results
cat benchmark-results-native-*/COMPARISON_REPORT.md
```

### 3. Full Cross-Platform Comparison

```bash
# Requires wasmtime: brew install wasmtime
# Takes ~45-60 minutes

./run-cross-platform-benchmarks.sh

# View results
cat benchmark-results-*/COMPARISON_REPORT.md
```

### 4. Test Specific Scheme

```bash
# Build manually first
cd src && make benchmark_comprehensive

# Test only CP-ABE with BLS12_381
DYLD_LIBRARY_PATH=../cli ./benchmark_comprehensive \
    -s cpabe -c BLS12_381 -n 50

# Test only PKE with NIST_P384
DYLD_LIBRARY_PATH=../cli ./benchmark_comprehensive \
    -s pke -e NIST_P384 -n 50

# Test everything with all curves
DYLD_LIBRARY_PATH=../cli ./benchmark_comprehensive \
    -s all --all-curves -n 50
```

---

## Troubleshooting

### Build Failures

**Issue**: Dependencies fail to build
```bash
# Clean and rebuild
make clean
cd deps && make clean && cd ..
./run-native-benchmarks.sh
```

**Issue**: Compilation errors
```bash
# Check build logs
cat benchmark-results-*/build-*.log
```

### Performance Issues

**Issue**: High standard deviation
- Close other applications
- Run on AC power (not battery)
- Increase iterations: `-n 200`

**Issue**: Unexpectedly slow
- Check system load: `top`
- Disable energy-saving features
- Run multiple times and average

### WASM Issues

**Issue**: wasmtime not found
```bash
# Install wasmtime
brew install wasmtime

# Or download from: https://wasmtime.dev/
```

**Issue**: WASM tests fail
```bash
# Check WASM build logs
cat benchmark-results-*/build-wasm-*.log

# Try rebuilding WASM
./build-wasm.sh
```

---

## Advanced Usage

### Custom Comparison Script

```bash
#!/bin/bash
# Custom benchmark workflow

# Test specific configuration
export ZML_LIB=with_mcl
cd deps && make -j4
cd ../src && make -j4 ZML_LIB=with_mcl

# Build and run custom benchmark
clang++ -std=c++14 -O2 \
    -DBP_WITH_MCL -DSSL_LIB_INIT \
    -I./src/include -I./deps/root/include \
    -L./cli -L./deps/root/lib \
    your_benchmark.cpp \
    -lopenabe ./deps/root/lib/libmcl.a \
    -lssl -lcrypto \
    -o my_benchmark

DYLD_LIBRARY_PATH=./cli ./my_benchmark
```

### Automated CI/CD Testing

```yaml
# Example GitHub Actions workflow
name: Performance Benchmarks
on: [push]
jobs:
  benchmark:
    runs-on: macos-latest
    steps:
      - uses: actions/checkout@v3
      - name: Run benchmarks
        run: ./run-native-benchmarks.sh -n 50
      - name: Upload results
        uses: actions/upload-artifact@v3
        with:
          name: benchmark-results
          path: benchmark-results-*/
```

---

## Files Generated

Each benchmark run creates a timestamped directory with:

```
benchmark-results-YYYYMMDD_HHMMSS/
├── COMPARISON_REPORT.md           # Main comparison report
├── results-native-relic.txt       # Native + RELIC results
├── results-native-mcl.txt         # Native + MCL results
├── results-wasm-relic.txt         # WASM + RELIC results (if available)
├── results-wasm-mcl.txt           # WASM + MCL results (if available)
├── build-*.log                    # Build logs for debugging
├── compile-*.log                  # Compilation logs
├── benchmark_native_relic         # Benchmark binaries (executable)
└── benchmark_native_mcl           # Benchmark binaries (executable)
```

---

## Performance Baseline (Apple M3 Max, for reference)

**Native + RELIC + BLS12_381** (typical results, 50 iterations):
- Setup: ~12-15 ms
- KeyGen (3 attrs): ~7-9 ms
- Encrypt (simple): ~10-13 ms
- Decrypt (matching): ~12-16 ms

**Native + MCL + BLS12_381** (typical results, 50 iterations):
- Setup: ~10-13 ms
- KeyGen (3 attrs): ~6-8 ms
- Encrypt (simple): ~9-12 ms
- Decrypt (matching): ~11-15 ms

**WASM + RELIC + BLS12_381** (typical results, 50 iterations):
- Setup: ~25-35 ms (~2-2.5x slower)
- KeyGen (3 attrs): ~15-20 ms
- Encrypt (simple): ~22-28 ms
- Decrypt (matching): ~26-35 ms

*Note: Your results will vary based on hardware and system load*

---

## Support

For issues or questions:
1. Check build logs in `benchmark-results-*/build-*.log`
2. Review troubleshooting section above
3. Open an issue on GitHub with:
   - Platform (uname -a)
   - Build logs
   - Error messages

---

## Changelog

### Version 1.0 (2025-01-15)
- Initial release
- Native benchmarks (RELIC vs MCL)
- Cross-platform support (Native + WASM)
- Comprehensive CP-ABE, PKE, PKSIG benchmarks
- Automated build and comparison scripts
