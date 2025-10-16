#!/bin/bash
# Native-Only Performance Comparison (RELIC vs MCL)
# Faster version that only tests native builds

set -e

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

info() { echo -e "${GREEN}[INFO]${NC} $1"; }
step() { echo -e "${BLUE}[STEP]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; }

ZROOT="$(pwd)"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
RESULTS_DIR="$ZROOT/benchmark-results-native-$TIMESTAMP"
mkdir -p "$RESULTS_DIR"

ITERATIONS=50  # Default iterations

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -n|--iterations)
            ITERATIONS="$2"
            shift 2
            ;;
        -h|--help)
            echo "Usage: $0 [options]"
            echo ""
            echo "Options:"
            echo "  -n, --iterations N    Number of iterations per benchmark (default: 50)"
            echo "  -h, --help            Show this help message"
            echo ""
            echo "This script will:"
            echo "  1. Build Native + RELIC"
            echo "  2. Build Native + MCL"
            echo "  3. Run comprehensive benchmarks for both"
            echo "  4. Generate comparison report"
            exit 0
            ;;
        *)
            error "Unknown option: $1"
            exit 1
            ;;
    esac
done

info "========================================="
info "Native Performance Comparison (RELIC vs MCL)"
info "========================================="
echo ""
info "Results will be saved to: $RESULTS_DIR"
info "Iterations per benchmark: $ITERATIONS"
echo ""

# ============================================================================
# NATIVE + RELIC
# ============================================================================
step "1/2 Building and testing: Native + RELIC"
echo ""

info "Building Native + RELIC (clean build)..."
# Clean source directory
cd "$ZROOT/src"
make clean > /dev/null 2>&1 || true
cd "$ZROOT"

# Clean OpenABE build artifacts
info "Cleaning OpenABE build artifacts..."
rm -f src/libopenabe.a src/libzsym.a 2>/dev/null || true
rm -rf root/include/openabe root/lib/libopenabe.* root/lib/libzsym.* 2>/dev/null || true

# Clean and rebuild deps for RELIC
info "Cleaning and rebuilding dependencies for Native + RELIC..."
export ZML_LIB=""
export ZROOT="$ZROOT"

cd deps
# Clean RELIC-specific build artifacts
make -C relic clean > /dev/null 2>&1 || true
# Rebuild all deps
if ! make -j4 > "$RESULTS_DIR/build-native-relic-deps.log" 2>&1; then
    error "Failed to build dependencies for Native + RELIC"
    error "See log: $RESULTS_DIR/build-native-relic-deps.log"
    exit 1
fi
cd "$ZROOT/src"

# Build just the libraries, not the test programs (which require gtest)
if ! make -j4 libopenabe.a libzsym.a > "$RESULTS_DIR/build-native-relic-src.log" 2>&1; then
    error "Failed to build source for Native + RELIC"
    error "See log: $RESULTS_DIR/build-native-relic-src.log"
    exit 1
fi
cd "$ZROOT"

info "Building benchmark for Native + RELIC..."
if ! clang++ -std=c++14 -O2 \
    -I./src/include -I./deps/root/include -I/opt/homebrew/include \
    -L./cli -L./deps/root/lib -L/opt/homebrew/lib \
    ./src/benchmark_comprehensive.cpp \
    -lopenabe -lrelic_s -lgmpxx -lgmp -lssl -lcrypto \
    -o "$RESULTS_DIR/benchmark_native_relic" > "$RESULTS_DIR/compile-native-relic.log" 2>&1; then
    error "Failed to compile benchmark for Native + RELIC"
    error "See log: $RESULTS_DIR/compile-native-relic.log"
    exit 1
fi

info "Running benchmarks for Native + RELIC..."
DYLD_LIBRARY_PATH=./cli "$RESULTS_DIR/benchmark_native_relic" \
    -s all -a -n $ITERATIONS \
    > "$RESULTS_DIR/results-native-relic.txt" 2>&1
info "✓ Native + RELIC complete"
echo ""

# ============================================================================
# NATIVE + MCL
# ============================================================================
step "2/2 Building and testing: Native + MCL"
echo ""

info "Rebuilding for Native + MCL..."
# Clean source directory
cd "$ZROOT/src"
make clean > /dev/null 2>&1 || true
cd "$ZROOT"

# Clean OpenABE build artifacts
info "Cleaning OpenABE build artifacts..."
rm -f src/libopenabe.a src/libzsym.a 2>/dev/null || true
rm -rf root/include/openabe root/lib/libopenabe.* root/lib/libzsym.* 2>/dev/null || true

# Clean and rebuild deps for MCL
info "Cleaning and rebuilding dependencies for Native + MCL..."
export ZML_LIB="with_mcl"
export ZROOT="$ZROOT"

cd deps
# Clean MCL-specific build artifacts
make -C mcl clean > /dev/null 2>&1 || true
# Rebuild all deps
if ! make -j4 > "$RESULTS_DIR/build-native-mcl-deps.log" 2>&1; then
    error "Failed to build dependencies for Native + MCL"
    error "See log: $RESULTS_DIR/build-native-mcl-deps.log"
    exit 1
fi
cd "$ZROOT/src"

# Build just the libraries, not the test programs (which require gtest)
if ! make -j4 ZML_LIB=with_mcl libopenabe.a libzsym.a > "$RESULTS_DIR/build-native-mcl-src.log" 2>&1; then
    error "Failed to build source for Native + MCL"
    error "See log: $RESULTS_DIR/build-native-mcl-src.log"
    exit 1
fi
cd "$ZROOT"

info "Building benchmark for Native + MCL..."
if ! clang++ -std=c++14 -O2 \
    -DBP_WITH_MCL -DSSL_LIB_INIT -DEC_WITH_OPENSSL \
    -I./src/include -I./deps/root/include -I/opt/homebrew/include \
    -L./cli -L./deps/root/lib -L/opt/homebrew/lib \
    ./src/benchmark_comprehensive.cpp \
    -lopenabe ./deps/root/lib/libmcl.a ./deps/root/lib/libmclecdsa.a \
    -lssl -lcrypto \
    -o "$RESULTS_DIR/benchmark_native_mcl" > "$RESULTS_DIR/compile-native-mcl.log" 2>&1; then
    error "Failed to compile benchmark for Native + MCL"
    error "See log: $RESULTS_DIR/compile-native-mcl.log"
    exit 1
fi

info "Running benchmarks for Native + MCL..."
DYLD_LIBRARY_PATH=./cli "$RESULTS_DIR/benchmark_native_mcl" \
    -s all -a -n $ITERATIONS \
    > "$RESULTS_DIR/results-native-mcl.txt" 2>&1
info "✓ Native + MCL complete"
echo ""

# ============================================================================
# Generate Comparison Report
# ============================================================================
step "Generating comparison report..."
echo ""

cat > "$RESULTS_DIR/COMPARISON_REPORT.md" << 'REPORT_START'
# OpenABE Native Performance Comparison (RELIC vs MCL)

## Test Configuration

REPORT_START

echo "- **Date**: $(date)" >> "$RESULTS_DIR/COMPARISON_REPORT.md"
echo "- **Iterations**: $ITERATIONS per benchmark" >> "$RESULTS_DIR/COMPARISON_REPORT.md"
echo "- **Platform**: $(uname -s) $(uname -m)" >> "$RESULTS_DIR/COMPARISON_REPORT.md"
echo "" >> "$RESULTS_DIR/COMPARISON_REPORT.md"

cat >> "$RESULTS_DIR/COMPARISON_REPORT.md" << 'REPORT_MIDDLE'
## Tested Configurations

### 1. Native + RELIC (default)
- **Pairing library**: RELIC 0.7.0
- **Supported curves**: BLS12_381, BN254, BN462, BLS12_461
- **EC library**: OpenSSL 3.3.2
- **Advantages**: Mature, supports more curves, well-tested
- **Build**: Default OpenABE configuration

### 2. Native + MCL
- **Pairing library**: MCL (Modern Cryptography Library)
- **Supported curves**: BLS12_381, BN254
- **EC library**: OpenSSL 3.3.2
- **Advantages**: Modern C++, potentially faster on some curves
- **Build**: ZML_LIB=with_mcl

## Detailed Results

REPORT_MIDDLE

echo "### Native + RELIC" >> "$RESULTS_DIR/COMPARISON_REPORT.md"
echo '```' >> "$RESULTS_DIR/COMPARISON_REPORT.md"
cat "$RESULTS_DIR/results-native-relic.txt" >> "$RESULTS_DIR/COMPARISON_REPORT.md" 2>/dev/null || echo "Results not available" >> "$RESULTS_DIR/COMPARISON_REPORT.md"
echo '```' >> "$RESULTS_DIR/COMPARISON_REPORT.md"
echo "" >> "$RESULTS_DIR/COMPARISON_REPORT.md"

echo "### Native + MCL" >> "$RESULTS_DIR/COMPARISON_REPORT.md"
echo '```' >> "$RESULTS_DIR/COMPARISON_REPORT.md"
cat "$RESULTS_DIR/results-native-mcl.txt" >> "$RESULTS_DIR/COMPARISON_REPORT.md" 2>/dev/null || echo "Results not available" >> "$RESULTS_DIR/COMPARISON_REPORT.md"
echo '```' >> "$RESULTS_DIR/COMPARISON_REPORT.md"
echo "" >> "$RESULTS_DIR/COMPARISON_REPORT.md"

cat >> "$RESULTS_DIR/COMPARISON_REPORT.md" << 'REPORT_END'
## Performance Analysis

### Key Metrics Compared

1. **CP-ABE Operations**
   - Setup (parameter generation)
   - Key generation (3 attributes)
   - Encryption (simple 1-attr and complex policy)
   - Decryption (matching and non-matching)

2. **PKE Operations** (Public Key Encryption)
   - Key generation
   - Encryption
   - Decryption

3. **PKSIG Operations** (Digital Signatures)
   - Key generation
   - Signing
   - Verification

### Factors to Consider

1. **Library Maturity**
   - RELIC: Battle-tested, default choice
   - MCL: Newer, potentially different performance characteristics

2. **Curve Support**
   - RELIC: Supports BN462, BLS12_461 for higher security
   - MCL: Focused on BLS12_381, BN254

3. **Build Complexity**
   - RELIC: Requires GMP dependency
   - MCL: No GMP dependency needed

### Recommendations

- **For production use**: Test both libraries with your specific workload
- **For standardization**: BLS12_381 is well-supported by both
- **For maximum curve options**: Use RELIC
- **For simpler dependency management**: Consider MCL

REPORT_END

info "✓ Comparison report generated: $RESULTS_DIR/COMPARISON_REPORT.md"
echo ""

# ============================================================================
# Summary
# ============================================================================
info "========================================="
info "Benchmarks complete!"
info "========================================="
echo ""
info "Results saved to: $RESULTS_DIR/"
echo ""
info "Files generated:"
ls -lh "$RESULTS_DIR/" | grep -v "^total" | awk '{print "  - " $9 " (" $5 ")"}'
echo ""
info "View the comparison report:"
echo "  cat $RESULTS_DIR/COMPARISON_REPORT.md"
echo ""
info "Or open it in your browser:"
echo "  open $RESULTS_DIR/COMPARISON_REPORT.md"
echo ""
