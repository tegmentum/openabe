#!/bin/bash
# Cross-Platform and Cross-Library Performance Comparison
# Tests all valid combinations of platform (Native/WASM) and library (RELIC/MCL)

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
RESULTS_DIR="$ZROOT/benchmark-results-$TIMESTAMP"
mkdir -p "$RESULTS_DIR"

ITERATIONS=50  # Default iterations (faster for comprehensive testing)

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
            echo "  3. Build WASM + RELIC (if wasmtime available)"
            echo "  4. Build WASM + MCL (if wasmtime available)"
            echo "  5. Run comprehensive benchmarks for each combination"
            echo "  6. Generate comparison report"
            exit 0
            ;;
        *)
            error "Unknown option: $1"
            exit 1
            ;;
    esac
done

info "========================================="
info "Cross-Platform Performance Comparison"
info "========================================="
echo ""
info "Results will be saved to: $RESULTS_DIR"
info "Iterations per benchmark: $ITERATIONS"
echo ""

# Check if wasmtime is available
HAS_WASMTIME=false
if command -v wasmtime &> /dev/null; then
    HAS_WASMTIME=true
    info "wasmtime detected - WASM benchmarks will be included"
else
    warn "wasmtime not found - WASM benchmarks will be skipped"
    warn "Install with: brew install wasmtime"
fi
echo ""

# ============================================================================
# NATIVE + RELIC
# ============================================================================
step "1/4 Building and testing: Native + RELIC"
echo ""

info "Cleaning previous builds..."
make clean > /dev/null 2>&1 || true
cd deps && make clean > /dev/null 2>&1 || true
cd "$ZROOT"

info "Building Native + RELIC..."
export ZML_LIB=""
export ZROOT="$ZROOT"

cd deps
if ! make -j4 > "$RESULTS_DIR/build-native-relic-deps.log" 2>&1; then
    error "Failed to build dependencies for Native + RELIC"
    error "See log: $RESULTS_DIR/build-native-relic-deps.log"
    exit 1
fi
cd "$ZROOT/src"

if ! make -j4 > "$RESULTS_DIR/build-native-relic-src.log" 2>&1; then
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
step "2/4 Building and testing: Native + MCL"
echo ""

info "Cleaning previous builds..."
make clean > /dev/null 2>&1 || true
cd deps && make clean > /dev/null 2>&1 || true
cd "$ZROOT"

info "Building Native + MCL..."
export ZML_LIB="with_mcl"
export ZROOT="$ZROOT"

cd deps
if ! make -j4 > "$RESULTS_DIR/build-native-mcl-deps.log" 2>&1; then
    error "Failed to build dependencies for Native + MCL"
    error "See log: $RESULTS_DIR/build-native-mcl-deps.log"
    exit 1
fi
cd "$ZROOT/src"

if ! make -j4 ZML_LIB=with_mcl > "$RESULTS_DIR/build-native-mcl-src.log" 2>&1; then
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
# WASM + RELIC (if wasmtime available)
# ============================================================================
if [ "$HAS_WASMTIME" = true ]; then
    step "3/4 Building and testing: WASM + RELIC"
    echo ""

    info "Cleaning previous builds..."
    rm -rf build-wasm cli-wasm 2>/dev/null || true

    info "Building WASM + RELIC..."
    export ZML_LIB=""

    if ! ./build-wasm.sh > "$RESULTS_DIR/build-wasm-relic.log" 2>&1; then
        error "Failed to build WASM + RELIC"
        error "See log: $RESULTS_DIR/build-wasm-relic.log"
        exit 1
    fi

    # Build WASM benchmark
    info "Building WASM benchmark for RELIC..."
    if ! ./build-cli-wasm.sh benchmark_comprehensive \
        > "$RESULTS_DIR/build-wasm-relic-benchmark.log" 2>&1; then
        error "Failed to build WASM benchmark for RELIC"
        error "See log: $RESULTS_DIR/build-wasm-relic-benchmark.log"
        exit 1
    fi

    if [ -f "cli-wasm/benchmark_comprehensive.wasm" ]; then
        info "Running benchmarks for WASM + RELIC..."
        wasmtime cli-wasm/benchmark_comprehensive.wasm \
            -- -s all -a -n $ITERATIONS \
            > "$RESULTS_DIR/results-wasm-relic.txt" 2>&1 || true
        info "✓ WASM + RELIC complete"
    else
        warn "WASM benchmark binary not found, skipping WASM + RELIC tests"
    fi
    echo ""
else
    warn "Skipping WASM + RELIC (wasmtime not available)"
    echo ""
fi

# ============================================================================
# WASM + MCL (if wasmtime available)
# ============================================================================
if [ "$HAS_WASMTIME" = true ]; then
    step "4/4 Building and testing: WASM + MCL"
    echo ""

    info "Cleaning previous builds..."
    rm -rf build-wasm cli-wasm 2>/dev/null || true

    info "Building WASM + MCL..."
    export ZML_LIB="with_mcl"

    if ! ZML_LIB=with_mcl ./build-wasm.sh > "$RESULTS_DIR/build-wasm-mcl.log" 2>&1; then
        error "Failed to build WASM + MCL"
        error "See log: $RESULTS_DIR/build-wasm-mcl.log"
        exit 1
    fi

    # Build WASM benchmark
    info "Building WASM benchmark for MCL..."
    if ! ZML_LIB=with_mcl ./build-cli-wasm.sh benchmark_comprehensive \
        > "$RESULTS_DIR/build-wasm-mcl-benchmark.log" 2>&1; then
        error "Failed to build WASM benchmark for MCL"
        error "See log: $RESULTS_DIR/build-wasm-mcl-benchmark.log"
        exit 1
    fi

    if [ -f "cli-wasm/benchmark_comprehensive.wasm" ]; then
        info "Running benchmarks for WASM + MCL..."
        wasmtime cli-wasm/benchmark_comprehensive.wasm \
            -- -s all -a -n $ITERATIONS \
            > "$RESULTS_DIR/results-wasm-mcl.txt" 2>&1 || true
        info "✓ WASM + MCL complete"
    else
        warn "WASM benchmark binary not found, skipping WASM + MCL tests"
    fi
    echo ""
else
    warn "Skipping WASM + MCL (wasmtime not available)"
    echo ""
fi

# ============================================================================
# Generate Comparison Report
# ============================================================================
step "Generating comparison report..."
echo ""

cat > "$RESULTS_DIR/COMPARISON_REPORT.md" << 'REPORT_START'
# OpenABE Cross-Platform Performance Comparison

## Test Configuration

REPORT_START

echo "- **Date**: $(date)" >> "$RESULTS_DIR/COMPARISON_REPORT.md"
echo "- **Iterations**: $ITERATIONS per benchmark" >> "$RESULTS_DIR/COMPARISON_REPORT.md"
echo "- **Platform**: $(uname -s) $(uname -m)" >> "$RESULTS_DIR/COMPARISON_REPORT.md"
echo "" >> "$RESULTS_DIR/COMPARISON_REPORT.md"

cat >> "$RESULTS_DIR/COMPARISON_REPORT.md" << 'REPORT_MIDDLE'
## Tested Combinations

### Native Builds
1. **Native + RELIC** (default configuration)
   - Pairing library: RELIC 0.7.0
   - Supported curves: BLS12_381, BN254, BN462, BLS12_461
   - EC library: OpenSSL 3.3.2

2. **Native + MCL**
   - Pairing library: MCL
   - Supported curves: BLS12_381, BN254
   - EC library: OpenSSL 3.3.2

REPORT_MIDDLE

if [ "$HAS_WASMTIME" = true ]; then
    cat >> "$RESULTS_DIR/COMPARISON_REPORT.md" << 'REPORT_WASM'
### WASM Builds
3. **WASM + RELIC**
   - Platform: WebAssembly/WASI
   - Pairing library: RELIC 0.7.0
   - Supported curves: BLS12_381, BN254, BN462, BLS12_461

4. **WASM + MCL**
   - Platform: WebAssembly/WASI
   - Pairing library: MCL
   - Supported curves: BLS12_381, BN254

REPORT_WASM
fi

echo "" >> "$RESULTS_DIR/COMPARISON_REPORT.md"
echo "## Detailed Results" >> "$RESULTS_DIR/COMPARISON_REPORT.md"
echo "" >> "$RESULTS_DIR/COMPARISON_REPORT.md"

# Add links to detailed results
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

if [ "$HAS_WASMTIME" = true ]; then
    echo "### WASM + RELIC" >> "$RESULTS_DIR/COMPARISON_REPORT.md"
    echo '```' >> "$RESULTS_DIR/COMPARISON_REPORT.md"
    cat "$RESULTS_DIR/results-wasm-relic.txt" >> "$RESULTS_DIR/COMPARISON_REPORT.md" 2>/dev/null || echo "Results not available" >> "$RESULTS_DIR/COMPARISON_REPORT.md"
    echo '```' >> "$RESULTS_DIR/COMPARISON_REPORT.md"
    echo "" >> "$RESULTS_DIR/COMPARISON_REPORT.md"

    echo "### WASM + MCL" >> "$RESULTS_DIR/COMPARISON_REPORT.md"
    echo '```' >> "$RESULTS_DIR/COMPARISON_REPORT.md"
    cat "$RESULTS_DIR/results-wasm-mcl.txt" >> "$RESULTS_DIR/COMPARISON_REPORT.md" 2>/dev/null || echo "Results not available" >> "$RESULTS_DIR/COMPARISON_REPORT.md"
    echo '```' >> "$RESULTS_DIR/COMPARISON_REPORT.md"
    echo "" >> "$RESULTS_DIR/COMPARISON_REPORT.md"
fi

cat >> "$RESULTS_DIR/COMPARISON_REPORT.md" << 'REPORT_END'
## Analysis Notes

### Performance Factors

1. **Platform Impact (Native vs WASM)**
   - Native code runs directly on hardware
   - WASM adds virtualization overhead
   - WASM may have different optimization characteristics

2. **Library Impact (RELIC vs MCL)**
   - RELIC: Mature, C-based, supports more curves
   - MCL: Modern C++, focused on BLS12/BN curves
   - Different optimization strategies

3. **Curve Impact**
   - BLS12_381: Modern, standardized, good performance
   - BN254: Faster operations, older standard
   - BN462/BLS12_461: Higher security level, slower

### Recommendations

- **For maximum performance**: Use Native + fastest curve combination
- **For portability**: Use WASM builds
- **For standardization**: Use BLS12_381
- **For maximum security**: Use BN462 or BLS12_461

REPORT_END

info "✓ Comparison report generated: $RESULTS_DIR/COMPARISON_REPORT.md"
echo ""

# ============================================================================
# Summary
# ============================================================================
info "========================================="
info "All benchmarks complete!"
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

# Generate quick summary
info "Quick Summary:"
echo ""
for result_file in "$RESULTS_DIR"/results-*.txt; do
    if [ -f "$result_file" ]; then
        config=$(basename "$result_file" .txt | sed 's/results-//')
        echo "=== $config ==="
        grep -A 1 "Platform:" "$result_file" 2>/dev/null || echo "Platform info not available"
        grep -A 1 "Backend:" "$result_file" 2>/dev/null || echo "Backend info not available"
        echo ""
    fi
done
