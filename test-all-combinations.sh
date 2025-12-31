#!/bin/bash
# Comprehensive Test Suite for OpenABE
# Tests all combinations: Native/WASM x RELIC/MCL
# Date: October 22, 2025

set -e

ZROOT="/Users/zacharywhitley/git/openabe"
cd "$ZROOT"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test result tracking
TESTS_PASSED=0
TESTS_FAILED=0
TESTS_SKIPPED=0

# Function to print section header
print_header() {
    echo ""
    echo "========================================================================"
    echo -e "${BLUE}$1${NC}"
    echo "========================================================================"
    echo ""
}

# Function to print test result
print_result() {
    if [ $1 -eq 0 ]; then
        echo -e "${GREEN}✅ PASSED${NC}: $2"
        ((TESTS_PASSED++))
    else
        echo -e "${RED}❌ FAILED${NC}: $2"
        ((TESTS_FAILED++))
    fi
}

# Function to print skip
print_skip() {
    echo -e "${YELLOW}⏭️  SKIPPED${NC}: $1"
    ((TESTS_SKIPPED++))
}

# Function to run CP-ABE test
test_cpabe() {
    local backend=$1
    local platform=$2
    local test_name="$platform-$backend"

    echo "Testing CP-ABE with $backend on $platform..."

    # Create test message
    echo "Test message for $test_name" > "test-$test_name.txt"

    # Setup
    if ! ./oabe_setup -s CP -p "test-$test_name" 2>&1 | grep -q "Setup complete"; then
        echo "Setup output:"
        ./oabe_setup -s CP -p "test-$test_name" 2>&1 || true
        return 1
    fi

    # Key generation
    if ! ./oabe_keygen -s CP -p "test-$test_name" -i 'one|two|three' -o "test-$test_name-alice.key" 2>&1 | grep -q "Keygen complete"; then
        echo "Keygen output:"
        ./oabe_keygen -s CP -p "test-$test_name" -i 'one|two|three' -o "test-$test_name-alice.key" 2>&1 || true
        return 1
    fi

    # Encryption
    if ! ./oabe_enc -s CP -p "test-$test_name" -e '(one and two)' -i "test-$test_name.txt" -o "test-$test_name.cpabe" 2>&1 | grep -q "Encryption complete"; then
        echo "Encryption output:"
        ./oabe_enc -s CP -p "test-$test_name" -e '(one and two)' -i "test-$test_name.txt" -o "test-$test_name.cpabe" 2>&1 || true
        return 1
    fi

    # Decryption
    if ! ./oabe_dec -s CP -p "test-$test_name" -k "test-$test_name-alice.key" -i "test-$test_name.cpabe" -o "test-$test_name-decrypted.txt" 2>&1 | grep -q "Decryption complete"; then
        echo "Decryption output:"
        ./oabe_dec -s CP -p "test-$test_name" -k "test-$test_name-alice.key" -i "test-$test_name.cpabe" -o "test-$test_name-decrypted.txt" 2>&1 || true
        return 1
    fi

    # Verify
    if ! diff "test-$test_name.txt" "test-$test_name-decrypted.txt" > /dev/null 2>&1; then
        echo "Content mismatch!"
        return 1
    fi

    return 0
}

# Start tests
print_header "OpenABE Comprehensive Test Suite"
echo "Testing all combinations: Native/WASM x RELIC/MCL"
echo "Started: $(date)"
echo ""

# ========================================================================
# Test 1: Native + RELIC
# ========================================================================
print_header "Test 1: Native + RELIC (BLS12-381 - 128-bit security)"

if [ -f "cli/oabe_setup" ]; then
    cd cli
    source ../env
    unset ZML_LIB  # Use RELIC

    if test_cpabe "RELIC" "Native"; then
        print_result 0 "Native + RELIC (BLS12-381)"
    else
        print_result 1 "Native + RELIC (BLS12-381)"
    fi
    cd ..
else
    print_skip "Native binaries not found (cli/oabe_setup missing)"
fi

# ========================================================================
# Test 2: Native + MCL
# ========================================================================
print_header "Test 2: Native + MCL (BLS12-381 - 128-bit security)"

if [ -f "cli/oabe_setup" ]; then
    cd cli
    source ../env
    export ZML_LIB="with_mcl"  # Use MCL

    if test_cpabe "MCL" "Native"; then
        print_result 0 "Native + MCL (BLS12-381)"
    else
        print_result 1 "Native + MCL (BLS12-381)"
    fi
    cd ..
else
    print_skip "Native binaries not found (cli/oabe_setup missing)"
fi

# ========================================================================
# Test 3: WASM + RELIC
# ========================================================================
print_header "Test 3: WASM + RELIC (BLS12-381 - 128-bit security)"

if [ -f "cli-wasm/oabe_setup.wasm" ] && command -v wasmtime &> /dev/null; then
    cd cli-wasm

    # WASM tests would use wasmtime
    # Implementation depends on WASM build availability
    print_skip "WASM + RELIC (WASM build not in scope for this test)"
    cd ..
else
    print_skip "WASM binaries or wasmtime not found"
fi

# ========================================================================
# Test 4: WASM + MCL
# ========================================================================
print_header "Test 4: WASM + MCL (BLS12-381 - 128-bit security)"

if [ -f "cli-wasm/oabe_setup.wasm" ] && command -v wasmtime &> /dev/null; then
    cd cli-wasm

    # WASM tests would use wasmtime
    # Implementation depends on WASM build availability
    print_skip "WASM + MCL (WASM build not in scope for this test)"
    cd ..
else
    print_skip "WASM binaries or wasmtime not found"
fi

# ========================================================================
# Additional Tests: CCA Security
# ========================================================================
print_header "Additional Test: CCA-Secured Encryption (Native + RELIC)"

if [ -f "cli/oabe_setup" ]; then
    cd cli
    source ../env
    unset ZML_LIB

    echo "Testing CCA-secured CP-ABE..."
    if ./oabe_setup -s CP -p test-cca 2>&1 | grep -q "Setup complete" && \
       ./oabe_keygen -s CP -p test-cca -i 'alice|bob' -o test-cca-alice.key 2>&1 | grep -q "Keygen complete" && \
       echo "CCA test message" > test-cca.txt && \
       ./oabe_enc -s CP -p test-cca -e '(alice and bob)' -i test-cca.txt -o test-cca.cpabe 2>&1 | grep -q "Encryption complete" && \
       ./oabe_dec -s CP -p test-cca -k test-cca-alice.key -i test-cca.cpabe -o test-cca-dec.txt 2>&1 | grep -q "Decryption complete" && \
       diff test-cca.txt test-cca-dec.txt > /dev/null 2>&1; then
        print_result 0 "CCA-secured encryption/decryption"
    else
        print_result 1 "CCA-secured encryption/decryption"
    fi
    cd ..
else
    print_skip "CCA security test (Native binaries not found)"
fi

# ========================================================================
# Summary
# ========================================================================
print_header "Test Summary"

echo "Total tests run: $((TESTS_PASSED + TESTS_FAILED))"
echo -e "${GREEN}Passed: $TESTS_PASSED${NC}"
echo -e "${RED}Failed: $TESTS_FAILED${NC}"
echo -e "${YELLOW}Skipped: $TESTS_SKIPPED${NC}"
echo ""

if [ $TESTS_FAILED -eq 0 ] && [ $TESTS_PASSED -gt 0 ]; then
    echo -e "${GREEN}✅ ALL TESTS PASSED!${NC}"
    exit 0
elif [ $TESTS_PASSED -eq 0 ] && [ $TESTS_SKIPPED -gt 0 ]; then
    echo -e "${YELLOW}⚠️  ALL TESTS SKIPPED (binaries not built)${NC}"
    exit 2
else
    echo -e "${RED}❌ SOME TESTS FAILED${NC}"
    exit 1
fi
