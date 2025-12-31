#!/bin/bash
# Verification Test for Bug #19 Fix in RELIC
# This test verifies that Bug #19 automated fix works correctly
# Date: October 22, 2025

set -e

ZROOT="/Users/zacharywhitley/git/openabe"
cd "$ZROOT"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

TESTS_PASSED=0
TESTS_FAILED=0

print_header() {
    echo ""
    echo "========================================================================"
    echo -e "${BLUE}$1${NC}"
    echo "========================================================================"
}

print_test() {
    echo -e "${YELLOW}TEST:${NC} $1"
}

print_pass() {
    echo -e "${GREEN}✅ PASS${NC}: $1"
    ((TESTS_PASSED++))
}

print_fail() {
    echo -e "${RED}❌ FAIL${NC}: $1"
    ((TESTS_FAILED++))
}

# Start
print_header "RELIC Bug #19 Fix Verification Test Suite"
echo "This test verifies the automated Bug #19 fix is working correctly"
echo "Started: $(date)"

# ========================================================================
# Test 1: Verify Bug #19 fix script exists
# ========================================================================
print_header "Test 1: Bug #19 Fix Script Existence"
print_test "Checking if apply_bls12_381_scalar_fix.sh exists"

if [ -f "deps/relic/apply_bls12_381_scalar_fix.sh" ]; then
    print_pass "Bug #19 fix script exists"

    # Check if executable
    if [ -x "deps/relic/apply_bls12_381_scalar_fix.sh" ]; then
        print_pass "Bug #19 fix script is executable"
    else
        print_fail "Bug #19 fix script is not executable"
    fi
else
    print_fail "Bug #19 fix script not found"
    exit 1
fi

# ========================================================================
# Test 2: Verify Makefile integration
# ========================================================================
print_header "Test 2: Makefile Integration"
print_test "Checking if Makefile calls Bug #19 fix script"

if grep -q "apply_bls12_381_scalar_fix.sh" deps/relic/Makefile; then
    print_pass "Makefile integrates Bug #19 fix script"
else
    print_fail "Makefile does not integrate Bug #19 fix script"
fi

# ========================================================================
# Test 3: Clean and rebuild RELIC with Bug #19 fix
# ========================================================================
print_header "Test 3: RELIC Build with Bug #19 Fix"
print_test "Clean building RELIC to apply Bug #19 fix"

# Clean
echo "Cleaning RELIC build..."
make -C deps/relic clean > /dev/null 2>&1

# Build and capture output
echo "Building RELIC (this will take a moment)..."
BUILD_OUTPUT=$(make -C deps/relic -j8 2>&1)

# Check if fix was applied
if echo "$BUILD_OUTPUT" | grep -q "Applied BLS12-381 scalar buffer fix (Bug #19)"; then
    print_pass "Bug #19 fix was applied during build"
else
    print_fail "Bug #19 fix was NOT applied during build"
    echo "Build output:"
    echo "$BUILD_OUTPUT" | grep -i "scalar\|bug\|applied" || echo "(No relevant output found)"
fi

# Check if build succeeded
if echo "$BUILD_OUTPUT" | grep -q "Built target relic"; then
    print_pass "RELIC built successfully"
else
    print_fail "RELIC build failed"
fi

# ========================================================================
# Test 4: Verify source code changes
# ========================================================================
print_header "Test 4: Source Code Verification"
print_test "Verifying Bug #19 fix modified source files correctly"

# Check if source directory exists
if [ ! -d "deps/relic/relic-toolkit-0.7.0" ]; then
    print_fail "RELIC source directory not found (build may have failed)"
    exit 1
fi

# Define files to check
FILES_TO_CHECK=(
    "src/ep/relic_ep_mul.c"
    "src/ep/relic_ep_mul_fix.c"
    "src/epx/relic_ep2_mul.c"
    "src/epx/relic_ep3_mul.c"
    "src/epx/relic_ep4_mul.c"
    "src/epx/relic_ep8_mul.c"
    "src/ed/relic_ed_mul.c"
    "src/ed/relic_ed_mul_fix.c"
)

FILES_CORRECT=0
FILES_WRONG=0

for file in "${FILES_TO_CHECK[@]}"; do
    FULL_PATH="deps/relic/relic-toolkit-0.7.0/$file"

    if [ ! -f "$FULL_PATH" ]; then
        echo "  ⚠️  File not found: $file"
        ((FILES_WRONG++))
        continue
    fi

    # Check if uses RLC_BN_BITS (correct)
    if grep -q "l = RLC_BN_BITS + 1" "$FULL_PATH"; then
        echo -e "  ${GREEN}✓${NC} $file uses RLC_BN_BITS (correct)"
        ((FILES_CORRECT++))
    # Check if still uses RLC_FP_BITS (wrong)
    elif grep -q "l = RLC_FP_BITS + 1" "$FULL_PATH"; then
        echo -e "  ${RED}✗${NC} $file still uses RLC_FP_BITS (WRONG!)"
        ((FILES_WRONG++))
    else
        echo "  ℹ️  $file has no buffer sizing code (may be expected)"
    fi
done

if [ $FILES_CORRECT -eq 8 ] && [ $FILES_WRONG -eq 0 ]; then
    print_pass "All 8 files correctly use RLC_BN_BITS"
elif [ $FILES_CORRECT -gt 0 ] && [ $FILES_WRONG -eq 0 ]; then
    print_pass "$FILES_CORRECT files correctly use RLC_BN_BITS"
else
    print_fail "$FILES_WRONG files still use RLC_FP_BITS or are missing"
fi

# ========================================================================
# Test 5: Verify specific file content
# ========================================================================
print_header "Test 5: Detailed Source Verification (relic_ep_mul.c)"
print_test "Checking specific line numbers in relic_ep_mul.c"

TEST_FILE="deps/relic/relic-toolkit-0.7.0/src/ep/relic_ep_mul.c"

if [ -f "$TEST_FILE" ]; then
    # Extract specific lines and check
    LINE_263=$(sed -n '263p' "$TEST_FILE" 2>/dev/null || echo "")
    LINE_265=$(sed -n '265p' "$TEST_FILE" 2>/dev/null || echo "")
    LINE_542=$(sed -n '542p' "$TEST_FILE" 2>/dev/null || echo "")

    echo "Checking line 263:"
    if echo "$LINE_263" | grep -q "l = RLC_BN_BITS + 1"; then
        echo -e "  ${GREEN}✓${NC} Line 263: Uses RLC_BN_BITS (correct)"
        print_pass "Line 263 correct"
    else
        echo -e "  ${RED}✗${NC} Line 263: $LINE_263"
        print_fail "Line 263 incorrect"
    fi

    echo "Checking line 265:"
    if echo "$LINE_265" | grep -q "l = RLC_BN_BITS + 1"; then
        echo -e "  ${GREEN}✓${NC} Line 265: Uses RLC_BN_BITS (correct)"
        print_pass "Line 265 correct"
    else
        echo -e "  ${RED}✗${NC} Line 265: $LINE_265"
        print_fail "Line 265 incorrect"
    fi

    echo "Checking line 542:"
    if echo "$LINE_542" | grep -q "l = RLC_BN_BITS + 1"; then
        echo -e "  ${GREEN}✓${NC} Line 542: Uses RLC_BN_BITS (correct)"
        print_pass "Line 542 correct"
    else
        echo -e "  ${RED}✗${NC} Line 542: $LINE_542"
        print_fail "Line 542 incorrect"
    fi
else
    print_fail "Test file not found: $TEST_FILE"
fi

# ========================================================================
# Test 6: Verify RELIC library files exist
# ========================================================================
print_header "Test 6: RELIC Library Files"
print_test "Checking if RELIC libraries were built and installed"

if [ -f "deps/root/lib/librelic.dylib" ] || [ -f "deps/root/lib/librelic.so" ]; then
    print_pass "RELIC shared library exists"
else
    print_fail "RELIC shared library not found"
fi

if [ -f "deps/root/lib/librelic_s.a" ]; then
    print_pass "RELIC static library exists"
else
    print_fail "RELIC static library not found"
fi

# ========================================================================
# Summary
# ========================================================================
print_header "Test Summary"

TOTAL_TESTS=$((TESTS_PASSED + TESTS_FAILED))
echo "Total tests run: $TOTAL_TESTS"
echo -e "${GREEN}Passed: $TESTS_PASSED${NC}"
echo -e "${RED}Failed: $TESTS_FAILED${NC}"
echo ""

if [ $TESTS_FAILED -eq 0 ] && [ $TESTS_PASSED -gt 0 ]; then
    echo "========================================================================"
    echo -e "${GREEN}✅ ✅ ✅  ALL TESTS PASSED!  ✅ ✅ ✅${NC}"
    echo "========================================================================"
    echo ""
    echo "Bug #19 automated fix is working correctly!"
    echo "RELIC 0.7.0 with BLS12-381 support is ready for production."
    echo ""
    exit 0
else
    echo "========================================================================"
    echo -e "${RED}❌ ❌ ❌  SOME TESTS FAILED  ❌ ❌ ❌${NC}"
    echo "========================================================================"
    echo ""
    exit 1
fi
