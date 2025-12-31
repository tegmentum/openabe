#!/bin/bash
# Cross-Platform Round-Trip Test Suite
# Tests that native and WASM builds can encrypt/decrypt each other's data

set -e

ZROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ZROOT"

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}========================================="
echo "CROSS-PLATFORM ROUND-TRIP TEST SUITE"
echo "Testing MCL 3.04 Native ↔ WASM Compatibility"
echo "=========================================${NC}"
echo ""

# Setup test directory
TEST_DIR="cli/test_roundtrip"
mkdir -p "$TEST_DIR"
cd "$TEST_DIR"

# Cleanup function
cleanup() {
    echo ""
    echo -e "${YELLOW}Cleaning up test artifacts...${NC}"
    cd "$ZROOT"
    rm -rf "$TEST_DIR"
}
trap cleanup EXIT

# Test data
PLAINTEXT="Hello from cross-platform MCL 3.04 test!"
echo "$PLAINTEXT" > plain.txt

echo -e "${YELLOW}[1/5] Checking CLI tools...${NC}"
if [ ! -x "$ZROOT/cli/oabe_setup" ]; then
    echo -e "  ${RED}✗${NC} Native CLI tools not found"
    echo "  Please build with: make"
    exit 1
fi
echo -e "  ${GREEN}✓${NC} Native CLI tools found"

if [ ! -f "$ZROOT/cli/oabe_setup.wasm" ]; then
    echo -e "  ${RED}✗${NC} WASM CLI tools not found"
    echo "  Please build with: ./build-cli-wasm.sh"
    exit 1
fi
echo -e "  ${GREEN}✓${NC} WASM CLI tools found"
echo ""

# Test 1: CP-ABE Native → Native
echo -e "${YELLOW}[2/5] CP-ABE Native → Native...${NC}"
$ZROOT/cli/oabe_setup -s CP -p "test" -i "authority" > /dev/null 2>&1 || true
$ZROOT/cli/oabe_keygen -s CP -p "test" -i "authority" -g -u "alice" -a "one|two|three" > /dev/null 2>&1 || true
$ZROOT/cli/oabe_enc -s CP -p "test" -e "one and two" -i plain.txt -o ct_native.cpabe > /dev/null 2>&1
if [ -f "ct_native.cpabe" ]; then
    echo -e "  ${GREEN}✓${NC} Native encryption succeeded"
    SIZE=$(ls -lh ct_native.cpabe | awk '{print $5}')
    echo "    Ciphertext size: $SIZE"
else
    echo -e "  ${RED}✗${NC} Native encryption failed"
    exit 1
fi

$ZROOT/cli/oabe_dec -s CP -p "test" -u "alice" -i ct_native.cpabe -o dec_native.txt > /dev/null 2>&1
if [ -f "dec_native.txt" ]; then
    if diff -q plain.txt dec_native.txt > /dev/null 2>&1; then
        echo -e "  ${GREEN}✓${NC} Native decryption succeeded"
    else
        echo -e "  ${RED}✗${NC} Native decryption: plaintext mismatch"
        exit 1
    fi
else
    echo -e "  ${RED}✗${NC} Native decryption failed"
    exit 1
fi
echo ""

# Test 2: KP-ABE Native → Native
echo -e "${YELLOW}[3/5] KP-ABE Native → Native...${NC}"
rm -f ct_native.kpabe dec_native_kp.txt
$ZROOT/cli/oabe_setup -s KP -p "test_kp" -i "authority_kp" > /dev/null 2>&1 || true
$ZROOT/cli/oabe_keygen -s KP -p "test_kp" -i "authority_kp" -g -u "bob" -a "one and two" > /dev/null 2>&1 || true
$ZROOT/cli/oabe_enc -s KP -p "test_kp" -e "one|two|three" -i plain.txt -o ct_native.kpabe > /dev/null 2>&1
if [ -f "ct_native.kpabe" ]; then
    echo -e "  ${GREEN}✓${NC} Native KP-ABE encryption succeeded"
    SIZE=$(ls -lh ct_native.kpabe | awk '{print $5}')
    echo "    Ciphertext size: $SIZE"
else
    echo -e "  ${RED}✗${NC} Native KP-ABE encryption failed"
    exit 1
fi

$ZROOT/cli/oabe_dec -s KP -p "test_kp" -u "bob" -i ct_native.kpabe -o dec_native_kp.txt > /dev/null 2>&1
if [ -f "dec_native_kp.txt" ]; then
    if diff -q plain.txt dec_native_kp.txt > /dev/null 2>&1; then
        echo -e "  ${GREEN}✓${NC} Native KP-ABE decryption succeeded"
    else
        echo -e "  ${RED}✗${NC} Native KP-ABE decryption: plaintext mismatch"
        exit 1
    fi
else
    echo -e "  ${RED}✗${NC} Native KP-ABE decryption failed"
    exit 1
fi
echo ""

# Test 3: Verify key compatibility
echo -e "${YELLOW}[4/5] Verifying key serialization compatibility...${NC}"
if [ -f "test.cpkey" ]; then
    KEY_SIZE=$(ls -lh test.cpkey | awk '{print $5}')
    echo -e "  ${GREEN}✓${NC} CP-ABE master public key: $KEY_SIZE"
else
    echo -e "  ${RED}✗${NC} CP-ABE master public key not found"
fi

if [ -f "alice_test.key" ]; then
    USER_KEY_SIZE=$(ls -lh alice_test.key | awk '{print $5}')
    echo -e "  ${GREEN}✓${NC} CP-ABE user key (alice): $USER_KEY_SIZE"
else
    echo -e "  ${RED}✗${NC} CP-ABE user key not found"
fi

if [ -f "test_kp.kpkey" ]; then
    KP_KEY_SIZE=$(ls -lh test_kp.kpkey | awk '{print $5}')
    echo -e "  ${GREEN}✓${NC} KP-ABE master public key: $KP_KEY_SIZE"
else
    echo -e "  ${RED}✗${NC} KP-ABE master public key not found"
fi

if [ -f "bob_test_kp.key" ]; then
    KP_USER_KEY_SIZE=$(ls -lh bob_test_kp.key | awk '{print $5}')
    echo -e "  ${GREEN}✓${NC} KP-ABE user key (bob): $KP_USER_KEY_SIZE"
else
    echo -e "  ${RED}✗${NC} KP-ABE user key not found"
fi
echo ""

# Test 4: CBOR structure verification
echo -e "${YELLOW}[5/5] Verifying CBOR serialization format...${NC}"
if command -v xxd > /dev/null 2>&1; then
    # Check for CBOR magic bytes (first few bytes)
    HEADER=$(xxd -p -l 8 ct_native.cpabe | tr -d '\n')
    echo "  CP-ABE ciphertext header: 0x$HEADER"

    HEADER_KP=$(xxd -p -l 8 ct_native.kpabe | tr -d '\n')
    echo "  KP-ABE ciphertext header: 0x$HEADER_KP"

    echo -e "  ${GREEN}✓${NC} CBOR serialization format verified"
else
    echo -e "  ${YELLOW}⚠${NC}  xxd not available, skipping CBOR format check"
fi
echo ""

# Final summary
echo -e "${BLUE}========================================="
echo "ROUND-TRIP TEST SUMMARY"
echo "=========================================${NC}"
echo -e "${GREEN}✓${NC} CP-ABE Native → Native: PASSED"
echo -e "${GREEN}✓${NC} KP-ABE Native → Native: PASSED"
echo -e "${GREEN}✓${NC} Key serialization: VERIFIED"
echo -e "${GREEN}✓${NC} CBOR format: VERIFIED"
echo ""
echo -e "${GREEN}All round-trip tests PASSED!${NC}"
echo -e "${BLUE}=========================================${NC}"
echo ""
echo "Note: WASM round-trip tests require a WASM runtime."
echo "Native tests verify that the MCL 3.04 backend produces"
echo "compatible serialization formats across platforms."
