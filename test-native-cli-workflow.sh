#!/bin/bash
# Native CLI Workflow Test
# Tests full CP-ABE workflow with native binaries: setup, keygen, encrypt, decrypt

set -e

ZROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ZROOT"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}========================================="
echo "NATIVE CLI FULL WORKFLOW TEST"
echo "MCL 3.04 with BLS12-381"
echo "Testing: setup → keygen → encrypt → decrypt"
echo "=========================================${NC}"
echo ""

# Check native CLI tools
CLI_DIR="cli"
TOOLS=("oabe_setup" "oabe_keygen" "oabe_enc" "oabe_dec")
for tool in "${TOOLS[@]}"; do
    if [ ! -f "$CLI_DIR/$tool" ]; then
        echo -e "${RED}✗${NC} $tool not found in $CLI_DIR"
        exit 1
    fi
done
echo -e "${GREEN}✓${NC} All native CLI tools found"

# Setup test directory
TEST_DIR="cli/test_native_workflow"
mkdir -p "$TEST_DIR"
cd "$TEST_DIR"

# Cleanup function
cleanup() {
    echo ""
    echo -e "${YELLOW}Cleaning up test artifacts...${NC}"
    cd "$ZROOT"
}
trap cleanup EXIT

# Test data
PLAINTEXT="This is a test message for MCL 3.04 native CLI full workflow test. Testing CP-ABE encryption and decryption with attribute-based access control."
echo "$PLAINTEXT" > plain.txt
PLAINTEXT_SIZE=$(ls -lh plain.txt | awk '{print $5}')
echo -e "${GREEN}✓${NC} Created plaintext file ($PLAINTEXT_SIZE)"

# Policy and attributes
POLICY="((ONE or TWO) and (THREE or FOUR))"
ATTRIBUTES="ONE|THREE"

echo ""
echo -e "${BLUE}========================================="
echo "Step 1: CP-ABE Setup"
echo "=========================================${NC}"
../oabe_setup -s CP -p test -v

if [ -f "test.mpk.cpabe" ] && [ -f "test.msk.cpabe" ]; then
    MPK_SIZE=$(ls -lh test.mpk.cpabe | awk '{print $5}')
    MSK_SIZE=$(ls -lh test.msk.cpabe | awk '{print $5}')
    echo -e "${GREEN}✓${NC} Setup succeeded"
    echo "  Master public key: $MPK_SIZE"
    echo "  Master secret key: $MSK_SIZE"
else
    echo -e "${RED}✗${NC} Setup failed - keys not created"
    exit 1
fi

echo ""
echo -e "${BLUE}========================================="
echo "Step 2: Key Generation"
echo "=========================================${NC}"
echo "Generating secret key for attributes: $ATTRIBUTES"
../oabe_keygen -s CP -p test -i "$ATTRIBUTES" -o userkey -v

if [ -f "userkey.key" ]; then
    SK_SIZE=$(ls -lh userkey.key | awk '{print $5}')
    echo -e "${GREEN}✓${NC} Key generation succeeded"
    echo "  Secret key: $SK_SIZE"
else
    echo -e "${RED}✗${NC} Key generation failed - secret key not created"
    exit 1
fi

echo ""
echo -e "${BLUE}========================================="
echo "Step 3: Encryption"
echo "=========================================${NC}"
echo "Encrypting with policy: $POLICY"
../oabe_enc -s CP -p test -e "$POLICY" -i plain.txt -o cipher -v

if [ -f "cipher.cpabe" ]; then
    CT_SIZE=$(ls -lh cipher.cpabe | awk '{print $5}')
    echo -e "${GREEN}✓${NC} Encryption succeeded"
    echo "  Ciphertext: $CT_SIZE"
else
    echo -e "${RED}✗${NC} Encryption failed - ciphertext not created"
    exit 1
fi

echo ""
echo -e "${BLUE}========================================="
echo "Step 4: Decryption"
echo "=========================================${NC}"
echo "Decrypting with secret key for attributes: $ATTRIBUTES"
../oabe_dec -s CP -p test -k userkey.key -i cipher.cpabe -o decrypted.txt -v

if [ -f "decrypted.txt" ]; then
    DEC_SIZE=$(ls -lh decrypted.txt | awk '{print $5}')
    echo -e "${GREEN}✓${NC} Decryption succeeded"
    echo "  Decrypted text: $DEC_SIZE"
else
    echo -e "${RED}✗${NC} Decryption failed - decrypted file not created"
    exit 1
fi

echo ""
echo -e "${BLUE}========================================="
echo "Step 5: Verification"
echo "=========================================${NC}"

# Compare original and decrypted
ORIGINAL=$(cat plain.txt)
DECRYPTED=$(cat decrypted.txt)

if [ "$ORIGINAL" = "$DECRYPTED" ]; then
    echo -e "${GREEN}✓${NC} Round-trip verification: PASSED"
    echo ""
    echo "Original:"
    echo "  $ORIGINAL"
    echo ""
    echo "Decrypted:"
    echo "  $DECRYPTED"
else
    echo -e "${RED}✗${NC} Round-trip verification: FAILED"
    echo ""
    echo "Original:"
    echo "  $ORIGINAL"
    echo ""
    echo "Decrypted:"
    echo "  $DECRYPTED"
    exit 1
fi

echo ""
echo -e "${GREEN}========================================="
echo "NATIVE CLI FULL WORKFLOW TEST: SUCCESS!"
echo "=========================================${NC}"
echo ""
echo "Summary:"
echo -e "${GREEN}✓${NC} CP-ABE Setup (master keys generated)"
echo -e "${GREEN}✓${NC} Key Generation (secret key for attributes)"
echo -e "${GREEN}✓${NC} Encryption (with access policy)"
echo -e "${GREEN}✓${NC} Decryption (with matching attributes)"
echo -e "${GREEN}✓${NC} Round-trip verification (plaintext matches)"
echo ""
echo "File sizes:"
echo "  Plaintext:      $PLAINTEXT_SIZE"
echo "  Master PK:      $MPK_SIZE"
echo "  Master SK:      $MSK_SIZE"
echo "  User SK:        $SK_SIZE"
echo "  Ciphertext:     $CT_SIZE"
echo "  Decrypted:      $DEC_SIZE"
echo ""
echo -e "${BLUE}MCL 3.04 native CLI is fully functional!${NC}"
echo -e "${BLUE}=========================================${NC}"
