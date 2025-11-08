#!/bin/bash
# Simple native-only test for CP-ABE encryption/decryption
# Tests the fix for attribute separator bug

set -e

GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

info() { echo -e "${GREEN}[INFO]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Clean up previous test files
rm -f test.mpk.cpabe test.msk.cpabe sk_alice.key ct.cpabe decrypted.txt plain.txt

# Create test message
echo "Hello MCL 3.04 CP-ABE!" > plain.txt
info "Created test message: $(cat plain.txt)"

# Run full encryption/decryption cycle
info "Setting up CP-ABE system..."
./cli/oabe_setup -s CP -p test

info "Generating key for 'role:developer'..."
./cli/oabe_keygen -s CP -p test -i "role:developer" -o sk_alice

info "Encrypting with policy 'role:developer'..."
./cli/oabe_enc -s CP -p test -e "role:developer" -i plain.txt -o ct.cpabe

info "Decrypting ciphertext..."
./cli/oabe_dec -s CP -p test -k sk_alice.key -i ct.cpabe -o decrypted.txt

# Verify
if diff -q plain.txt decrypted.txt > /dev/null; then
    info "✓ Test PASSED: Encryption and decryption successful"
    info "✓ CCA verification working correctly"
else
    error "✗ Test FAILED: Decrypted content does not match original"
    exit 1
fi

# Clean up
rm -f test.mpk.cpabe test.msk.cpabe sk_alice.key ct.cpabe decrypted.txt plain.txt

echo -e "\n${GREEN}========================================${NC}"
echo -e "${GREEN}Native CP-ABE test completed successfully${NC}"
echo -e "${GREEN}========================================${NC}\n"
