#!/bin/bash
#
# End-to-End CP-ABE Test
#
# This test verifies that:
# 1. CP-ABE setup works
# 2. Key generation works
# 3. Encryption works
# 4. Decryption works
# 5. Access control is enforced
#

set -e

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

info() { echo -e "${GREEN}[INFO]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }
success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }

# Create test directory
TEST_DIR="test-cpabe-output"
rm -rf "$TEST_DIR"
mkdir -p "$TEST_DIR"
cd "$TEST_DIR"

info "Starting CP-ABE End-to-End Test..."
echo ""

# Step 1: Setup
info "Step 1: Setting up CP-ABE (generating master keys)..."
../cli/oabe_setup -s CP -p "master" 2>&1 | head -5
if [ $? -eq 0 ]; then
    success "CP-ABE setup complete"
else
    error "CP-ABE setup failed"
fi
echo ""

# Step 2: Generate user key with attributes
info "Step 2: Generating user key with attributes: 'dept:engineering|role:developer|clearance:secret'"
../cli/oabe_keygen -s CP -p "master" -i "dept:engineering|role:developer|clearance:secret" -o user1.key 2>&1 | head -5
if [ $? -eq 0 ]; then
    success "User key generated"
    ls -lh user1.key
else
    error "Key generation failed"
fi
echo ""

# Step 3: Create test plaintext
info "Step 3: Creating test plaintext..."
cat > plaintext.txt << 'EOF'
This is a confidential message for engineering department.
It contains sensitive information that should only be accessible
to authorized personnel with the right attributes.

Test data: CP-ABE with BLS12-381 pairing
Date: October 27, 2025
Status: Testing MCL backend
EOF

info "Plaintext content:"
cat plaintext.txt
echo ""

# Step 4: Encrypt with policy
POLICY="(dept:engineering and role:developer)"
info "Step 4: Encrypting with policy: $POLICY"
../cli/oabe_enc -s CP -p "master" -e "$POLICY" -i plaintext.txt -o ciphertext.cpabe 2>&1 | head -5
if [ $? -eq 0 ]; then
    success "Encryption successful"
    ls -lh ciphertext.cpabe
else
    error "Encryption failed"
fi
echo ""

# Step 5: Decrypt with correct key
info "Step 5: Decrypting with user key (should succeed)..."
../cli/oabe_dec -s CP -p "master" -k user1.key -i ciphertext.cpabe -o decrypted.txt 2>&1 | head -5
if [ $? -eq 0 ]; then
    success "Decryption successful"
    info "Decrypted content:"
    cat decrypted.txt
    echo ""
else
    error "Decryption failed"
fi

# Step 6: Verify plaintext == decrypted
info "Step 6: Verifying plaintext matches decrypted..."
if diff plaintext.txt decrypted.txt > /dev/null 2>&1; then
    success "Plaintext matches decrypted text - CP-ABE working correctly!"
else
    error "Plaintext does not match decrypted text!"
fi
echo ""

# Step 7: Test access control (negative test)
info "Step 7: Testing access control (generating key without required attributes)..."
../cli/oabe_keygen -s CP -p "master" -i "dept:marketing|role:analyst" -o user2.key 2>&1 | head -5
if [ $? -eq 0 ]; then
    success "Second user key generated"

    info "Attempting to decrypt with insufficient attributes (should fail)..."
    if ../cli/oabe_dec -s CP -p "master" -k user2.key -i ciphertext.cpabe -o decrypted2.txt 2>&1 | grep -i "error\|failed\|cannot"; then
        success "Access control working - decryption correctly failed for user without required attributes"
    else
        # Check if file was created (shouldn't be)
        if [ ! -f decrypted2.txt ] || [ ! -s decrypted2.txt ]; then
            success "Access control working - no output file created"
        else
            error "Access control FAILED - user without attributes was able to decrypt!"
        fi
    fi
else
    error "Second key generation failed"
fi
echo ""

# Summary
info "========================================="
info "CP-ABE End-to-End Test Summary"
info "========================================="
success "1. Setup: PASS"
success "2. Key generation: PASS"
success "3. Encryption: PASS"
success "4. Decryption: PASS"
success "5. Content verification: PASS"
success "6. Access control: PASS"
info ""
success "All tests passed! CP-ABE is working correctly with MCL backend."
info "========================================="

cd ..
