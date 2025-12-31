#!/bin/bash

echo "=== Testing Bug #15 Fix ==="
echo

# Set environment
export DYLD_LIBRARY_PATH=./deps/root/lib

# Clean up old test files
rm -f fix-test.*

# Create test message
echo "test message for bug15 fix" > fix-test.txt

# Setup master keys
echo "1. Running setup..."
./cli/oabe_setup -s CP -p fix-test
if [ $? -ne 0 ]; then
  echo "ERROR: Setup failed"
  exit 1
fi

# Generate user key
echo "2. Generating user key..."
./cli/oabe_keygen -s CP -p fix-test -i "ONE|THREE" -o fix-test-alice.key
if [ $? -ne 0 ]; then
  echo "ERROR: Keygen failed"
  exit 1
fi

# Encrypt
echo "3. Encrypting..."
./cli/oabe_enc -s CP -e "((ONE or THREE))" -i fix-test.txt -o fix-test.cpabe -p fix-test
if [ $? -ne 0 ]; then
  echo "ERROR: Encryption failed"
  exit 1
fi

# Decrypt (this tests CCA verification)
echo "4. Decrypting with CCA verification..."
./cli/oabe_dec -s CP -k fix-test-alice.key -o fix-test-decrypted.txt -i fix-test.cpabe -p fix-test 2>&1
if [ $? -ne 0 ]; then
  echo "ERROR: Decryption failed - Bug #15 NOT FIXED"
  exit 1
fi

# Verify decrypted content
if [ -f fix-test-decrypted.txt ]; then
  ORIG=$(cat fix-test.txt)
  DECR=$(cat fix-test-decrypted.txt)
  if [ "$ORIG" = "$DECR" ]; then
    echo
    echo "SUCCESS: Bug #15 is FIXED!"
    echo "Original: $ORIG"
    echo "Decrypted: $DECR"
    exit 0
  else
    echo "ERROR: Decrypted content doesn't match"
    echo "Original: $ORIG"
    echo "Decrypted: $DECR"
    exit 1
  fi
else
  echo "ERROR: Decrypted file not created"
  exit 1
fi
