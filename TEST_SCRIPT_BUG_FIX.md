# CP-ABE Test Script Bug Fix

## Date
2025-11-07

## Summary
Fixed attribute separator mismatch in `test-roundtrip.sh` that was causing CCA verification failures in CP-ABE encryption/decryption tests.

## Problem
The `test-roundtrip.sh` script was failing with a CCA verification error:
```
ERROR: Failed ABE decryption verification check. (code: 32)
```

Debug logging showed that the encrypted key `K` and decrypted key `K` were different, indicating the re-encryption check was failing.

## Root Cause
Attribute separator inconsistency in the test script:
- **Line 27** (key generation): Used `"role|developer"` (pipe `|` separator)
- **Line 28** (encryption policy): Used `"role:developer"` (colon `:` separator)

This mismatch caused:
1. Key generated with attribute: `role|developer`
2. Ciphertext encrypted for policy: `role:developer`
3. LSSS attribute matching failed (no matching attributes found)
4. Empty `lsssRows` vector passed to multi-pairing
5. Multi-pairing returned identity element (1) as denominator
6. Incorrect key recovery in `decryptKEM`
7. CCA verification failure

## Investigation Process
1. Added debug logging to `src/abe/zcontextcca.cpp` to compare encrypted/decrypted `M`
2. Traced through CCA → CPA → CP-ABE decryptKEM chain
3. Found multi-pairing was being called with 0 pairs
4. Discovered LSSS couldn't find matching attributes
5. Identified separator mismatch in test script

## Fix
Changed `test-roundtrip.sh` line 27:

**Before:**
```bash
./cli/oabe_keygen -s CP -p test -i "role|developer" -o sk_alice
```

**After:**
```bash
./cli/oabe_keygen -s CP -p test -i "role:developer" -o sk_alice
```

## Verification
1. **Native→Native test**: PASSED
   ```
   [CCA DEBUG] Comparison result: MATCH
   [CCA DEBUG] Verification passed! Setting symmetric key.
   ✓ Native→Native: PASSED
   ```

2. **Clean test**: Created `test-native-only.sh` - PASSED
   ```
   ✓ Test PASSED: Encryption and decryption successful
   ✓ CCA verification working correctly
   ```

## Files Added
- `test-roundtrip.sh` - Cross-platform MCL 3.04 serialization test (fixed)
- `test-native-only.sh` - Simple native CP-ABE test script

## Conclusion
The MCL 3.04-based CP-ABE implementation is functioning correctly. The issue was purely a configuration error in the test script. The colon (`:`) separator is the correct format for attributes in OpenABE.
