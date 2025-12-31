# CP-ABE Debug Logging Implementation

## Overview

Comprehensive debug logging has been added to CP-ABE decryption to diagnose why it fails with MCL backend while KP-ABE succeeds.

## Implementation Location

**File**: `src/abe/zcontextcpwaters.cpp`
**Lines**: 377-406

## Debug Output

The logging traces the complete CP-ABE decryption formula step-by-step:

### Formula Being Debugged
```
final = e(Cprime, K) / (prodT * e(prod1, L))
```

Where:
- `prodT` = multi-pairing result: `∏ e(KX[i]^coeff[i], D[i])`
- `prod1` = product of ciphertext components: `∏ C[i]^coeff[i]`
- `Cprime`, `K`, `L` = key/ciphertext components

### Logged Values

The debug output includes:

1. **prodT after multi_pairing**: Result of the multi-pairing operation
2. **prod1**: Accumulated G1 product
3. **Cprime**: G1 element from ciphertext
4. **K**: G2 element from decryption key
5. **L**: G2 element from decryption key
6. **e(Cprime, K)**: First pairing result (numerator)
7. **e(prod1, L)**: Second pairing result
8. **prodT * e(prod1, L)**: Complete denominator
9. **final GT element**: Result before hashing to symmetric key

## Purpose

These intermediate values will pinpoint exactly where MCL's computation diverges from the expected result:

- ✅ If `prodT` is wrong → issue in multi-pairing
- ✅ If pairings are wrong → issue in single pairing operation
- ✅ If GT operations are wrong → issue in GT multiplication/division
- ✅ If all intermediate values correct → issue in GT-to-bytes serialization or hashing

## Current Status

### ✅ Completed
- Debug logging code implemented and ready
- Comprehensive tracing of all intermediate values
- Logging placed at optimal location in decryption path

### ⏸️ Blocked
Build environment issues prevent running the debug test:
1. Incomplete exception-to-return-code refactoring causing compilation errors
2. Functions with `ASSERT_NOTNULL` returning error codes from non-error return types
3. Dependency build path issues (RELIC CMAKE PREFIX)

### 📋 Next Steps

To complete the debugging:

1. **Fix Compilation Errors**:
   - Update functions using `ASSERT_NOTNULL` that return `string` or `OpenABEByteString`
   - Either change return types to `OpenABE_ERROR` or use try-catch for these cases

2. **Rebuild Environment**:
   ```bash
   cd deps && make clean && make
   cd .. && ./build.sh native
   ```

3. **Run Debug Test**:
   ```bash
   src/test_libopenabe --gtest_filter="*CP_WATERS*BasicEncDec" 2>&1 | grep "CP-ABE DEBUG"
   ```

4. **Analyze Output**:
   - Compare logged GT elements to expected values
   - Identify which specific operation produces incorrect result
   - Fix MCL wrapper or adjust CP-ABE implementation accordingly

## MCL Migration Context

This debugging is part of migrating OpenABE from RELIC 0.7.0 to MCL 1.61:

- **Test Status**: 28/46 passing (61%)
- **KP-ABE**: ✅ Working (uses simpler formula)
- **CP-ABE**: ❌ Failing (complex multi-pairing formula)
- **PKE**: ✅ Working (hybrid OpenSSL EC backend)
- **Primitives**: ✅ All pairing operations tested and working

The debug logging will reveal whether the issue is in:
- MCL's multi-pairing implementation
- MCL's GT group operations
- CP-ABE's specific formula complexity
- Serialization/deserialization of GT elements

## Code Sample

```cpp
// From src/abe/zcontextcpwaters.cpp:377-406
this->getPairing()->multi_pairing(prodT, g1s, g2s);
std::cerr << "[CP-ABE DEBUG] prodT after multi_pairing: " << prodT << std::endl;

G1 *Cprime = ciphertext->getG1("Cprime");
G2 *K = decKey->getG2("K");
G2 *L = decKey->getG2("L");
ASSERT_NOTNULL(Cprime);
ASSERT_NOTNULL(K);
ASSERT_NOTNULL(L);

std::cerr << "[CP-ABE DEBUG] prod1: " << prod1 << std::endl;
std::cerr << "[CP-ABE DEBUG] Cprime: " << *Cprime << std::endl;
std::cerr << "[CP-ABE DEBUG] K: " << *K << std::endl;
std::cerr << "[CP-ABE DEBUG] L: " << *L << std::endl;

GT e_Cprime_K = this->getPairing()->pairing(*Cprime, *K);
std::cerr << "[CP-ABE DEBUG] e(Cprime, K): " << e_Cprime_K << std::endl;

GT e_prod1_L = this->getPairing()->pairing(prod1, *L);
std::cerr << "[CP-ABE DEBUG] e(prod1, L): " << e_prod1_L << std::endl;

GT denominator = prodT * e_prod1_L;
std::cerr << "[CP-ABE DEBUG] prodT * e(prod1, L): " << denominator << std::endl;

GT final = e_Cprime_K / denominator;
std::cerr << "[CP-ABE DEBUG] final GT element: " << final << std::endl;

key->hashToSymmetricKey(final, keyByteLen, HASH_FUNCTION_TYPE_SHA256);
```

## References

- MCL Library: https://github.com/herumi/mcl
- CP-ABE (Waters): Based on "Ciphertext-Policy Attribute-Based Encryption" by Waters (2011)
- Previous Migration Docs: `docs/MCL-MIGRATION-PROGRESS.md`
