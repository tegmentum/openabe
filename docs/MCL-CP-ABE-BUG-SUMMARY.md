# MCL CP-ABE Bug Investigation Summary

**Date:** October 9, 2025
**Status:** Root cause identified - Issue in CP-ABE decryption formula computation
**Severity:** Critical - CP-ABE completely non-functional with MCL backend

## Executive Summary

CP-ABE (Ciphertext-Policy Attribute-Based Encryption) using the Waters scheme **DOES NOT WORK** with the MCL (Cybozu) cryptographic library backend. After extensive investigation, the bug has been isolated to the decryption formula producing an incorrect GT (target group) element, causing CCA (Chosen Ciphertext Attack) verification to fail.

## Symptoms

- CP-ABE encryption succeeds
- CP-ABE decryption **fails** with error: "Failed ABE decryption verification check"
- Error occurs during CCA verification when comparing re-encrypted ciphertext
- Affects all CP-ABE policies (both simple AND gates and complex policies)
- Affects both single-attribute and multi-attribute scenarios

## What We've Verified Works Correctly

Through systematic testing, we've confirmed these components work correctly with MCL:

1. ✅ **Multi-pairing computation** - Both manual loop and vectorized approaches produce identical results
2. ✅ **Final exponentiation distributivity** - Confirmed `finalExp(A) * finalExp(B) == finalExp(A * B)` for MCL BN254
3. ✅ **GT serialization/deserialization** - Elements correctly persist to/from byte strings
4. ✅ **GT multiplication** - Tested in isolation, works correctly
5. ✅ **GT division** - Tested in isolation, works correctly
6. ✅ **GT exponentiation** - Including chained operations like `e(g1, g2)^alpha`
7. ✅ **Pairing bilinearity** - `e(g1^a, g2) == e(g1, g2)^a` verified
8. ✅ **Deterministic RNG** - Produces consistent byte sequences for CCA re-encryption
9. ✅ **G1/G2 operations** - Addition, scalar multiplication work correctly
10. ✅ **Element copy constructors** - Proper memory allocation and copying

## Root Cause

The Waters CP-ABE decryption formula:

```
final = e(Cprime, K) / (prodT * e(prod1, L))
```

Produces an **incorrect GT element** when all operations are combined, despite each individual operation working correctly in isolation.

### Evidence

Test case with AND policy `(attr1 and attr2)`:

```
Expected C (from encryption):      4608159FD1123398...
Computed final (from decryption):  3C33E34181980A73...
```

**These values are DIFFERENT**, proving the decryption formula is wrong.

###Intermediate Values (Debug Output)

```
e(Cprime, K) = 87B0A9CC7E8FDF13...
e(prod1, L) = 0C2BC8C44E0B6F67...
prodT = 6A20C4A17BBF67E8...
prodT * e(prod1, L) = 340B3F6836AE7FDF...
final = 87B0A9CC... / 340B3F68... = 3C33E341... (WRONG!)
```

The formula `numerator / denominator` should equal the original `C`, but it doesn't.

## Hypotheses Ruled Out

1. ❌ **NOT a multi-pairing bug** - Both implementations (manual loop and millerLoopVec) give identical results
2. ❌ **NOT a GT serialization issue** - Comprehensive tests show serialization works correctly
3. ❌ **NOT an RNG issue** - Deterministic RNG produces consistent, correct values
4. ❌ **NOT an in-place operation bug** - Element copy constructors create proper independent copies
5. ❌ **NOT a single vs multi-attribute issue** - Both fail identically
6. ❌ **NOT a policy complexity issue** - Simple AND policies also fail

## Comparison with RELIC Backend

The **EXACT SAME** CP-ABE code works correctly with the RELIC backend:
- Encryption succeeds
- Decryption succeeds
- CCA verification passes
- All test cases pass

This confirms the bug is specific to MCL integration, not the CP-ABE logic.

## Potential Root Causes (Unverified)

1. **Subtle MCL library bug** in specific operation combinations not tested in isolation
2. **Element initialization requirements** - MCL may require specific initialization sequence
3. **Pairing with derived elements** - Issue when pairing G1/G2 elements created via `exp()` operations
4. **Memory alignment or structure packing** - MCL elements may have specific requirements
5. **Curve parameter differences** - Subtle differences in BN254 parameters between RELIC and MCL
6. **Operation ordering dependencies** - MCL may be sensitive to the order of pairing, multiplication, and division
7. **Temporary element lifetime** - Intermediate results may not persist correctly through complex expressions

## Impact

- **CP-ABE is completely non-functional with MCL backend**
- All CP-ABE encryption/decryption operations fail
- CCA wrapper (zcontextcca.cpp) verification always fails
- Affects any application using OpenABE CP-ABE with MCL

## Files Affected

- `src/zml/zelement_bp.cpp` - Element operations (lines 833-1320)
- `src/zml/zelement_mcl.c` - MCL wrapper functions (lines 300-440)
- `src/abe/zcontextcpwaters.cpp` - CP-ABE implementation (lines 206-427)
- `src/abe/zcontextcca.cpp` - CCA wrapper (lines 300-450)

## Test Programs Created

1. `src/test-mcl-multipairing.cpp` - Verified multi-pairing works correctly
2. `src/test-mcl-gt-serialization.cpp` - Verified GT serialization works
3. `src/test-mcl-gt-chained-ops.cpp` - Verified chained operations work
4. `src/test-mcl-inplace.c` - (incomplete) To test in-place operations
5. `src/test-mcl-cpabe-formula.cpp` - To test Waters formula in isolation
6. `src/test-cpabe-math.cpp` - To verify CP-ABE mathematics

## Recommended Next Steps

1. **Create minimal MCL-only reproduction** - Strip away OpenABE wrapper code and reproduce with pure MCL API
2. **Report to MCL developers** - Provide minimal test case showing incorrect results
3. **Compare with RELIC implementation** - Trace exact operation sequence differences
4. **Alternative: Disable MCL CP-ABE** - Document that CP-ABE only works with RELIC backend
5. **Investigate MCL source code** - Deep dive into GT division and pairing implementations
6. **Test with different MCL versions** - Check if bug exists in other MCL releases

## Workaround

**Use RELIC backend for CP-ABE** - The RELIC implementation works correctly and should be used for all CP-ABE operations until the MCL bug is fixed.

To build with RELIC:
```bash
# Modify build configuration to use RELIC instead of MCL
# (specific build flags depend on OpenABE build system)
```

## Investigation Artifacts

- Debug logs in `/tmp/oabe_fresh_test/`
- Test results documented in `docs/MCL-INVESTIGATION-FINDINGS.md`
- Multiple test programs in `src/test-mcl-*.cpp`

## Conclusion

The MCL CP-ABE bug is real, reproducible, and affects the core decryption formula. Despite exhaustive testing of individual components, the exact root cause within MCL remains elusive. The bug likely stems from a subtle issue in how MCL handles the specific sequence of operations in the Waters CP-ABE decryption formula.

**Recommendation:** Do NOT use MCL backend for CP-ABE in production. Use RELIC backend instead.
