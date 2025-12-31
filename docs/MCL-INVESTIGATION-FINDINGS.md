# MCL CP-ABE Investigation Findings

## Date
October 9, 2025

## Summary

CP-ABE **DOES NOT WORK** with MCL backend. After extensive investigation, the issue is NOT with the multi-pairing algorithm as initially suspected.

## Key Findings

### 1. MCL's Final Exponentiation IS Distributive

Created test program `test-mcl-multipairing.cpp` which proved:

```
finalExp(A) * finalExp(B) == finalExp(A * B)
```

This is **mathematically unexpected** but confirmed for MCL's BN254 implementation. This means:
- The original multi-pairing code was mathematically correct
- The "fixed" code (using miller loops + one final exp) gives the **SAME** result
- Both methods are equivalent for MCL

**Test Results:**
```
✓ pairing(P1,Q1) == finalExp(millerLoop(P1,Q1))
✓ Both methods give same result!
  This means finalExp IS distributive (unexpected!)
✓ Bilinearity verified!
```

### 2. Multi-Pairing is NOT the Problem

Since both multi-pairing approaches give identical results, the issue must be elsewhere in the CP-ABE implementation.

### 3. CP-ABE Consistently Fails

**Test Case:** AND policy with 2 attributes (attr1 and attr2)
- Uses 2 pairings in `prodT` computation
- Encryption succeeds
- Decryption fails with verification error

**Symptom:**
```
Original r:  CEC095AC7F02EF556F6BFE6FAA357E21A095ED2B9D832DDD5786D2C649676189
Recovered r: 7CA0A779FF44775B5CC9DF3D4354D768C7A9C7B3A6E2450459144CF15745E122
ERROR: Failed ABE decryption verification check
```

The recovered `r` value doesn't match the original, indicating the GT element computed during decryption is wrong.

### 4. Single-Attribute Policies Also Fail

Even with n==1 (single pairing), CP-ABE fails:
```
Original r:  8355C5B9AE9103351BB8C1A01E9D3E5E...
Recovered r: E70F7CC8811F8645B7FB203A0DEBCB5F...
```

This rules out multi-pairing as the root cause.

## Additional Tests Performed (October 9, 2025 - Later)

### GT Serialization Test
Created `test-mcl-gt-serialization.cpp` which verified:
- GT elements serialize and deserialize correctly
- GT multiplication + serialization works
- GT division + serialization works
- **Result**: ✅ All tests PASSED

### GT Chained Operations Test
Created `test-mcl-gt-chained-ops.cpp` which verified:
- `A = e(g1, g2)^alpha` (chained pairing + exp) works correctly
- `C = A^s` works correctly
- In-place GT exponentiation works correctly
- Serialization of chained operation results works correctly
- **Result**: ✅ All tests PASSED

### GT Division Implementation
Located and verified `gt_div_op` for MCL:
```c
void gt_div_op(const bp_group_t group, gt_ptr z, gt_ptr x, gt_ptr y) {
  mclBnGT inv;
  memset(&inv, 0, sizeof(inv));
  mclBnGT_inv(&inv, y);
  mclBnGT_mul(z, x, &inv);
  (void)group;
}
```
- Implementation looks correct: z = x * y^(-1)
- **Result**: ✅ Implementation is correct

## Potential Root Causes (Not Yet Identified)

After extensive low-level testing of MCL primitives, all basic operations work correctly:
- ❌ NOT GT serialization (tested and works)
- ❌ NOT GT division (tested and works)
- ❌ NOT GT exponentiation (tested and works)
- ❌ NOT chained pairing+exp operations (tested and works)

Remaining possibilities:

1. **OpenABE-specific issue in CP-ABE flow**
   - Bug in how OpenABE orchestrates the operations
   - Issue with component storage/retrieval in ciphertext/key structures
   - Problem with LSSS coefficient computation or application

2. **G1/G2 Operations**
   - Haven't tested G1/G2 operations as thoroughly as GT
   - May be issue with G1.exp() or G2.exp() implementations
   - Could be G1/G2 serialization issue

3. **Random Number Generation**
   - Different RNG behavior between RELIC and MCL
   - May affect attribute randomization in encryption
   - Need to compare RNG implementations

4. **Group Order or Field Operations**
   - Subtle differences in how MCL vs RELIC handle scalar operations
   - May affect negative exponents or inversions
   - Issue with ZP (scalar field) operations

5. **Component Storage/Retrieval**
   - OpenABE stores ciphertext/key components in maps
   - Serialization/deserialization of components may have issues
   - Need to verify component-level serialize/deserialize

## What We've Ruled Out

- ❌ Multi-pairing algorithm bug (both methods work identically)
- ❌ Miller loop implementation (tested and works correctly)
- ❌ Final exponentiation (tested and works correctly)
- ❌ Single vs multiple pairings (both fail)

## What Works

- ✅ MCL pairing operations (tested with standalone program)
- ✅ MCL bilinearity (verified)
- ✅ MCL finalExp distributivity (verified, though unexpected)
- ✅ CP-ABE with RELIC backend (works correctly)

## Recommended Next Steps

1. **Test in-memory CP-ABE** (no serialization) to rule out serialization issues
2. **Verify GT division** implementation for MCL
3. **Compare intermediate values** between RELIC and MCL encryption/decryption
4. **Test with MCL's built-in test vectors** if available
5. **Check MCL initialization** and curve parameter setup

## Code Locations

- Multi-pairing: `src/zml/zelement_bp.cpp` lines 307-367
- CP-ABE encryption: `src/abe/zcontextcpwaters.cpp` lines 206-300
- CP-ABE decryption: `src/abe/zcontextcpwaters.cpp` lines 328-427
- Test program: `src/test-mcl-multipairing.cpp`

## BREAKTHROUGH: Root Cause Identified (October 9, 2025 - Evening)

### The Real Issue

After adding extensive debugging, discovered that:

1. **The deterministic RNG works correctly** - produces same byte sequences on re-encryption
   - Test showed: `191dbed3...`, `8fe0a436...` etc. identical across runs

2. **The CCA verification fails because:**
   - Decrypted GT element: `1B56F78BC8B90E29...`
   - Re-encrypted GT element: `785C9314016DF3E7...`
   - **These are DIFFERENT!**

3. **The CP-ABE decryption formula produces the WRONG GT element**
   - Formula: `final = e(Cprime, K) / (prodT * e(prod1, L))`
   - All intermediate pairings are computed
   - But the final result doesn't match what was encrypted

### What This Means

- ❌ NOT an RNG issue (RNG is deterministic and works correctly)
- ❌ NOT a multi-pairing issue (verified to work)
- ❌ NOT GT operations in isolation (all tested and work)
- ✅ **ISSUE: CP-ABE decryption formula produces wrong result with MCL**

The bug is subtle - it only manifests when all the CP-ABE operations are combined together. Individual operations (pairing, GT div, GT exp, etc.) all work correctly in isolation, but when combined in the full CP-ABE decryption formula, the result is wrong.

### Hypothesis

The issue may be related to:
1. **Element initialization or group context** - MCL may require elements to be properly initialized with group context
2. **Temporary element lifetime** - Intermediate GT elements from pairings may not persist correctly
3. **Operation ordering** - The sequence of operations (pairing, mult, div) may expose a bug in MCL
4. **Memory layout or alignment** - MCL's GT element structure may have specific alignment requirements

## Conclusion

The MCL backend has a bug in the CP-ABE decrypt formula computation. The issue is **NOT** in any individual operation, but in how they combine. The decrypted GT element is incorrect, which causes the CCA verification to fail.

**Status: INVESTIGATION ONGOING** - Systematically ruling out potential causes.

## Investigation Summary (October 9, 2025 - Comprehensive Analysis)

After extensive testing and debugging, we have:

### ✅ Verified Working Correctly:
1. **MCL multi-pairing** - Both methods (manual loop and millerLoopVec) produce identical, correct results
2. **MCL finalExp distributivity** - Confirmed that `finalExp(A) * finalExp(B) == finalExp(A * B)` for MCL BN254
3. **GT serialization/deserialization** - All tests passed
4. **GT multiplication and division in isolation** - Tested and working
5. **GT chained operations** - `A = e(g1, g2)^alpha` works correctly
6. **Deterministic RNG** - Produces identical byte sequences across runs
7. **G1/G2 basic operations** - Addition, multiplication work correctly

### ❌ Hypotheses Ruled Out:
1. **NOT a multi-pairing bug** - Verified both implementations give same results
2. **NOT a GT serialization issue** - Comprehensive tests passed
3. **NOT an RNG issue** - Deterministic RNG works correctly
4. **NOT an in-place operation bug** - `GT z = x;` creates proper copy, operations are correct

### 🔍 Current Status:
The CP-ABE decryption formula `final = e(Cprime, K) / (prodT * e(prod1, L))` produces wrong GT element.

**Test Evidence:**
- Expected C (from encryption): `4608159FD1123398...`
- Computed final (from decryption): `3C33E34181980A73...`
- These are DIFFERENT, causing CCA verification to fail

**Intermediate Values (from debug output):**
- `e(Cprime, K) = 87B0A9CC7E8FDF13...`
- `e(prod1, L) = 0C2BC8C44E0B6F67...`
- `prodT = 6A20C4A17BBF67E8...`
- `prodT * e(prod1, L) = 340B3F6836AE7FDF...`
- `final = 87B0A9CC... / 340B3F68... = 3C33E341...` (WRONG!)

### 🤔 Remaining Possibilities:
1. **Subtle MCL library bug** in specific operation combinations
2. **Element initialization issue** - MCL may require specific initialization sequence
3. **Pairing with exponentiated elements** - Issue when pairing G1/G2 elements that were created via `exp()`
4. **Memory alignment or structure packing** - MCL elements may have specific requirements
5. **Group parameter mismatch** - Curve parameters may differ subtly between RELIC and MCL

**Status: ROOT CAUSE NOT YET IDENTIFIED** - Need deeper investigation into MCL library internals or comparison with RELIC backend.

## Next Investigation Steps (October 9, 2025 - Late Evening)

Given that all individual MCL operations work correctly in isolation, the bug must be in how OpenABE orchestrates them. Potential areas to investigate:

### 1. Element Initialization and Lifecycle
- **Hypothesis**: MCL elements may need explicit initialization with group context before use
- G1/G2/GT elements created via `exp()` return new objects - are they properly initialized?
- Check if temporary GT elements from pairings are correctly managed in memory
- Verify that element operations don't have side effects on source elements

### 2. In-Place vs Copy Operations
- Check if MCL's `mclBnG1_mul`, `mclBnG2_mul`, `mclBnGT_mul` etc. correctly handle in-place operations (z = op(z, x))
- Verify that division `z = x / y` implemented as `z = x * inv(y)` handles all edge cases
- Test if the issue appears when result pointer equals one of the operand pointers

### 3. Operation Ordering and Intermediate Values
- Add detailed logging to trace exact GT values at each step:
  - Original C from encryption
  - prodT after multi_pairing
  - e(Cprime, K)
  - e(prod1, L)
  - denominator = prodT * e(prod1, L)
  - final = e(Cprime, K) / denominator
- Compare intermediate values between RELIC and MCL backends
- Check if the formula components are mathematically correct given the scheme

### 4. Simplified Test Case
- Create minimal CP-ABE test with single attribute (n=1)
- This eliminates multi_pairing complexity
- Should help isolate if issue is in specific operation or combination
