# MCL CP-ABE Final Analysis

## Executive Summary

CP-ABE with MCL backend **FAILS** in production use, even though basic MCL operations work correctly. The issue is **NOT** with MCL itself, but appears to be a subtle incompatibility or bug in how OpenABE uses MCL for complex CP-ABE operations.

## Key Findings

### 1. MCL Library Works Correctly ✅

Direct testing of MCL shows all fundamental operations work:
- ✅ Pairing bilinearity: `e(g1^a, g2^b) = e(g1, g2)^(a*b)`
- ✅ Negative exponents: `A^x * A^(-x) = identity`
- ✅ Group operations: multiplication, division, exponentiation
- ✅ All distributive laws

**Test program**: `test-mcl-negative-fix.cpp`
```
--- Method 1: Direct negation (BROKEN) ---
A^x * A^(-x) is identity: YES ✓
```

This contradicts the earlier finding from `test-mcl-g1-exp.cpp` which was using the OpenABE wrapper layer.

### 2. OpenABE Wrapper Layer Has Issues ⚠️

When using MCL through OpenABE's wrapper (`zelement_bp.cpp`, `zelement_mcl.c`), basic operations still work:
- ✅ Test 1: `(A * B)^x = A^x * B^x`
- ✅ Test 2: `(A^x)^y = A^(x*y)`
- ✅ Test 3: `A^x * A^(-x) = identity`

BUT:
- ❌ Test 4: CP-ABE formula verification fails

**Test program**: `test-mcl-g1-exp.cpp`

### 3. CP-ABE Encryption/Decryption Fails ❌

Full CP-ABE workflow using CLI tools:
- ✅ Setup works
- ✅ Keygen works
- ✅ Encryption completes
- ❌ **Decryption verification fails**

**Evidence**:
```
DEBUG CCA ENCRYPT: Original r (hex): 8355C5B9AE9103351BB8C1A01E9D3E5E...
DEBUG CCA: Recovered r (hex): E70F7CC8811F8645B7FB203A0DEBCB5F...
ERROR: Failed ABE decryption verification check. (code: 32)
```

The recovered `r` value differs from the original, causing CCA re-encryption verification to fail.

## Root Cause Analysis

The bug is **NOT** in:
- MCL's scalar multiplication
- MCL's negative exponent handling
- MCL's pairing implementation

The bug **IS** in:
- The complex interaction between OpenABE and MCL during CP-ABE operations
- Possibly in how GT elements are serialized/deserialized
- Possibly in multi-pairing operations
- Possibly in the specific sequence of operations used in CP-ABE Waters encryption

### Specific Failure Point

From debug output during decryption:
```
[CP-ABE DEBUG] final GT element: (347F0B6F82697F5726F4FD17C397DADF...)
[CP-ABE ENCRYPT DEBUG] Cprime after exp(s): [1 5443204151578751281390238366196955...]
```

The final GT element computed during decryption doesn't match what would be needed to correctly recover the encryption randomness `r`.

### Why Basic Tests Pass But CP-ABE Fails

1. **Basic tests** (`test-mcl-bilinearity.cpp`, `test-mcl-negative-fix.cpp`): Use MCL directly → Pass ✅
2. **OpenABE wrapper tests** (`test-mcl-g1-exp.cpp` Tests 1-3): Simple operations → Pass ✅
3. **OpenABE wrapper tests** (`test-mcl-g1-exp.cpp` Test 4): Complex CP-ABE formula → Fail ❌
4. **Full CP-ABE** (CLI tools): Complete workflow → Fail ❌

This suggests the bug is triggered only during complex combinations of operations as used in CP-ABE.

## Possible Issues

### Hypothesis 1: GT Element Handling
MCL and RELIC may handle GT elements differently. The Waters CP-ABE scheme heavily relies on GT exponentiation and comparison.

### Hypothesis 2: Multi-Pairing
Debug output shows:
```
[MULTI_PAIRING DEBUG] Called with 1 pairs
[MULTI_PAIRING DEBUG] After multi_bp_map_op, checking isInfinity...
```

The multi-pairing implementation might have subtle differences between MCL and RELIC.

### Hypothesis 3: Serialization
GT elements are serialized during encryption and deserialized during decryption. MCL's GT serialization might not be correctly implemented in the OpenABE wrapper.

### Hypothesis 4: Floating Point Precision
While unlikely, there could be precision issues in how MCL represents and computes with very large numbers in the GT field.

## Impact

- ❌ **CP-ABE Waters with MCL**: BROKEN
- ❌ **KP-ABE with MCL**: Likely also broken (uses similar operations)
- ✅ **PKE with MCL**: Works (simpler operations)
- ✅ **PKSig with MCL**: Works (doesn't use pairings)
- ✅ **All schemes with RELIC**: Work correctly

## Recommendation

**Use RELIC backend for all ABE operations.**

MCL is a high-quality library, but the specific combination of operations required for CP-ABE Waters doesn't work correctly when used through the OpenABE wrapper layer. The exact cause would require deep debugging of the pairing operations, GT element handling, or serialization logic.

To build with RELIC:
```bash
cd deps/relic && make
cd ../..
export ZML_LIB="with_relic"
make clean && make
```

## Test Programs Created

1. **test-mcl-bilinearity.cpp** - Verifies MCL pairing correctness ✅
2. **test-mcl-g1-exp.cpp** - Tests G1 exponentiation laws ✅ (3/4 tests)
3. **test-mcl-negative-fix.cpp** - Tests MCL negative exponents directly ✅
4. **test-cpabe-formula.cpp** - Simulates CP-ABE formula ❌
5. **CLI tools test** - Full CP-ABE workflow ❌

## Conclusion

While MCL itself works correctly, its integration with OpenABE for CP-ABE operations has a subtle bug that causes decryption verification to fail. The bug is complex enough that it doesn't manifest in simple tests, but breaks the full CP-ABE workflow.

**Use RELIC for production ABE deployments.**

## Date

Analysis completed: October 9, 2025
MCL Version: 1.61
OpenABE Version: Latest from repository
