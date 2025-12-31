# MCL Multi-Pairing Implementation Analysis

**Date:** October 9, 2025
**Status:** Ongoing investigation into CP-ABE decryption bug

## Key Discovery

The MCL backend implements multi-pairing differently from RELIC:

### RELIC Implementation (Working ✅)
```cpp
// Uses vectorized pairing operation
pp_map_sim_oatep_k12(gt.m_GT, g_1, g_2, n);
```

- Single optimized operation
- Computes all pairings simultaneously
- No intermediate state

### MCL Implementation (In CP-ABE: Broken ❌)
```cpp
// Manual loop with in-place multiplication
mclBnGT temp;
memset(&temp, 0, sizeof(temp));
if (n == 0) {
    mclBnGT_clear(gt.m_GT);
} else {
    for (size_t i = 0; i < n; i++) {
        mclBn_pairing(&temp, ps[i], qs[i]);
        if (i == 0) {
            mclBnGT_copy(gt.m_GT, &temp);
        } else {
            mclBnGT_mul(gt.m_GT, gt.m_GT, &temp);  // ← IN-PLACE OPERATION
        }
    }
}
```

**Note:** Line 339 performs **in-place multiplication**: `mclBnGT_mul(result, operand1, operand2)` where `result == operand1`.

## Previous Test Results

### Test: test-mcl-multipairing.cpp (PASSED ✅)
This test showed multi-pairing works correctly in isolation. However, it tested with:
- Fresh G1/G2 elements created from generators
- Simple scalar multiplications
- Clean, isolated environment

### CP-ABE Decryption (FAILED ❌)
Uses multi-pairing with:
- G1 elements created via `hashToG1(...).exp(t)`
- G2 elements created via `g2.exp(ri)`
- Complex derived elements
- Multiple operations before multi-pairing

## Hypothesis: Element Derivation Context

The multi-pairing may work correctly for "fresh" elements but fail when elements are:
1. Created via hash-to-curve operations
2. Exponentiated with field elements
3. Part of a larger computation chain

This could indicate:
- **State corruption** in MCL elements after certain operations
- **Aliasing issues** when pairing results of `exp()` operations
- **Memory layout assumptions** that don't hold for derived elements

## Code Locations

**Multi-pairing implementation:**
- File: `src/zml/zelement_bp.cpp`
- Lines: 327-342 (MCL version)
- Lines: 344-358 (RELIC version)

**CP-ABE decryption usage:**
- File: `src/abe/zcontextcpwaters.cpp`
- Line 392: `this->getPairing()->multi_pairing(prodT, g1s, g2s);`
- Context: Computing `prodT = ∏ e(KX_i^coeff, D_i)`

**Element derivation in CP-ABE:**
- Line 388: `g1s.push_back(Kx->exp(coeff));` - G1 from exponentiation
- Line 389: `g2s.push_back(*Dx);` - G2 from ciphertext (originally `g2^ri`)
- Line 211: `Kx = hashToG1(...).exp(t)` - Original derivation during keygen
- Line 300: `Di = g2.exp(ri)` - Original derivation during encryption

## Comparison with Working Schemes

### KP-ABE (Works with MCL ✅)
- Also uses multi-pairing
- Different element derivation pattern
- May not trigger the same edge case

### PKE, PKSig (Work with MCL ✅)
- Simpler pairing operations
- Fewer derived elements
- Different computation patterns

## Next Investigation Steps

1. **Test multi-pairing with hash-derived elements** ← Current focus
   - Create G1 via `hashToG1()` then `.exp()`
   - Pair with G2 created via `.exp()`
   - See if multi-pairing produces correct result

2. **Compare element internal state**
   - Examine MCL element structure after hash+exp
   - Compare with fresh elements
   - Look for corruption or invalid state

3. **Test single pairing with same elements**
   - Use CP-ABE's exact element derivations
   - Compute pairings individually vs. multi-pairing
   - Identify if issue is in pairing or multiplication

4. **Memory analysis**
   - Check if `g1s.push_back(Kx->exp(coeff))` creates proper copies
   - Verify vector doesn't have dangling references
   - Ensure element lifetimes are correct

## Related Files

- `test-mcl-multipairing.cpp` - Verified basic multi-pairing works
- `test-mcl-g1g2-derived.cpp` - Created to test derived elements (compilation issues)
- `test-mcl-g1g2-pure.c` - Pure MCL version (compilation issues)

## Status

Investigation continuing. Multi-pairing works in isolation but fails in CP-ABE context.
Focusing on element derivation as potential root cause.
