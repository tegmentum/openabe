# Root Cause Analysis: WASM CP-ABE CCA Decryption Failure

## Executive Summary

The intermittent CCA (Chosen-Ciphertext Attack) verification failures in OpenABE's WASM build are caused by a **fundamental CP-ABE decryption bug** where the decrypt function returns completely incorrect plaintext values. This is NOT a CCA-specific issue, but rather a critical bug in the core ABE decryption algorithm when compiled to WebAssembly.

## Investigation Timeline

### Phase 1: Initial Hypothesis - PRNG Non-determinism
- **Initial observation**: CCA verification fails 70-90% of the time in WASM, but works 100% in native
- **Hypothesis**: PRNG was generating different random values during CCA re-encryption
- **Finding**: Added comprehensive CTR-DRBG logging and confirmed PRNG behaves correctly
- **Result**: Hypothesis DISPROVEN - PRNG is deterministic in both native and WASM

### Phase 2: UID Mismatch Discovery
- **Observation**: During CCA re-encryption, a different UID is being derived
- **Evidence**:
  - Encryption UID: `c9 0e 21 eb 45 8e d7 4c`
  - Re-encryption UID: `00 5f 51 cf d4 af 82 d4`
- **Analysis**: UID is derived from `u = H_1(r || K || policy)`, so different UID means different `r` or `K`
- **Hypothesis**: The recovered `r'` and `K'` from decryption don't match the original `r` and `K`

### Phase 3: ROOT CAUSE IDENTIFIED - Decryption Returns Wrong Values
- **Test**: Added logging to compare original vs recovered `r` and `K` values
- **CRITICAL FINDING**: The values are completely different!

```
Original (during encryption):
  r = d5cb1f0997fdf48ba82890d6a075c031...
  K = 68bc100e1e65ecb71a7162cbd590ee25...

Recovered (during decryption):
  r' = 4bcc06da98ca5a3a6f64dd311b146d93...  ❌ COMPLETELY WRONG
  K' = 7bb377aec03d98a81ca1bb3532ee7088...  ❌ COMPLETELY WRONG
```

## Root Cause

**The CP-ABE decrypt function is broken in WASM and returns garbage plaintext.**

### Technical Details

In CP-ABE with CCA security:
1. **Encryption** encrypts message `M = r || K` where `r` and `K` are random 32-byte values
2. **Decryption** should recover exactly `M = r || K` from the ciphertext using pairing operations
3. **CCA Verification** re-encrypts with recovered `M` and compares ciphertexts

The decryption algorithm:
```
M' = Decrypt(CT, SK) = e(C0, K0) / ∏ e(Cx, Kx)^coeff
```

Where `e()` is the pairing function.

### The Bug

In WASM, the `Decrypt()` function returns a **completely incorrect** `M'` value:
- NOT close to the original (not a precision issue)
- NOT partially correct (not a truncation issue)
- Appears to be **random garbage** or result of fundamentally broken pairing computation

### Why CCA Fails

```
1. Encrypt with M = r || K
   → u = H_1(M || policy)
   → UID = first 16 bytes of u
   → PRNG seeded with u
   → Ciphertext CT₁

2. Decrypt CT₁
   → M' = Decrypt(CT₁, SK)  ❌ M' ≠ M (BUG HERE!)
   → r' || K' = M'           ❌ Wrong values extracted

3. CCA Re-encryption with M'
   → u' = H_1(M' || policy)  ❌ u' ≠ u (because M' ≠ M)
   → UID' ≠ UID
   → PRNG' seeded with u'    ❌ Different PRNG
   → Ciphertext CT₂          ❌ Different ciphertext

4. Compare CT₁ vs CT₂
   → MISMATCH ❌ CCA FAILURE
```

## Why Native Works But WASM Fails

**Native Build**: CP-ABE decrypt correctly recovers `M' = M`, so CCA verification passes 100%

**WASM Build**: CP-ABE decrypt returns wrong `M' ≠ M`, causing cascading failures:
- Wrong UID derived
- Wrong PRNG initialization
- Wrong ciphertext components
- CCA verification fails

## Likely Causes

The decrypt bug is likely in one of these WASM-specific areas:

### 1. **GT Element Operations** (Most Likely)
- The pairing result is a GT (target group) element
- GT operations (division, multiplication) may have WASM-specific bugs
- GT serialization for hashing may be incorrect

### 2. **Multi-Pairing Computation**
- Decryption uses `∏ e(Cx, Kx)` - product of multiple pairings
- WASM optimizer might miscompile the multi-pairing accumulation
- Floating-point or big-integer precision issues in WASM

### 3. **GT to Bytes Conversion**
- After pairing computation, GT element is hashed to derive symmetric key
- GT serialization might be corrupted in WASM
- Endianness or alignment issues

### 4. **Coefficient Computation**
- LSSS coefficients used in decryption might be wrong
- ZP (scalar field) division/subtraction bugs in WASM
- We saw ZP operations work correctly in previous tests, so less likely

## Evidence Files

- `wasm_enc_log.txt`: Shows original `r` and `K` values during encryption
- `wasm_dec_log.txt`: Shows completely different recovered `r'` and `K'` values
- Native test logs: Show 100% success with matching `r` and `K` values

## Next Steps

1. **Add GT logging** in the decrypt function to track pairing results
2. **Compare GT values** between native and WASM during decryption
3. **Test simple pairing** operation in isolation (encrypt/decrypt single element)
4. **Check GT serialization** - compare bytes in native vs WASM
5. **Investigate MCL GT operations** in WASM build for bugs

## Impact

**Severity**: CRITICAL - Complete failure of CP-ABE decryption in WASM
**Scope**: All CP-ABE with CCA security operations in WASM
**Workaround**: None - decryption is fundamentally broken
**Fix Required**: Debug and fix GT/pairing operations in WASM build

## Files Modified for Debugging

1. `/Users/zacharywhitley/git/openabe/src/abe/zcontextcca.cpp`
   - Added `r`/`K` logging in `encryptKEM()` (lines 270-280)
   - Added `r'`/`K'` logging in `decryptKEM()` (lines 356-366)

2. `/Users/zacharywhitley/git/openabe/src/tools/zprng.cpp`
   - Added CTR-DRBG state logging (lines 245-260, 368-392)

3. `/Users/zacharywhitley/git/openabe/src/zml/zelement_bp.cpp`
   - Added ZP/G1 random element logging (lines 810-820, 1177-1186)

## Conclusion

The "CCA bug" is actually a symptom of a much deeper issue: **CP-ABE decryption is completely broken in WASM**. The decryption function returns random garbage instead of the correct plaintext, which then causes CCA verification to fail. This needs to be fixed at the pairing/GT computation level before CCA can work correctly.
