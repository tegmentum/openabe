# MCL CP-ABE Decryption Issue

## Summary

CP-ABE (Ciphertext-Policy Attribute-Based Encryption) decryption is **broken** when using the MCL (Cybozu Cryptography Library) backend. Encryption works correctly, but decryption computes an incorrect GT element, causing verification failure.

## Symptoms

- CP-ABE setup, keygen, and encryption complete successfully
- Multi-pairing operations return non-zero values
- Decryption computes wrong GT element:
  - Encryption computes: `C = e(g1, g2)^(alpha*s)`
  - Decryption should recover this same value
  - Instead, decryption computes a completely different GT element
- CCA verification fails with "ciphertexts don't match" error

## Test Results

### Encryption Output
```
[CP-ABE ENCRYPT DEBUG] GT element C = A^s: 0E2DB9A19DD4D094...
```

### Decryption Output
```
[CP-ABE DEBUG] final GT element: 5AAC6ABBAB119FFA...
```

These values are completely different, indicating the decryption formula is computing incorrectly.

## Technical Details

### Decryption Formula
The CP-ABE Waters scheme decryption computes:
```
final = e(Cprime, K) / (prodT * e(prod1, L))
```

Where:
- `Cprime = g1^s` (from ciphertext)
- `K = g2^alpha * (g2^a)^t` (from user key)
- `prodT = product(e(KX_i^w_i, D_i))` (multi-pairing)
- `prod1 = product(C_i^w_i)` (G1 accumulation)
- `L = g2^t` (from user key)
- `w_i` are LSSS reconstruction coefficients

### Verified Working Components
- ✅ MCL initialization and curve setup (BN254)
- ✅ G1/G2 point generation and serialization
- ✅ Simple pairings: `e(g1, g2)` returns correct non-zero values
- ✅ Multi-pairing: returns non-zero GT elements
- ✅ GT exponentiation: `A^s` works correctly
- ✅ G1/G2 exponentiation: `g1^s`, `g2^t` work correctly
- ✅ LSSS secret sharing and coefficient recovery
- ✅ CP-ABE encryption: produces valid ciphertext

### Broken Component
- ❌ **CP-ABE decryption GT computation**: The final pairing/division formula produces wrong result

### ROOT CAUSE IDENTIFIED ✓

**MCL's G1 exponentiation with negative exponents is BROKEN!**

Test results show that:
- `A^x * A^(-x)` does NOT equal the identity element
- This breaks CP-ABE because encryption uses: `C_attr = g1a^lambda * h^(-r_i)`
- The negative exponent `h^(-r_i)` does not compute the correct inverse

Verified working:
- ✅ `(A * B)^x = A^x * B^x` (distributive law)
- ✅ `(A^x)^y = A^(x*y)` (exponentiation composition)
- ❌ `A^x * A^(-x) = identity` (negative exponent inverse)

See test results in `test-mcl-g1-exp.cpp` for full details.

### Possible Fixes

1. **Workaround**: Avoid negative exponents in G1/G2 operations
2. **MCL Fix**: Report bug to MCL maintainers - `mclBnG1_mul` with negative scalar
3. **Use RELIC**: RELIC backend works correctly

## Workaround

**Use RELIC instead of MCL** for CP-ABE operations. RELIC backend works correctly.

To build with RELIC:
```bash
# Build RELIC dependency
cd deps/relic
make

# Build OpenABE without MCL flag
cd ../..
make CXXFLAGS="-DBP_WITH_RELIC"
```

## Impact

- **KP-ABE**: Not tested, likely also affected
- **PKE**: Works correctly with MCL
- **PKSig**: Works correctly with MCL
- **CP-ABE**: **BROKEN** with MCL
- **CryptoBox (uses CP-ABE)**: **BROKEN** with MCL

## Files Involved

- `src/abe/zcontextcpwaters.cpp:333-426` - CP-ABE decryptKEM function
- `src/zml/zelement_bp.cpp:305-373` - multi_bp_map_op (multi-pairing)
- `src/zml/zelement_mcl.c:430-436` - gt_div_op (GT division)
- `src/zml/zelement_mcl.c:294-303` - g1_set_to_infinity (G1 identity)

## Debug Output Example

Complete test showing the issue:
```bash
./test-cpabe-mcl
```

Output shows:
- Encryption: `C = 0E2DB9A1...`
- Decryption: `final = 5AAC6ABB...` (should equal C, but doesn't!)
- Re-encryption with wrong `r||K` fails verification

## Next Steps

To fix this issue, someone needs to:

1. **Verify MCL pairing implementation** with standalone tests
2. **Test GT division** independently: `a / b` should equal `a * inv(b)`
3. **Test GT multiplication** independently: ensure associativity
4. **Compare with RELIC** implementation to identify algorithmic differences
5. **Check MCL version compatibility**: We're using MCL 1.61, maybe upgrade needed?
6. **Contact MCL maintainers** if library bug is suspected

## References

- Waters CP-ABE Paper: "Ciphertext-Policy Attribute-Based Encryption"
- MCL Library: https://github.com/herumi/mcl
- OpenABE: https://github.com/zeutro/openabe

## Date

Issue identified: October 2024
MCL Version: 1.61
OpenSSL Version: 3.3.2
