# PKE Hybrid Backend Limitation

## Issue Summary

The hybrid MCL+OpenSSL backend **cannot support PKE operations** (OPDH, ECDSA, ECDH) in its current implementation due to a fundamental architectural incompatibility.

## Root Cause

The OpenABE codebase uses a single `bignum_t` type throughout for representing:
1. **Pairing curve scalars**: Elements in the scalar field Fr of BLS12-381 or BN254 curves
2. **EC curve orders**: The order of NIST P-256, P-384, P-521 elliptic curve groups

When the hybrid backend is enabled (`BP_WITH_MCL` + `EC_WITH_OPENSSL`):
- `bignum_t` is defined as `mclBnFr` (MCL's scalar field element)
- NIST curve orders (256-521 bits as plain integers) cannot be represented as `mclBnFr` (scalar modulo BLS12-381's r)

### Technical Details

**BLS12-381 Scalar Field Modulus (r)**:
```
r = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
  ≈ 2^255
```

**NIST P-256 Order**:
```
n = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
  ≈ 2^256
```

These values are not compatible - you cannot store a 256-bit integer modulo one prime into a field element modulo a completely different prime.

### Where It Fails

1. **`ECGroup::ECGroup(OpenABECurveID id)`** (zelement_ec.cpp:447)
   - Tries to store NIST curve order in `bignum_t order` (which is `mclBnFr`)
   - Original code called: `ec_bignum_to_bignum(ec_order, order)`
   - This attempts: `mclBnFr_setStr(&bn, hex_str, ...)` with NIST order
   - **Result**: Undefined behavior, potential segfault

2. **`OpenABEEllipticCurve::randomZP()`** (zelliptic.cpp:201)
   - Calls `getGroupOrder(result.order)` to get NIST curve order
   - Then calls `result.setRandom(rng)` which does modular arithmetic with the order
   - With order set to zero (workaround), random generation fails

3. **All `ZP_t` operations** requiring the curve order
   - Addition, multiplication, modular inverse
   - All require valid order for modular reduction

## Current Workaround

The fix applied in this session:
```cpp
// In ECGroup::ECGroup() - avoid the problematic conversion
#if defined(BP_WITH_MCL) && defined(EC_WITH_OPENSSL)
    // Leave order uninitialized - cannot convert NIST order to MCL Fr
#else
    ec_get_order(group, order);
#endif
```

**Effect**: Prevents segfault during initialization, but EC operations remain non-functional.

## Why ABE Still Works

ABE operations (CP-ABE, KP-ABE) only use **pairing** operations:
- G1, G2, GT group elements
- Fr scalars for BLS12-381 or BN254
- **Never use EC operations** (no call to ECGroup for NIST curves)

Therefore, ABE is completely unaffected by the PKE issue.

## Architectural Solutions

### Option 1: Separate Bignum Types (Complex, Complete)

Modify OpenABE to use different bignum types in different contexts:
```cpp
// For pairing operations
typedef mclBnFr pairing_scalar_t;

// For EC operations
typedef BIGNUM* ec_scalar_t;

// Context-specific usage
class PairingGroup {
    pairing_scalar_t order;
};

class ECGroup {
    ec_scalar_t order;  // NOT bignum_t
};
```

**Pros**: Clean separation, full functionality
**Cons**: Requires extensive refactoring of ZP_t, G_t, and all crypto schemes

### Option 2: EC-Only Mode (Simple, Limited)

Disable MCL when using OpenSSL EC:
```makefile
# Use OpenSSL for everything (no hybrid)
CXXFLAGS += -DEC_WITH_OPENSSL -DBN_WITH_OPENSSL

# Don't define BP_WITH_MCL
```

**Pros**: PKE works fine with OpenSSL BIGNUM throughout
**Cons**: Loses MCL's superior pairing implementation for ABE

### Option 3: Maintain Separate Builds (Current Recommendation)

Keep two build configurations:
1. **ABE Build**: `BP_WITH_MCL` only - for CP-ABE, KP-ABE (production ready)
2. **PKE Build**: `EC_WITH_OPENSSL + BN_WITH_OPENSSL` - for OPDH, ECDSA (not yet implemented)

**Pros**: Each build works correctly for its use case
**Cons**: Cannot mix ABE + PKE in same application

## Recommendation

For immediate production use:
- **Use ABE build** (`BP_WITH_MCL` only) - fully functional, tested, performant
- **Do NOT use hybrid mode** for applications requiring PKE operations

For future development:
- Implement **Option 1** (separate bignum types) for true hybrid support
- Estimated effort: 2-3 weeks of careful refactoring + testing

## Testing Status

| Feature | Hybrid Backend Status | Notes |
|---------|----------------------|-------|
| CP-ABE | ✅ Fully Functional | Uses MCL only, no EC interaction |
| KP-ABE | ✅ Fully Functional | Uses MCL only, no EC interaction |
| Symmetric Crypto | ✅ Fully Functional | No bignum types involved |
| OPDH (PKE) | ❌ Non-Functional | Requires NIST curve order in bignum_t |
| ECDSA | ❌ Non-Functional | Requires NIST curve order in bignum_t |
| ECDH | ❌ Non-Functional | Requires NIST curve order in bignum_t |

## Conclusion

The hybrid MCL+OpenSSL backend successfully achieves its primary goal: **enabling MCL-based ABE operations**. However, OpenSSL EC operations (PKE schemes) are not compatible with the current architecture without substantial refactoring.

**Bottom Line**: Use the hybrid backend for ABE only. For PKE, use a separate OpenSSL-only build configuration.

---

**Date**: 2025-10-28
**Status**: DOCUMENTED - Architectural limitation identified and explained
