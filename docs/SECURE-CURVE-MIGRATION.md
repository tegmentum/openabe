# Migrating to More Secure Pairing-Friendly Curves

## Problem: BN254 Security Degradation

### Background

**BN254 (also called BN256 or BN_P254)** was designed to provide ~128-bit security level, but recent cryptanalytic advances have degraded its security:

- **Original estimate (2005)**: ~128-bit security
- **After Kim-Barbulescu (2016)**: ~110-bit security
- **Current consensus (2020+)**: ~100-bit security

This is due to advances in discrete logarithm attacks on pairing-friendly curves, particularly the **Tower Number Field Sieve** and related algorithms.

### Security Level Comparison

| Curve Type | Embedding Degree | Field Size | Current Security | Recommended For |
|------------|------------------|------------|------------------|-----------------|
| **BN254** | k=12 | 254-bit | ~100 bits | ⚠️ Legacy only |
| **BN382** | k=12 | 382-bit | ~128 bits | ✅ Standard security |
| **BN462** | k=12 | 462-bit | ~128 bits | ✅ Standard security |
| **BLS12-381** | k=12 | 381-bit | ~128 bits | ✅✅ Best choice |
| **BLS12-461** | k=12 | 461-bit | ~128 bits | ✅ Extra margin |
| **BLS24-509** | k=24 | 509-bit | ~192 bits | 🔒 High security |
| **KSS16-339** | k=16 | 339-bit | ~128 bits | ✅ Alternative |

### Recommended: BLS12-381

**BLS12-381** is the current industry standard:
- ✅ Designed by Zcash team with security foremost
- ✅ ~128-bit security (conservative estimate)
- ✅ Efficient implementation
- ✅ Widely adopted (Ethereum 2.0, Zcash, Filecoin, etc.)
- ✅ Mature libraries available
- ✅ Smaller signatures than BN curves
- ✅ Better security margins

## What Needs to Change

### 1. Math Library Support

#### Option A: RELIC with BLS12-381 ✅ **EASIEST**

RELIC 0.7.0+ supports BLS12-381 natively!

**Changes needed:**
```cpp
// Current default in openabe.h:
const std::string DEFAULT_BP_PARAM = "BN_P254";

// Change to:
const std::string DEFAULT_BP_PARAM = "BLS12_381";
```

**RELIC configuration:**
```bash
cmake -DCURVE=BLS381 ...
```

**Status:** ✅ Already supported by RELIC 0.7.0!

#### Option B: MCL with BLS12-381 ✅ **ALSO SUPPORTED**

MCL supports BLS12-381 as well:

```bash
make MCL_FP_BIT=381 MCL_FR_BIT=256 MCL_USE_BLS12_381=1
```

**MCL initialization:**
```cpp
// Instead of:
mclBn_init(mclBn_CurveFp254BNb, MCLBN_COMPILED_TIME_VAR);

// Use:
mclBn_init(MCL_BLS12_381, MCLBN_COMPILED_TIME_VAR);
```

**Status:** ✅ Supported in MCL 1.28+

#### Option C: Use arkworks or blst Libraries

**blst** (by Supranational):
- Extremely fast BLS12-381 implementation
- Used by Ethereum 2.0
- C API available
- Audited and battle-tested

**arkworks** (Rust):
- Multiple pairing-friendly curves
- Academic quality implementation
- Rust library with FFI

### 2. OpenABE Code Changes

#### Changes to Constants

**File: `src/include/openabe/utils/zconstants.h`**

```cpp
// Add new curve IDs
typedef enum _OpenABECurveID {
  OpenABE_NONE_ID = 0,
  // EC curves (ECDSA)
  OpenABE_NIST_P256_ID = 1,
  OpenABE_NIST_P384_ID = 2,
  OpenABE_NIST_P521_ID = 3,
  // Pairing curves (existing)
  OpenABE_BN_P158_ID = 10,
  OpenABE_BN_P254_ID = 11,  // DEPRECATED - only ~100 bit security
  OpenABE_BN_P256_ID = 12,
  OpenABE_BN_P382_ID = 13,
  OpenABE_BN_P638_ID = 14,
  // New secure pairing curves
  OpenABE_BLS12_381_ID = 20,  // RECOMMENDED - 128 bit security
  OpenABE_BLS12_461_ID = 21,
  OpenABE_BLS24_509_ID = 22,
  OpenABE_KSS16_339_ID = 23,
} OpenABECurveID;
```

**File: `src/include/openabe/openabe.h`**

```cpp
// Update default (CRITICAL CHANGE)
const std::string DEFAULT_BP_PARAM = "BLS12_381";  // Was: "BN_P254"

// Or for extra security:
const std::string DEFAULT_BP_PARAM = "BLS12_461";
```

#### Add Curve String Mappings

**File: `src/openabe.cpp`**

```cpp
OpenABECurveID OpenABE_convertStringToCurveID(const string paramsID) {
  OpenABECurveID curveID = OpenABE_NONE_ID;

  // Existing curves
  if (paramsID == "NIST_P256") {
    curveID = OpenABE_NIST_P256_ID;
  } else if (paramsID == "NIST_P384") {
    curveID = OpenABE_NIST_P384_ID;
  } else if (paramsID == "NIST_P521") {
    curveID = OpenABE_NIST_P521_ID;
  }
  // Legacy pairing curves (mark as deprecated)
  else if (paramsID == "BN_P254" || paramsID == "BN_P256") {
    fprintf(stderr, "WARNING: BN254 provides only ~100 bit security. "
                    "Consider using BLS12_381 instead.\n");
    curveID = OpenABE_BN_P254_ID;
  } else if (paramsID == "BN_P382") {
    curveID = OpenABE_BN_P382_ID;
  } else if (paramsID == "BN_P638") {
    curveID = OpenABE_BN_P638_ID;
  }
  // New secure curves
  else if (paramsID == "BLS12_381") {
    curveID = OpenABE_BLS12_381_ID;
  } else if (paramsID == "BLS12_461") {
    curveID = OpenABE_BLS12_461_ID;
  } else if (paramsID == "BLS24_509") {
    curveID = OpenABE_BLS24_509_ID;
  } else if (paramsID == "KSS16_339") {
    curveID = OpenABE_KSS16_339_ID;
  } else {
    fprintf(stderr, "ERROR: Unknown curve parameter: %s\n", paramsID.c_str());
    return OpenABE_NONE_ID;
  }

  return curveID;
}

string OpenABE_convertCurveIDToString(OpenABECurveID id) {
  switch (id) {
  case OpenABE_NIST_P256_ID:
    return "NIST_P256";
  case OpenABE_NIST_P384_ID:
    return "NIST_P384";
  case OpenABE_NIST_P521_ID:
    return "NIST_P521";
  case OpenABE_BN_P254_ID:
    return "BN_P254";  // Deprecated
  case OpenABE_BN_P256_ID:
    return "BN_P256";  // Deprecated
  case OpenABE_BN_P382_ID:
    return "BN_P382";
  case OpenABE_BN_P638_ID:
    return "BN_P638";
  case OpenABE_BLS12_381_ID:
    return "BLS12_381";
  case OpenABE_BLS12_461_ID:
    return "BLS12_461";
  case OpenABE_BLS24_509_ID:
    return "BLS24_509";
  case OpenABE_KSS16_339_ID:
    return "KSS16_339";
  default:
    return "INVALID";
  }
}
```

#### Update RELIC Initialization

**File: `src/zml/zpairing.cpp`** (for RELIC backend)

```cpp
OpenABEPairing* OpenABE_createNewPairing(const std::string &pairingParams) {
  OpenABECurveID curveID = getPairingCurveID(pairingParams);

  switch(curveID) {
    case OpenABE_BN_P254_ID:
      fprintf(stderr, "WARNING: BN254 provides only ~100 bit security\n");
      return new BPGroup(OpenABE_BN_P254_ID);  // Legacy support

    case OpenABE_BLS12_381_ID:
      return new BPGroup(OpenABE_BLS12_381_ID);  // RECOMMENDED

    case OpenABE_BLS12_461_ID:
      return new BPGroup(OpenABE_BLS12_461_ID);

    // ... other curves

    default:
      fprintf(stderr, "ERROR: Unsupported curve\n");
      return nullptr;
  }
}
```

#### Update MCL Initialization

**File: `src/zml/zelement_mcl.c`** (for MCL backend)

```cpp
void zml_init() {
  if (!mcl_initialized) {
    int ret;

    #ifdef MCL_USE_BLS12_381
      // BLS12-381 (RECOMMENDED - 128 bit security)
      ret = mclBn_init(MCL_BLS12_381, MCLBN_COMPILED_TIME_VAR);
      fprintf(stderr, "[MCL INIT] MCL initialized for BLS12-381\n");
    #else
      // BN254 (LEGACY - only 100 bit security)
      ret = mclBn_init(mclBn_CurveFp254BNb, MCLBN_COMPILED_TIME_VAR);
      fprintf(stderr, "[MCL INIT] WARNING: Using BN254 (~100 bit security)\n");
    #endif

    if (ret != 0) {
      fprintf(stderr, "MCL initialization failed: %d\n", ret);
      exit(1);
    }
    mcl_initialized = 1;
  }
}
```

### 3. Build System Changes

#### RELIC Configuration

**File: `deps/relic/Makefile`**

```makefile
# Current (BN254):
RELIC_CMAKE_FLAGS = -DCURVE=BN_P254 ...

# Change to BLS12-381:
RELIC_CMAKE_FLAGS = -DCURVE=BLS12_381 -DFP_PRIME=381 -DCOMP="-O3 -funroll-loops" ...

# Or for extra security, BLS12-461:
RELIC_CMAKE_FLAGS = -DCURVE=BLS12_461 -DFP_PRIME=461 ...
```

#### MCL Configuration

**File: `deps/mcl/Makefile`**

```makefile
# Current (BN254):
$(MCL_DIR)/lib/libmcl.a: mcl-$(VERSION).tar.gz
	cd $(MCL_DIR) && $(MAKE) -j4 \
		MCL_USE_GMP=0 \
		MCL_USE_OPENSSL=0 \
		MCL_USE_LLVM=1 \
		MCL_FP_BIT=256 \
		MCL_FR_BIT=256

# Change to BLS12-381:
$(MCL_DIR)/lib/libmcl.a: mcl-$(VERSION).tar.gz
	cd $(MCL_DIR) && $(MAKE) -j4 \
		MCL_USE_GMP=0 \
		MCL_USE_OPENSSL=0 \
		MCL_USE_LLVM=1 \
		MCL_FP_BIT=381 \
		MCL_FR_BIT=255 \
		MCL_USE_BLS12_381=1
```

#### Makefile.common Updates

**File: `Makefile.common`**

```makefile
# Add configuration variable for curve selection
PAIRING_CURVE ?= BLS12_381  # Default to secure curve

# Pass to compiler
CXXFLAGS += -DPAIRING_CURVE_$(PAIRING_CURVE)

# Allow override:
# make PAIRING_CURVE=BN_P254  # Legacy
# make PAIRING_CURVE=BLS12_381  # Recommended (default)
# make PAIRING_CURVE=BLS12_461  # Extra security
```

### 4. Testing Changes

All existing tests should work with new curves, but need to verify:

```cpp
// test_bls12_381.cpp - New test file
#include <openabe/openabe.h>

using namespace oabe;

int main() {
    InitializeOpenABE();

    // Test CP-ABE with BLS12-381
    unique_ptr<OpenABEContextSchemeCCA> cpabe =
        OpenABE_createContextABESchemeCCA(OpenABE_SCHEME_CP_WATERS_CCA);

    // Use BLS12-381 explicitly
    cpabe->generateParams("BLS12_381");

    // Rest of test...
    // (keygen, encrypt, decrypt should work identically)

    ShutdownOpenABE();
    return 0;
}
```

### 5. Performance Implications

**Expected Performance Changes (BLS12-381 vs BN254):**

| Operation | BN254 | BLS12-381 | Change |
|-----------|-------|-----------|--------|
| **G1 mul** | 100 μs | 120 μs | +20% |
| **G2 mul** | 250 μs | 300 μs | +20% |
| **Pairing** | 1.5 ms | 1.8 ms | +20% |
| **Keygen** | 5 ms | 6 ms | +20% |
| **Encrypt** | 10 ms | 12 ms | +20% |
| **Decrypt** | 15 ms | 18 ms | +20% |

**Summary:** ~20% slower, but still fast enough for most applications.

### 6. Backward Compatibility

**Option A: Keep BN254 Support (Deprecated)**

```cpp
// Allow users to explicitly choose BN254 with warning
unique_ptr<OpenABEContextSchemeCCA> cpabe =
    OpenABE_createContextABESchemeCCA(OpenABE_SCHEME_CP_WATERS_CCA);

cpabe->generateParams("BN_P254");  // Emits warning
```

**Option B: Data Migration Tool**

For existing systems with BN254 keys/ciphertexts:

```cpp
// Key migration tool
OpenABE_ERROR migrateKey(
    const string& old_key_path,    // BN254 key
    const string& new_key_path,    // BLS12-381 key
    const string& new_curve = "BLS12_381"
) {
    // 1. Load old key
    // 2. Extract attributes/policy (not curve-specific)
    // 3. Generate new key with same attributes on new curve
    // 4. Save new key

    // NOTE: Cannot decrypt old ciphertexts with new key!
    // Must re-encrypt data.
}
```

**Option C: Dual-Curve Support**

For transition period, support both curves:

```cpp
// Detect curve from serialized data
OpenABECurveID detectCurve(const OpenABEByteString& data) {
    // Check header/metadata
    // Return curve ID
}

// Auto-select correct implementation
OpenABE_ERROR decrypt(const OpenABEByteString& ciphertext) {
    OpenABECurveID curve = detectCurve(ciphertext);

    if (curve == OpenABE_BN_P254_ID) {
        // Use BN254 implementation (legacy)
        return decrypt_bn254(ciphertext);
    } else if (curve == OpenABE_BLS12_381_ID) {
        // Use BLS12-381 implementation (current)
        return decrypt_bls12_381(ciphertext);
    }

    return OpenABE_ERROR_INVALID_INPUT;
}
```

## Implementation Roadmap

### Phase 1: Library Support (1-2 weeks)

1. ✅ Verify RELIC 0.7.0 supports BLS12-381 (already done)
2. Update RELIC build configuration for BLS12-381
3. Update MCL build configuration for BLS12-381
4. Add curve ID constants and mappings
5. Test math operations with new curve

### Phase 2: OpenABE Integration (2-3 weeks)

1. Update default curve to BLS12-381
2. Add curve selection API
3. Update initialization code
4. Add deprecation warnings for BN254
5. Update all tests to use BLS12-381
6. Performance benchmarking

### Phase 3: Testing & Documentation (1-2 weeks)

1. Comprehensive testing of all schemes
2. Cross-curve compatibility testing
3. Performance regression testing
4. Update documentation
5. Add migration guide
6. Security audit

### Phase 4: Deployment (ongoing)

1. Release new version with BLS12-381 default
2. Provide migration tools
3. Support transition period (both curves)
4. Eventually deprecate BN254 entirely

## Recommended Configuration

```makefile
# For maximum security (2024+)
PAIRING_CURVE = BLS12_381
ZML_LIB = (use RELIC or MCL, both support it)
EC_LIB = with_openssl  # For ECDSA

# Security levels achieved:
# - Pairing operations: ~128 bits (BLS12-381)
# - ECDSA operations: ~128 bits (NIST P-256)
# - Symmetric crypto: 128 bits (AES-128-GCM)
```

## References

1. **BLS12-381 Specification**: https://electriccoin.co/blog/new-snark-curve/
2. **RELIC BLS12-381**: https://github.com/relic-toolkit/relic/tree/main
3. **MCL BLS12-381**: https://github.com/herumi/mcl
4. **Security Analysis**: "Updating key size estimations for pairings" (2017)
5. **Ethereum 2.0 BLS**: https://github.com/ethereum/consensus-specs

## Cost-Benefit Analysis

### Benefits ✅

1. **Security**: 128-bit security (vs ~100-bit for BN254)
2. **Future-proof**: Designed with modern attacks in mind
3. **Industry standard**: Used by major projects
4. **Better signature sizes**: BLS signatures are more compact
5. **Confidence**: Extensive cryptanalytic review

### Costs ❌

1. **Performance**: ~20% slower
2. **Migration**: Existing keys/data incompatible
3. **Testing**: Need to verify all operations
4. **Code changes**: ~1000 lines of modifications

### Verdict: **Strongly Recommended** 🎯

The security improvement far outweighs the modest performance cost. BN254 should be deprecated for new deployments.
