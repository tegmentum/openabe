# ABE-CBOR v1 Implementation Plan for OpenABE

## Overview

This document outlines the implementation plan for adding ABE-CBOR v1 portable serialization to OpenABE. The goal is to create a deterministic, crypto-agile, and interoperable serialization format for ABE cryptographic materials.

## Design Goals

1. **Deterministic & stable**: Integer map keys; deterministic CBOR (CTAP2/Dag-CBOR rules)
2. **Crypto-agile**: Explicit suite (scheme + curve) and group-element encoding
3. **MA/DCPABE-ready**: Support for multi-authority with `auth_id` and delegation blocks
4. **Policy/attribute clarity**: Canonicalized attributes; Boolean-AST or MSP/LSSS encodings
5. **Cross-platform**: Works with native (C++) and WASM builds

## Current State

OpenABE currently uses:
- **Native**: Custom binary serialization via `ZObject` base class
- **Format**: Base64-encoded binary blobs with proprietary structure
- **Issues**:
  - Not interoperable with other ABE libraries
  - No crypto-agility (curve/scheme implicit)
  - No standardized attribute/policy encoding
  - Not deterministic (can vary across implementations)

## Implementation Phases

### Phase 1: Foundation & Specification (Week 1-2)

#### 1.1 Create Specification Documents
**Files to create:**
- `docs/ABE-CBOR-SPEC.md` - Complete CDDL specification
- `docs/ABE-CBOR-REGISTRY.md` - Suite/curve/encoding registry
- `docs/ABE-CBOR-EXAMPLES.md` - Test vectors and examples

**Tasks:**
- [ ] Document complete CDDL schema from design
- [ ] Define OpenABE-specific scheme IDs: `"cpabe-waters", "kpabe-gpsw"`
- [ ] Define MCL encoding profiles for BLS12-381 and BN254
- [ ] Create attribute canonicalization rules
- [ ] Document policy encoding specifications

#### 1.2 CBOR Library Integration
**Options:**
1. **tinycbor** - Lightweight, C-based, used in IoT (Recommended)
2. **libcbor** - Full-featured, C-based
3. **cn-cbor** - Minimal footprint

**Decision criteria:**
- ✅ Deterministic encoding support
- ✅ WASM compatibility (Emscripten)
- ✅ Active maintenance
- ✅ Permissive license (MIT/Apache)

**Tasks:**
- [ ] Evaluate CBOR libraries for OpenABE requirements
- [ ] Select library and add to `deps/`
- [ ] Update build scripts (`Makefile.common`, `build-deps-wasm.sh`)
- [ ] Create wrapper API in `src/cbor/zcbor_wrapper.h`

### Phase 2: Core Serialization Primitives (Week 3-4)

#### 2.1 Group Element Encoding
**File:** `src/cbor/zge_encoding.cpp`

**Implementation:**
```cpp
class ZGroupElementEncoder {
public:
    // Encode MCL elements to CBOR bytes
    OpenABEByteString encodeG1(const mcl::bn::G1& elem, GEEncoding enc);
    OpenABEByteString encodeG2(const mcl::bn::G2& elem, GEEncoding enc);
    OpenABEByteString encodeGT(const mcl::bn::GT& elem, GEEncoding enc);

    // Decode CBOR bytes to MCL elements
    bool decodeG1(mcl::bn::G1& elem, const OpenABEByteString& data, bool subgroupCheck);
    bool decodeG2(mcl::bn::G2& elem, const OpenABEByteString& data, bool subgroupCheck);
    bool decodeGT(mcl::bn::GT& elem, const OpenABEByteString& data, bool subgroupCheck);
};

enum class GEEncoding {
    IETF_COMPRESSED = 0,   // BLS12-381 IETF draft format
    UNCOMPRESSED = 1,       // Full coordinate representation
    MCL_CANONICAL = 2       // MCL's native format (document layout)
};
```

**Tasks:**
- [ ] Implement MCL element serialization with endianness control
- [ ] Add subgroup membership checks on decode
- [ ] Handle infinity/identity points correctly
- [ ] Add compressed/uncompressed point encoding
- [ ] Write unit tests for G1/G2/GT encoding round-trips

#### 2.2 Attribute Canonicalization
**File:** `src/cbor/zattr_canon.cpp`

**Implementation:**
```cpp
class ZAttributeCanonicalizer {
public:
    // Canonicalize attribute value based on type
    OpenABEByteString canonicalize(const ZAttribute& attr);

    // Normalize string attributes (UTF-8 NFC)
    std::string normalizeString(const std::string& value);

    // Sort attribute set deterministically
    std::vector<ZAttribute> sortAttributes(const std::vector<ZAttribute>& attrs);

    // Compare attributes for ordering
    static int compare(const ZAttribute& a, const ZAttribute& b);
};

enum class AttributeType {
    STRING = 0,
    INTEGER = 1,
    BYTES = 2,
    SET = 3,
    RANGE = 4
};
```

**Tasks:**
- [ ] Implement UTF-8 NFC normalization for string attributes
- [ ] Add integer canonicalization (no leading zeros)
- [ ] Implement set sorting (bytewise CBOR order)
- [ ] Add range attribute support
- [ ] Create attribute comparison function for stable ordering

#### 2.3 Policy Encoding
**File:** `src/cbor/zpolicy_encoding.cpp`

**Implementation:**
```cpp
class ZPolicyEncoder {
public:
    // Encode policy tree to Boolean AST (RPN)
    OpenABEByteString encodeBooleanAST(const OpenABEPolicy& policy);

    // Encode LSSS matrix to MSP format
    OpenABEByteString encodeMSP(const OpenABELSSS& lsss);

    // Decode policy from CBOR
    std::unique_ptr<OpenABEPolicy> decodeBooleanAST(const OpenABEByteString& data);
    std::unique_ptr<OpenABELSSS> decodeMSP(const OpenABEByteString& data);
};

enum class PolicyEncoding {
    BOOL_AST = 0,   // Boolean formula as RPN token list
    MSP = 1         // LSSS matrix representation
};
```

**Tasks:**
- [ ] Convert OpenABE policy trees to RPN token lists
- [ ] Implement MSP matrix encoding with row-attribute mapping
- [ ] Add attribute reference resolution (indices into sorted AttrSet)
- [ ] Handle threshold gates (k-of-n) in Boolean AST
- [ ] Write policy encoding/decoding tests

#### 2.4 Deterministic CBOR Serialization
**File:** `src/cbor/zcbor_deterministic.cpp`

**Implementation:**
```cpp
class ZDeterministicCBOR {
public:
    // Encode with canonical ordering and shortest forms
    OpenABEByteString encode(const CBORMap& data);

    // Verify deterministic encoding
    bool verifyDeterministic(const OpenABEByteString& encoded);

private:
    // Sort map keys for deterministic output
    void sortMapKeys(CBORMap& map);

    // Use shortest integer encoding
    void normalizeIntegers(CBORValue& value);
};
```

**Tasks:**
- [ ] Implement integer key sorting for maps
- [ ] Ensure shortest-form encoding for all types
- [ ] Forbid indefinite-length arrays/maps
- [ ] Add determinism verification tests
- [ ] Document CTAP2/Dag-CBOR compliance

### Phase 3: ABE Type Serialization (Week 5-6)

#### 3.1 Suite Descriptor
**File:** `src/cbor/zsuite.cpp`

**Implementation:**
```cpp
class ZSuiteDescriptor {
public:
    std::string scheme_id;        // "cpabe-waters", "kpabe-gpsw"
    std::string curve_id;         // "bls12-381", "bn254"
    uint32_t security_level;      // 128, 192, 256
    GEEncoding ge_encoding;       // Element encoding format
    bool big_endian;              // Endianness for element encoding
    bool subgroup_check;          // Require subgroup checks on decode
    std::string hash_id;          // "SHA-256", "SHA-384"
    std::string kdf_id;           // "HKDF-SHA256"

    OpenABEByteString toCBOR() const;
    static ZSuiteDescriptor fromCBOR(const OpenABEByteString& data);
};
```

**Tasks:**
- [ ] Implement suite descriptor serialization
- [ ] Add registry lookup for scheme/curve IDs
- [ ] Validate suite compatibility on decode
- [ ] Add suite versioning support

#### 3.2 MSK (Master Secret Key) Serialization
**File:** `src/cbor/zmsk_cbor.cpp`

**Integration:**
```cpp
class OpenABEContextSchemeCPA {
public:
    // Add CBOR serialization methods
    OpenABEByteString exportMSKtoCBOR() const;
    void importMSKfromCBOR(const OpenABEByteString& cbor);

private:
    ZSuiteDescriptor suite_;
};
```

**Tasks:**
- [ ] Serialize MSK group elements in scheme-specific order
- [ ] Add optional MA/DCPABE authority secrets
- [ ] Implement versioning and metadata support
- [ ] Add MSK import/export to OpenABEContextSchemeCPA

#### 3.3 MPK (Master Public Key) Serialization
**File:** `src/cbor/zmpk_cbor.cpp`

**Tasks:**
- [ ] Serialize MPK public elements tuple
- [ ] Add curve parameters and suite descriptor
- [ ] Implement MPK import/export methods
- [ ] Add backwards compatibility with legacy format

#### 3.4 SK (User Secret Key) Serialization
**File:** `src/cbor/zsk_cbor.cpp`

**Tasks:**
- [ ] Serialize SK secret elements
- [ ] Encode bound attributes (canonicalized and sorted)
- [ ] Add optional delegation proof structure
- [ ] Support auth_id for multi-authority schemes
- [ ] Implement SK import/export methods

#### 3.5 CT (Ciphertext) Serialization
**File:** `src/cbor/zct_cbor.cpp`

**Tasks:**
- [ ] Serialize ciphertext header elements
- [ ] Encode access policy (Boolean AST or MSP)
- [ ] Add encrypted payload wrapper
- [ ] Support both KEM and data encapsulation modes
- [ ] Implement CT import/export methods

### Phase 4: Testing & Validation (Week 7-8)

#### 4.1 Test Vectors
**File:** `src/test_cbor_serialization.cpp`

**Test cases:**
```cpp
TEST(ABE_CBOR, DeterministicEncoding) {
    // Verify byte-for-byte determinism across multiple encodes
}

TEST(ABE_CBOR, GroupElementRoundTrip) {
    // Test G1/G2/GT encoding/decoding
}

TEST(ABE_CBOR, AttributeCanonicalzation) {
    // Test string normalization, set sorting, etc.
}

TEST(ABE_CBOR, PolicyEncoding) {
    // Test Boolean AST and MSP encoding
}

TEST(ABE_CBOR, MSK_MPK_Serialization) {
    // Test key serialization round-trips
}

TEST(ABE_CBOR, SK_CT_Serialization) {
    // Test user key and ciphertext serialization
}

TEST(ABE_CBOR, CrossPlatformCompat) {
    // Verify native and WASM produce identical output
}

TEST(ABE_CBOR, LegacyCompatibility) {
    // Test backwards compatibility with old format
}
```

**Tasks:**
- [ ] Create comprehensive test suite
- [ ] Generate reference test vectors
- [ ] Add conformance tests for determinism
- [ ] Test cross-platform compatibility (native/WASM)
- [ ] Add fuzzing tests for robustness

#### 4.2 Interoperability Testing
**Tasks:**
- [ ] Create test vectors in hex + CBOR diagnostic format
- [ ] Document exact byte layouts for MCL encodings
- [ ] Test with external CBOR validators
- [ ] Verify subgroup checks work correctly
- [ ] Test attribute/policy canonicalization edge cases

### Phase 5: Integration & Migration (Week 9-10)

#### 5.1 OpenABE Integration
**Tasks:**
- [ ] Add CBOR export/import to all ABE contexts
- [ ] Update CLI tools to support CBOR format
- [ ] Add format auto-detection (legacy vs CBOR)
- [ ] Implement gradual migration strategy
- [ ] Update documentation and examples

#### 5.2 CLI Tools Update
**Files:** `cli/oabe_setup.cpp`, `cli/oabe_keygen.cpp`, `cli/oabe_enc.cpp`, `cli/oabe_dec.cpp`

**Add flags:**
```bash
--format=cbor|legacy  # Serialization format (default: auto-detect)
--suite=...           # Override default suite descriptor
```

**Tasks:**
- [ ] Add `--format` flag to all CLI tools
- [ ] Implement format auto-detection on import
- [ ] Default to CBOR for new operations
- [ ] Maintain legacy format support for backwards compatibility

#### 5.3 WASM Bindings
**File:** `cli-wasm/cbor_bindings.cpp`

**Tasks:**
- [ ] Expose CBOR encode/decode to JavaScript
- [ ] Ensure byte-for-byte determinism with native
- [ ] Add WASM-specific tests
- [ ] Update WASM build scripts

### Phase 6: Documentation & Release (Week 11-12)

#### 6.1 Documentation
**Files to create/update:**
- `docs/SERIALIZATION.md` - User guide for CBOR serialization
- `docs/ABE-CBOR-INTEROP.md` - Interoperability guide
- `docs/MIGRATION-GUIDE.md` - Migration from legacy format
- `README.md` - Update with CBOR support

**Tasks:**
- [ ] Write comprehensive user documentation
- [ ] Document migration strategy
- [ ] Create example code snippets
- [ ] Add troubleshooting guide

#### 6.2 Release Preparation
**Tasks:**
- [ ] Update CHANGELOG.md
- [ ] Bump version to 1.2.0
- [ ] Create release notes
- [ ] Tag release
- [ ] Update GitHub README

## Technical Decisions

### CBOR Library Selection

**Recommendation: tinycbor**

**Rationale:**
1. ✅ Lightweight and minimal dependencies
2. ✅ Supports deterministic encoding
3. ✅ WASM/Emscripten compatible
4. ✅ Apache 2.0 license (compatible with AGPL)
5. ✅ Actively maintained by Intel
6. ✅ Used in IETF standards (COSE, CBOR)

**Integration:**
```bash
# Add to deps/
cd deps
git clone https://github.com/intel/tinycbor.git
cd tinycbor
git checkout v0.6.0
```

### MCL Encoding Format

**For BLS12-381:**
- Use IETF compressed format (48 bytes G1, 96 bytes G2)
- Follow draft-irtf-cfrg-pairing-friendly-curves
- Big-endian byte order
- Always verify subgroup membership

**For BN254:**
- Document custom compressed format (no IETF standard)
- 32 bytes G1 compressed, 64 bytes G2 compressed
- Little-endian to match MCL default
- Document exact coordinate packing

### Backwards Compatibility

**Strategy:**
1. Auto-detect format on import (legacy vs CBOR)
2. Legacy format detection:
   - Starts with Base64 alphabet
   - Contains OpenABE-specific headers
3. CBOR format detection:
   - Starts with CBOR major type
   - Contains ABE-CBOR tag #6.60001
4. Default to CBOR for all new exports
5. Maintain legacy format support for 2 versions

## File Structure

```
openabe/
├── deps/
│   └── tinycbor/                    # CBOR library
├── src/
│   ├── cbor/
│   │   ├── zcbor_wrapper.h/cpp     # CBOR library wrapper
│   │   ├── zcbor_deterministic.h/cpp # Deterministic encoding
│   │   ├── zge_encoding.h/cpp       # Group element encoding
│   │   ├── zattr_canon.h/cpp        # Attribute canonicalization
│   │   ├── zpolicy_encoding.h/cpp   # Policy encoding
│   │   ├── zsuite.h/cpp             # Suite descriptor
│   │   ├── zmsk_cbor.h/cpp          # MSK serialization
│   │   ├── zmpk_cbor.h/cpp          # MPK serialization
│   │   ├── zsk_cbor.h/cpp           # SK serialization
│   │   └── zct_cbor.h/cpp           # CT serialization
│   ├── test_cbor_serialization.cpp  # CBOR tests
│   └── include/openabe/
│       └── cbor/                     # Public CBOR headers
├── docs/
│   ├── ABE-CBOR-SPEC.md             # CDDL specification
│   ├── ABE-CBOR-REGISTRY.md         # Suite registry
│   ├── ABE-CBOR-EXAMPLES.md         # Test vectors
│   ├── ABE-CBOR-IMPLEMENTATION-PLAN.md # This document
│   ├── ABE-CBOR-INTEROP.md          # Interoperability guide
│   ├── SERIALIZATION.md             # User guide
│   └── MIGRATION-GUIDE.md           # Migration guide
└── cli-wasm/
    └── cbor_bindings.cpp            # WASM CBOR bindings
```

## Success Criteria

1. ✅ Byte-for-byte deterministic encoding across platforms
2. ✅ Round-trip serialization for all ABE types (MSK, MPK, SK, CT)
3. ✅ Cross-platform compatibility (native C++ and WASM)
4. ✅ Comprehensive test coverage (>90%)
5. ✅ Backwards compatibility with legacy format
6. ✅ Complete documentation and examples
7. ✅ Performance: <10% overhead vs legacy format

## Future Extensions

### COSE Wrapping (v1.1)
- Add COSE signature support for MPK/SK provenance
- Implement COSE_Key-like representation
- Support external signatures for key delegation

### Multi-Authority Support (v1.2)
- Full MA-ABE and DCPABE support
- Authority chain of trust
- Delegation proof structures

### Advanced Attributes (v1.3)
- Date/time ranges for temporal policies
- Hierarchical attributes
- Wildcard attribute matching

## Timeline Summary

| Phase | Duration | Key Deliverables |
|-------|----------|------------------|
| 1. Foundation | 2 weeks | Specs, CBOR integration |
| 2. Primitives | 2 weeks | GE encoding, attr/policy |
| 3. ABE Types | 2 weeks | MSK/MPK/SK/CT serialization |
| 4. Testing | 2 weeks | Test vectors, conformance |
| 5. Integration | 2 weeks | CLI tools, WASM bindings |
| 6. Documentation | 2 weeks | Docs, release prep |
| **Total** | **12 weeks** | **Production-ready CBOR** |

## Next Steps

1. Review and approve this implementation plan
2. Set up development branch: `feature/cbor-serialization`
3. Begin Phase 1: Create specification documents
4. Integrate tinycbor library
5. Start implementing core primitives

## References

- CBOR RFC: https://www.rfc-editor.org/rfc/rfc8949.html
- COSE RFC: https://www.rfc-editor.org/rfc/rfc9052.html
- IETF BLS12-381: https://datatracker.ietf.org/doc/draft-irtf-cfrg-pairing-friendly-curves/
- tinycbor: https://github.com/intel/tinycbor
- MCL library: https://github.com/herumi/mcl
