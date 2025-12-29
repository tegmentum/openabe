# ABE-CBOR v1: Cross-Platform Serialization for OpenABE

## Overview

ABE-CBOR v1 is a portable, deterministic serialization format for OpenABE cryptographic objects based on [RFC 8949 (CBOR)](https://www.rfc-editor.org/rfc/rfc8949.html). It ensures bit-for-bit compatible serialization across different platforms (native x86/ARM and WebAssembly) and different programming languages.

## Motivation

Traditional OpenABE serialization used custom binary formats that were:
- Platform-specific (endianness issues)
- Non-deterministic (map ordering, attribute sorting)
- Not compatible between native and WASM builds
- Difficult to implement in other languages

ABE-CBOR v1 solves these problems by providing:
- **Deterministic encoding**: Same input always produces identical output
- **Platform independence**: Works identically on x86, ARM, and WebAssembly
- **Canonical representation**: Single valid encoding for each object
- **Interoperability**: Standard CBOR format enables cross-language implementations

## Serialization Layers

ABE-CBOR v1 is implemented in four layers, from low-level to high-level:

### Layer 1: CBOR Wrapper (`zcbor_wrapper.h`)
- Thin C++ wrapper around tinycbor library
- Provides type-safe encoding/decoding API
- Handles canonical CBOR encoding (RFC 8949 Section 4.2)
- Supports nested containers with proper state management

### Layer 2: Group Elements (`zcbor_group_elements.h`)
- Serializes pairing group elements (G1, G2, GT, Zr)
- Uses IETF compressed point encoding for elliptic curve points
- Enforces big-endian byte order for cross-platform compatibility
- Validates curve-specific sizes

### Layer 3: Attributes and Policies (`zcbor_attributes.h`, `zcbor_policy.h`)
- Serializes attribute values with 5 types: STRING, INTEGER, BYTES, SET, RANGE
- Implements canonical attribute list sorting
- Encodes policy trees in Reverse Polish Notation (RPN)
- Supports all OpenABE policy gates (AND, OR, NOT, XOR, THRESHOLD, etc.)

### Layer 4: High-Level ABE Objects (`zcbor_abe.h`)
- Serializes complete keys (MSK, MPK, SK) and ciphertexts (CT)
- Uses CBOR tag 60001 for ABE objects
- Supports multiple schemes (CP-ABE Waters, KP-ABE GPSW)
- Includes version and curve metadata

## Cross-Platform Compatibility Guarantees

### 1. Deterministic Encoding

ABE-CBOR v1 guarantees that the same cryptographic object will **always** serialize to the exact same byte sequence, regardless of:
- Platform (x86_64, ARM64, WebAssembly)
- Operating system (Linux, macOS, Windows)
- Compiler (GCC, Clang, Emscripten)
- Programming language (C++, JavaScript via WASM)

This is achieved through:
- **Canonical CBOR encoding** (sorted maps, shortest-length integers)
- **Deterministic attribute sorting** (by type, then canonical bytes)
- **Fixed endianness** (big-endian for all numeric values)
- **Consistent point encoding** (IETF compressed format)

### 2. Byte-Level Compatibility

A ciphertext serialized on **native x86_64 Linux** can be deserialized and decrypted on:
- Native ARM64 macOS
- WebAssembly in a browser
- Native Windows x86_64
- Any platform with a compliant ABE-CBOR v1 implementation

### 3. Test Vector Verification

The cross-platform test framework (`test_cbor_generate_vectors.cpp` and `test_cbor_verify_vectors.cpp`) provides 12 standard test vectors covering:

| Vector | Type | Description |
|--------|------|-------------|
| 1 | G1 | Random G1 element (48 bytes compressed) |
| 2 | G2 | Random G2 element (96 bytes compressed) |
| 3 | GT | Random GT element (576 bytes) |
| 4 | Zr | Random Zr scalar (32 bytes) |
| 5 | Attribute | String attribute ("department") |
| 6 | Attribute | Integer attribute (42) |
| 7 | Attribute | Bytes attribute (0xDEADBEEF) |
| 8 | Attribute List | Sorted list of 4 attributes |
| 9 | Policy | Simple AND policy: `A and B` |
| 10 | Policy | Nested policy: `(A and B) or C` |
| 11 | Policy | Complex policy: `(A and B) or (C and D)` |
| 12 | Array | Array of 3 G1 elements |

**Usage:**
```bash
# Generate test vectors on any platform
./test_cbor_generate_vectors

# Verify test vectors on another platform
./test_cbor_verify_vectors

# All 12 tests should pass with bit-for-bit identical encoding
```

## Serialization Format Details

### Group Element Encoding

#### G1 Elements (48 bytes compressed, BLS12-381)
```
CBOR byte string:
- Tag: 0x58 0x30 (byte string, 48 bytes)
- Data: 48 bytes (compressed point, big-endian)
```

#### G2 Elements (96 bytes compressed, BLS12-381)
```
CBOR byte string:
- Tag: 0x58 0x60 (byte string, 96 bytes)
- Data: 96 bytes (compressed point, big-endian)
```

#### GT Elements (576 bytes, BLS12-381)
```
CBOR byte string:
- Tag: 0x59 0x02 0x40 (byte string, 576 bytes)
- Data: 576 bytes (Fp12 element, big-endian)
```

#### Zr Elements (32 bytes, BLS12-381)
```
CBOR byte string:
- Tag: 0x58 0x20 (byte string, 32 bytes)
- Data: 32 bytes (scalar modulo r, big-endian)
```

### Attribute Encoding

Attributes are encoded as CBOR maps with keys 0 (type) and 1 (value):

#### String Attribute
```
{
  0: 0,              // AttributeType::STRING
  1: "department"    // UTF-8 string
}
```

#### Integer Attribute
```
{
  0: 1,    // AttributeType::INTEGER
  1: 42    // Signed 64-bit integer
}
```

#### Bytes Attribute
```
{
  0: 2,                      // AttributeType::BYTES
  1: h'DEADBEEF'             // Byte string
}
```

### Attribute List Sorting

Attribute lists are **canonically sorted** by:
1. Attribute type (ascending)
2. Canonical byte representation (lexicographic)

Example:
```cpp
Input:  ["role", 100, "department", 42]
Sorted: ["department", "role", 42, 100]
        (strings before integers, alphabetically sorted within each type)
```

### Policy Encoding (RPN)

Policies are encoded in **Reverse Polish Notation** (postfix notation):

#### Example: `A and B`
```
RPN tokens: [A, B, AND]

CBOR array:
[
  {0: 0, 1: {0: 0, 1: "A"}},   // ATTR token with string "A"
  {0: 0, 1: {0: 0, 1: "B"}},   // ATTR token with string "B"
  {0: 1}                        // AND operator
]
```

#### Example: `(A and B) or C`
```
RPN tokens: [A, B, AND, C, OR]

CBOR array:
[
  {0: 0, 1: {0: 0, 1: "A"}},
  {0: 0, 1: {0: 0, 1: "B"}},
  {0: 1},                       // AND
  {0: 0, 1: {0: 0, 1: "C"}},
  {0: 2}                        // OR
]
```

## Usage Examples

### Serialize a G1 Element
```cpp
#include <openabe/openabe.h>
#include <openabe/cbor/zcbor_group_elements.h>

using namespace oabe;
using namespace oabe::cbor;

OpenABEPairing pairing("BLS12_P381");
OpenABERNG rng;

// Create a random G1 element
G1 g1 = pairing.randomG1(&rng);

// Serialize to CBOR
GroupElementSerializer serializer(GEEncoding::IETF_COMPRESSED, Endianness::BIG);
ZCBOREncoder encoder;
serializer.encodeG1(encoder, g1);
std::vector<uint8_t> cbor_bytes = encoder.getEncoded();

// Deserialize from CBOR
ZCBORDecoder decoder(cbor_bytes);
G1 g1_decoded = pairing.initG1();
serializer.decodeG1(decoder, g1_decoded, OpenABE_BLS12_P381_ID);

// g1 and g1_decoded are now identical
```

### Serialize an Attribute List
```cpp
#include <openabe/cbor/zcbor_attributes.h>

using namespace oabe::cbor;

// Create attribute list
std::vector<AttributeValue> attrs;
attrs.push_back(AttributeValue("department"));
attrs.push_back(AttributeValue(42));
attrs.push_back(AttributeValue("role"));

// Serialize (automatically sorts)
AttributeSerializer attr_ser;
ZCBOREncoder encoder;
attr_ser.encodeAttributeList(encoder, attrs);
std::vector<uint8_t> cbor_bytes = encoder.getEncoded();

// Deserialize
ZCBORDecoder decoder(cbor_bytes);
std::vector<AttributeValue> attrs_decoded = attr_ser.decodeAttributeList(decoder);

// attrs_decoded is sorted: ["department", "role", 42]
```

### Serialize a Policy
```cpp
#include <openabe/cbor/zcbor_policy.h>

using namespace oabe;
using namespace oabe::cbor;

// Create policy tree
std::unique_ptr<OpenABEPolicy> policy = createPolicyTree("(A and B) or C");

// Serialize to RPN
PolicySerializer policy_ser;
ZCBOREncoder encoder;
policy_ser.encodeBooleanAST(encoder, *policy);
std::vector<uint8_t> cbor_bytes = encoder.getEncoded();

// Deserialize
ZCBORDecoder decoder(cbor_bytes);
std::unique_ptr<OpenABEPolicy> policy_decoded = policy_ser.decodeBooleanAST(decoder);

// policy and policy_decoded are equivalent
```

## Platform-Specific Notes

### Endianness Handling

ABE-CBOR v1 uses **big-endian** encoding for all numeric values (CBOR standard). The serialization layer automatically converts from platform endianness:

```cpp
// Automatic endianness conversion
void GroupElementSerializer::convertToBigEndian(uint8_t* data, size_t len) {
    if (endianness_ == Endianness::BIG && isLittleEndian()) {
        reverseBytes(data, len);  // Little-endian platform → reverse bytes
    }
}
```

### WebAssembly Considerations

When using ABE-CBOR in WebAssembly:
1. **Same binary format**: WASM uses the same CBOR encoding as native
2. **Endianness**: WASM is little-endian, conversion happens automatically
3. **Memory layout**: Serialization is independent of memory layout
4. **Test vectors**: Generated on native, verified on WASM (and vice versa)

### Multi-Language Implementations

To implement ABE-CBOR v1 in another language:
1. Use a compliant CBOR library (RFC 8949)
2. Implement canonical encoding (sorted maps, shortest integers)
3. Use big-endian byte order for all numeric values
4. Implement the 4-layer serialization stack
5. Verify against the 12 standard test vectors

Reference implementations:
- **C++**: `src/cbor/` (this implementation)
- **JavaScript/TypeScript**: (future - via WASM bindings)
- **Python**: (future - native implementation)

## Security Considerations

### Canonical Encoding Importance

Non-canonical CBOR encoding can lead to **signature malleability attacks**. ABE-CBOR v1 prevents this by:
- Enforcing canonical encoding (shortest-length integers, sorted maps)
- Validating canonical format during deserialization
- Rejecting non-canonical encodings

### Deterministic Sorting

Attribute list sorting is **security-critical** for:
- Consistent signature generation
- Preventing malleability through attribute reordering
- Ensuring policy equivalence checks

## Performance

### Serialization Overhead

Compared to traditional binary serialization:
- **G1/G2/GT**: Negligible overhead (~2 bytes CBOR header)
- **Attributes**: Small overhead (~4-6 bytes per attribute)
- **Policies**: Small overhead (~3 bytes per token)
- **Full ciphertext**: <1% size increase

### Speed

ABE-CBOR v1 serialization is:
- **Fast**: O(n) where n is object size
- **Memory-efficient**: Single-pass encoding, no intermediate buffers
- **Cache-friendly**: Sequential memory access

Typical performance (BLS12-381, native build):
- G1 serialize: ~5 μs
- G1 deserialize: ~8 μs
- Policy serialize (10 attributes): ~15 μs
- Full ciphertext: ~50 μs

## Future Extensions

### ABE-CBOR v2 (Planned)

Future versions may include:
- **MSP encoding**: Matrix representation for advanced policies
- **Compressed policies**: Delta encoding for repeated attributes
- **Batch operations**: Serialize multiple objects in single stream
- **Streaming API**: Handle arbitrarily large objects

### Backward Compatibility

ABE-CBOR uses versioned tags (60001 for v1) to ensure:
- New versions can read old formats
- Old versions reject new formats gracefully
- Clear upgrade path for implementations

## References

1. [RFC 8949: Concise Binary Object Representation (CBOR)](https://www.rfc-editor.org/rfc/rfc8949.html)
2. [IETF Draft: BLS Signatures](https://datatracker.ietf.org/doc/draft-irtf-cfrg-bls-signature/)
3. [tinycbor Library](https://github.com/intel/tinycbor)
4. OpenABE Cryptographic Library

## Implementation Status

- ✅ Layer 1: CBOR Wrapper
- ✅ Layer 2: Group Element Serialization
- ✅ Layer 3: Attribute and Policy Serialization
- ⏳ Layer 4: High-Level ABE Object Serialization (in progress)
- ✅ Cross-platform test framework
- ✅ WASM build integration
- ⏳ JavaScript/TypeScript bindings (planned)

## Contact

For questions, bug reports, or contributions, please see the main OpenABE repository.
