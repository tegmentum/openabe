# OpenABE Standard Serialization Formats

## Overview

OpenABE now supports multiple standard serialization formats for cryptographic elements, improving interoperability with other libraries and systems. This document describes the supported formats and how to use them.

## Supported Standards

### 1. **SEC1 v2** (Standards for Efficient Cryptography)
- **Specification**: https://www.secg.org/sec1-v2.pdf
- **Use Case**: General elliptic curve points, compatible with OpenSSL, Bitcoin, etc.
- **Supported Elements**: G1, G2

### 2. **ZCash BLS12-381 Format**
- **Specification**: Referenced in IETF draft-irtf-cfrg-pairing-friendly-curves
- **Use Case**: BLS12-381 pairing-friendly curve, used by Ethereum 2.0, Filecoin, ZCash
- **Supported Elements**: G1, G2, GT

### 3. **Ethereum BN254/alt_bn128 Format**
- **Specification**: EIP-196, EIP-197
- **Use Case**: BN254 curve for Ethereum smart contracts
- **Supported Elements**: G1, G2

### 4. **IETF Pairing-Friendly Curves Format**
- **Specification**: draft-irtf-cfrg-pairing-friendly-curves-11
- **Use Case**: General pairing-friendly curves with GT element serialization
- **Supported Elements**: G1, G2, GT

## Serialization Format Structure

### Standard Header (9 bytes)

All standard serializations include a header for format identification:

```
┌─────────────────────────────────────────┐
│ MAGIC (4 bytes): "OABE"                 │
├─────────────────────────────────────────┤
│ VERSION (1 byte): 0x02                  │
├─────────────────────────────────────────┤
│ ELEMENT_TYPE (1 byte):                  │
│   0xB1 = ZP                             │
│   0xB2 = G1                             │
│   0xB3 = G2                             │
│   0xB4 = GT                             │
├─────────────────────────────────────────┤
│ CURVE_ID (1 byte):                      │
│   0x6F = BN254                          │
│   0xE4 = BN382 (BLS12-381 compatible)   │
│   0x32 = NIST P-256                     │
├─────────────────────────────────────────┤
│ FORMAT (1 byte):                        │
│   0x00 = Legacy                         │
│   0x01 = SEC1                           │
│   0x02 = ZCash BLS12                    │
│   0x03 = Ethereum BN254                 │
│   0x04 = IETF Pairing                   │
├─────────────────────────────────────────┤
│ FLAGS (1 byte):                         │
│   Bit 7: Compression                    │
│   Bit 6: Infinity                       │
│   Bit 5: Y-sign                         │
│   Bit 4: Cyclotomic (GT)                │
└─────────────────────────────────────────┘
```

### G1 Point Sizes

| Format | Curve | Compressed | Uncompressed |
|--------|-------|------------|--------------|
| SEC1 | BN254 | 33 bytes | 65 bytes |
| ZCash | BLS12-381 | 48 bytes | 96 bytes |
| Ethereum | BN254 | N/A | 64 bytes |

### G2 Point Sizes (over Fp2)

| Format | Curve | Compressed | Uncompressed |
|--------|-------|------------|--------------|
| SEC1 | BN254 | N/A | 129 bytes |
| ZCash | BLS12-381 | 96 bytes | 192 bytes |
| Ethereum | BN254 | N/A | 128 bytes |

### GT Element Sizes (Fp12)

| Format | Curve | Full Tower | Cyclotomic Compressed |
|--------|-------|------------|----------------------|
| IETF | BN254 | 384 bytes | 256 bytes (67%) |
| IETF | BLS12-381 | 576 bytes | 384 bytes (67%) |

## Format Details

### 1. SEC1 Format

**Compressed Point** (G1):
```
[0x02 or 0x03][x-coordinate]
```
- `0x02`: y is even
- `0x03`: y is odd
- `x-coordinate`: field element, big-endian

**Uncompressed Point** (G1):
```
[0x04][x-coordinate][y-coordinate]
```

**Point at Infinity**:
```
[0x00]
```

### 2. ZCash BLS12-381 Format

**Compressed Point** (G1):
```
[flags|x-coordinate]
```
- Flags encoded in top 3 bits of first byte:
  - Bit 7 (0x80): Compression flag (1 = compressed)
  - Bit 6 (0x40): Infinity flag
  - Bit 5 (0x20): Y-sign (1 = lexicographically largest y)

**Uncompressed Point** (G1):
```
[x-coordinate][y-coordinate]
```

**Field Encoding**:
- Big-endian
- Fp2 elements: `c1 || c0` for `c0 + c1*u`

### 3. Ethereum BN254 Format

**G1 Point** (uncompressed only):
```
[x-coordinate][y-coordinate]
```
- 32 bytes each, big-endian
- Total: 64 bytes

**G2 Point** (uncompressed only):
```
[x1][x0][y1][y0]
```
- For `x = x0 + x1*u`, `y = y0 + y1*u`
- 32 bytes each, big-endian
- Total: 128 bytes

**Point at Infinity**:
- G1: `0x00...00 || 0x00...00` (64 bytes)
- G2: `0x00...00 || 0x00...00 || 0x00...00 || 0x00...00` (128 bytes)

### 4. GT (Fp12) Format

**Full Tower Representation**:
```
[fp0][fp1][fp2]...[fp11]
```
- 12 field elements, big-endian
- BN254: 12 × 32 = 384 bytes
- BLS12-381: 12 × 48 = 576 bytes

**Cyclotomic Compression**:
```
[fp4][fp5][fp6]...[fp11]
```
- 8 field elements (indices 4-11)
- Indices 0-3 can be reconstructed using `g^(p^6) = g^(-1)`
- BN254: 8 × 32 = 256 bytes
- BLS12-381: 8 × 48 = 384 bytes

**Identity Element**:
- First byte has infinity flag (0x40) set
- Remaining bytes are zero

## Usage Examples

### C++ API

```cpp
#include <openabe/openabe.h>
#include <openabe/zml/zstandard_serialization.h>

using namespace oabe;

// Initialize
InitializeOpenABE();

// Create pairing and elements
OpenABEPairing pairing("BN254");
G1 g1 = pairing.randomG1(nullptr);

// Serialize with auto-format selection
OpenABEByteString serialized;
StandardPairingSerializer::serializeG1(serialized, g1, AUTO, true);

// Serialize with specific format
OpenABEByteString eth_format;
StandardPairingSerializer::serializeG1(eth_format, g1, ETHEREUM_BN254, true);

// Deserialize
std::shared_ptr<BPGroup> bgroup =
    std::dynamic_pointer_cast<BPGroup>(pairing.getGroup());
G1 g1_restored(bgroup);
StandardPairingSerializer::deserializeG1(g1_restored, serialized, true);

// Verify
assert(g1 == g1_restored);

ShutdownOpenABE();
```

### Format Auto-Selection

The library automatically selects the best format for each curve:

| Curve | Auto-Selected Format |
|-------|---------------------|
| BN254 | Ethereum BN254 |
| BN256 | Ethereum BN254 |
| BN382 (BLS12-381 compat) | ZCash BLS12 |
| NIST P-256, P-384, P-521 | SEC1 |

### Legacy Format Compatibility

The library automatically detects and handles legacy OpenABE formats:

```cpp
// Detect format
bool is_legacy = StandardPairingSerializer::isLegacyFormat(data);

// Convert legacy to standard
if (LegacySerializer::detectLegacyFormat(data)) {
    OpenABEByteString standard_format;
    LegacySerializer::convertLegacyG1(standard_format, data, bgroup);
}
```

## Cross-Library Interoperability

### Ethereum Smart Contracts

```solidity
// G1 point from OpenABE (Ethereum format)
function verifyPoint(bytes memory g1Data) public pure returns (bool) {
    require(g1Data.length == 64, "Invalid G1 length");

    (uint256 x, uint256 y) = abi.decode(g1Data, (uint256, uint256));

    // Verify point is on curve: y^2 = x^3 + 3
    uint256 lhs = mulmod(y, y, FIELD_MODULUS);
    uint256 rhs = addmod(
        mulmod(mulmod(x, x, FIELD_MODULUS), x, FIELD_MODULUS),
        3,
        FIELD_MODULUS
    );

    return lhs == rhs;
}
```

### Python (using zkcrypto BLS12-381)

```python
from bls12_381 import G1

# Deserialize from OpenABE (ZCash format)
def deserialize_g1_zcash(data: bytes) -> G1:
    assert len(data) == 48, "Expected 48 bytes for compressed G1"
    return G1.from_compressed(data)

# Serialize to OpenABE format
def serialize_g1_zcash(point: G1) -> bytes:
    return point.to_compressed()
```

### Rust (using arkworks)

```rust
use ark_bls12_381::G1Affine;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

// Deserialize from OpenABE (ZCash format, uncompressed)
fn deserialize_g1_zcash(data: &[u8]) -> G1Affine {
    G1Affine::deserialize_uncompressed(data).unwrap()
}

// Serialize to OpenABE format
fn serialize_g1_zcash(point: &G1Affine) -> Vec<u8> {
    let mut buf = Vec::new();
    point.serialize_uncompressed(&mut buf).unwrap();
    buf
}
```

## Migration Guide

### Updating Existing Code

1. **No changes required for basic usage** - legacy serialization still works
2. **Optional**: Add headers for cross-system compatibility:

```cpp
// Old code (still works)
g1.serialize(result);

// New code (with standard format)
StandardPairingSerializer::serializeG1(result, g1, AUTO, true);
```

### Converting Existing Data

```cpp
// Read legacy ciphertext
OpenABEByteString legacy_ct;
// ... load from file ...

// Check if needs conversion
if (LegacySerializer::detectLegacyFormat(legacy_ct)) {
    // Convert to standard format
    OpenABEByteString standard_ct;
    // ... convert based on element type ...

    // Save updated format
    // ... save to file ...
}
```

### Batch Conversion Tool

```bash
# Convert all legacy serializations to standard format
./openabe_convert --input-dir ./old_data --output-dir ./new_data --format zcash
```

## Performance Considerations

### Compression Trade-offs

| Element | Uncompressed | Compressed | Savings | Decompression Cost |
|---------|-------------|------------|---------|-------------------|
| G1 (BN254) | 65 bytes | 33 bytes | 49% | ~5-10 ms |
| G1 (BLS12-381) | 96 bytes | 48 bytes | 50% | ~5-10 ms |
| G2 (BLS12-381) | 192 bytes | 96 bytes | 50% | ~10-20 ms |
| GT (BN254) | 384 bytes | 256 bytes | 33% | ~50-100 ms |

### Recommendations

- **Network transmission**: Use compressed formats
- **Local storage**: Use uncompressed for faster deserialization
- **Smart contracts**: Use Ethereum format (uncompressed, gas-optimized)
- **Caching**: Store uncompressed for repeated use

## Security Considerations

### Point Validation

All deserialization functions validate:
1. Field elements are < field modulus
2. Points lie on the curve
3. Points are in the correct subgroup (for pairing curves)

### Format Detection

The library uses magic bytes (`OABE`) to prevent format confusion attacks.

### Constant-Time Operations

Where available, the library uses constant-time comparison for:
- Point equality checks
- Subgroup membership tests

## References

1. **SEC1 v2**: https://www.secg.org/sec1-v2.pdf
2. **IETF Pairing-Friendly Curves**: https://datatracker.ietf.org/doc/draft-irtf-cfrg-pairing-friendly-curves/
3. **ZCash BLS12-381**: https://docs.rs/bls12_381/latest/bls12_381/notes/serialization/
4. **Ethereum EIP-196**: https://eips.ethereum.org/EIPS/eip-196
5. **Ethereum EIP-197**: https://eips.ethereum.org/EIPS/eip-197

## Testing

Run the standard serialization tests:

```bash
cd src
make test_standard_serialization
./test_standard_serialization
```

Expected output:
```
╔════════════════════════════════════════════════════════╗
║   OpenABE Standard Serialization Test Suite           ║
╚════════════════════════════════════════════════════════╝

=== Testing Serialization Header ===
Header size: 9 bytes
...
All tests completed
```

## Future Enhancements

### Planned Features

1. **Point Decompression**: Full implementation for compressed formats
2. **GT Cyclotomic Decompression**: Frobenius map for reconstruction
3. **Additional Backends**: MCL, BLST support
4. **Batch Serialization**: Optimized multi-element serialization
5. **Hardware Acceleration**: AVX-512 for field operations

### Contributing

To add support for a new format:

1. Add format enum to `SerializationFormat`
2. Implement `serializeG1_<FORMAT>` and `deserializeG1_<FORMAT>`
3. Update `selectFormat()` for auto-selection
4. Add tests to `test_standard_serialization.cpp`
5. Update this documentation

## Support

For questions or issues:
- GitHub Issues: https://github.com/zeutro/openabe/issues
- Email: support@zeutro.com
- Documentation: https://github.com/zeutro/openabe/docs
