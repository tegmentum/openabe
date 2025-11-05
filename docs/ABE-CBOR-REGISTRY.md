# ABE-CBOR Registry

## Version: 1.0
## Date: 2025-01-04
## Status: Draft

## 1. Overview

This document maintains the official registry of identifiers used in ABE-CBOR v1 serialization format. All implementations MUST use these exact string identifiers for interoperability.

## 2. Scheme Identifiers

Scheme identifiers specify the ABE construction being used.

| Identifier | Scheme Name | Construction | Security Assumption | Status | OpenABE Support |
|------------|-------------|--------------|---------------------|--------|-----------------|
| `cpabe-waters` | CP-ABE Waters | BSW07 Ciphertext-Policy ABE | DBDH | **stable** | ✅ Yes |
| `kpabe-gpsw` | KP-ABE GPSW | GPSW06 Key-Policy ABE | DBDH | **stable** | ✅ Yes |
| `cpabe-waters-cca` | CP-ABE Waters CCA | BSW07 with CCA security | DBDH + RO | **stable** | ✅ Yes |
| `kpabe-gpsw-cca` | KP-ABE GPSW CCA | GPSW06 with CCA security | DBDH + RO | **stable** | ✅ Yes |
| `maabe-lu08` | MA-ABE Lu et al. | Multi-Authority ABE | DBDH | planned | ❌ No |
| `dcpabe-waters11` | DCPABE Waters | Delegated CP-ABE | DBDH | planned | ❌ No |

### 2.1 Scheme Identifier Format

- Use lowercase with hyphens
- Format: `{type}-{author}-{variant}`
- Examples: `cpabe-waters`, `kpabe-gpsw-cca`

### 2.2 Adding New Schemes

To add a new scheme:
1. Choose unique identifier following format above
2. Submit pull request to OpenABE repository
3. Include: paper reference, security assumptions, test vectors
4. Status starts as `draft`, moves to `stable` after 2 implementations

## 3. Curve Identifiers

Curve identifiers specify the elliptic curve and pairing parameters.

| Identifier | Curve Family | Field Size (bits) | Embedding Degree | Security Level (bits) | Status | OpenABE Support |
|------------|--------------|-------------------|------------------|-----------------------|--------|-----------------|
| `bls12-381` | BLS12 | 381 | 12 | 128 | **recommended** | ✅ Yes (primary) |
| `bn254` | BN (Barreto-Naehrig) | 254 | 12 | ~100 | **legacy** | ✅ Yes (deprecated) |
| `bls12-377` | BLS12 | 377 | 12 | 128 | experimental | ❌ No |
| `bw6-761` | BW6 | 761 | 6 | 128 | experimental | ❌ No |

### 3.1 Curve Properties

#### bls12-381
- **Family**: BLS12 (Barreto-Lynn-Scott)
- **Field prime p**: 381 bits
- **Group order r**: 255 bits
- **Embedding degree k**: 12
- **Security**: 128-bit (conservative estimate)
- **Status**: IETF draft standard
- **References**:
  - https://datatracker.ietf.org/doc/draft-irtf-cfrg-pairing-friendly-curves/
  - https://electriccoin.co/blog/new-snark-curve/
- **OpenABE**: Primary curve, MCL backend

#### bn254
- **Family**: Barreto-Naehrig
- **Field prime p**: 254 bits
- **Group order r**: 254 bits
- **Embedding degree k**: 12
- **Security**: ~100-bit (reduced due to recent attacks)
- **Status**: Legacy, not recommended for new deployments
- **References**:
  - Original BN paper (Barreto-Naehrig 2005)
  - Kim-Barbulescu attack (2016) reduces security
- **OpenABE**: Supported for backwards compatibility

### 3.2 Curve Selection Guidelines

**Recommended**: `bls12-381`
- 128-bit security level
- IETF standardized
- Widely supported
- Efficient pairings

**Not Recommended**: `bn254`
- Reduced security (~100-bit)
- Use only for legacy system compatibility
- Migrate to BLS12-381 when possible

### 3.3 Adding New Curves

To add a new curve:
1. Verify security analysis (peer-reviewed)
2. Provide complete curve parameters
3. Implement group operations and pairing
4. Generate test vectors
5. Submit PR with documentation

## 4. Group Element Encoding Formats

GE encoding identifiers specify how group elements are serialized.

| ID | Identifier | Format | G1 Size | G2 Size | GT Size | Status | Notes |
|----|------------|--------|---------|---------|---------|--------|-------|
| 0 | `ietf-compressed` | IETF compressed point | 48 bytes | 96 bytes | 576 bytes | **recommended** | BLS12-381 only |
| 1 | `uncompressed` | Full affine coordinates | 96 bytes | 192 bytes | 576 bytes | **stable** | All curves |
| 2 | `mcl-canonical` | MCL library native | Variable | Variable | Variable | **stable** | MCL-specific |

### 4.1 Encoding Specifications

#### Format 0: IETF Compressed (BLS12-381)

**G1 Compressed** (48 bytes):
```
Byte layout:
[0]       : flags (compressed bit, infinity bit, sign bit)
[1..47]   : x-coordinate (big-endian)

Flags (byte 0, MSB first):
- Bit 7: compression_flag = 1 (always set)
- Bit 6: infinity_flag (1 if point at infinity)
- Bit 5: sign_bit (y-coordinate sign, 1 = negative/odd)
- Bits 4-0: part of x-coordinate
```

**G2 Compressed** (96 bytes):
```
Same as G1 but for x-coordinate in Fp2 (two Fp elements)
[0..47]  : x0 (imaginary component)
[48..95] : x1 (real component)
First byte of x0 contains flags
```

**GT** (576 bytes):
```
12 elements of Fp (48 bytes each) in Fp12
Stored in tower extension order
```

**References**:
- IETF draft: https://datatracker.ietf.org/doc/draft-irtf-cfrg-pairing-friendly-curves/
- ZCash BLS12-381 spec: https://github.com/zkcrypto/bls12_381

#### Format 1: Uncompressed

**G1 Uncompressed** (96 bytes):
```
[0]      : flags (infinity bit only)
[1..48]  : x-coordinate (big-endian)
[49..96] : y-coordinate (big-endian)
```

**G2 Uncompressed** (192 bytes):
```
[0]       : flags
[1..96]   : x-coordinate (x0 || x1, each 48 bytes)
[97..192] : y-coordinate (y0 || y1, each 48 bytes)
```

**GT Uncompressed** (576 bytes):
Same as compressed (GT doesn't compress well)

#### Format 2: MCL Canonical

MCL library's native serialization format. Varies by MCL version and configuration.

**For BLS12-381 with MCL**:
- G1: 48 bytes (compressed) or 96 bytes (uncompressed)
- G2: 96 bytes (compressed) or 192 bytes (uncompressed)
- GT: 576 bytes

**Endianness**: Little-endian (MCL default)

**Note**: Document exact MCL version and build flags used

### 4.2 Encoding Selection

**Recommendation**: Use format 0 (`ietf-compressed`) for BLS12-381
- Smallest size
- Standardized
- Widely compatible

**Fallback**: Use format 1 (`uncompressed`) if compression not supported

### 4.3 Adding New Encodings

To add a new encoding:
1. Document complete byte layout
2. Specify endianness
3. Define flag bits
4. Handle edge cases (infinity, zero)
5. Provide test vectors
6. Submit PR

## 5. Endianness

| Value | Endianness | Description | Default For |
|-------|------------|-------------|-------------|
| 0 | Big-endian | Most significant byte first | BLS12-381, IETF formats |
| 1 | Little-endian | Least significant byte first | MCL native, BN254 |

**Best Practice**: Use big-endian for new deployments (IETF standard)

## 6. Hash Function Identifiers

Hash functions used in ABE schemes for various purposes (attribute hashing, KDF, etc.).

| Identifier | Algorithm | Output Size | Block Size | Security | Status | OpenABE Support |
|------------|-----------|-------------|------------|----------|--------|-----------------|
| `SHA-256` | SHA-2 256-bit | 32 bytes | 64 bytes | 128-bit | **stable** | ✅ Yes |
| `SHA-384` | SHA-2 384-bit | 48 bytes | 128 bytes | 192-bit | **stable** | ✅ Yes |
| `SHA-512` | SHA-2 512-bit | 64 bytes | 128 bytes | 256-bit | **stable** | ✅ Yes |
| `BLAKE2s-256` | BLAKE2s | 32 bytes | 64 bytes | 128-bit | experimental | ❌ No |
| `BLAKE3` | BLAKE3 | Variable | N/A | 128-bit | experimental | ❌ No |

### 6.1 Hash Selection Guidelines

**Default**: `SHA-256`
- Widely supported
- Well-analyzed
- Sufficient for 128-bit security with BLS12-381

**High Security**: `SHA-384` or `SHA-512`
- For future-proofing
- Paranoid mode
- Minimal performance cost

## 7. KDF Identifiers

Key Derivation Functions used to derive keys from master secrets.

| Identifier | Algorithm | Based On | Variable Output | Status | OpenABE Support |
|------------|-----------|----------|-----------------|--------|-----------------|
| `HKDF-SHA256` | HKDF | HMAC-SHA-256 | Yes | **stable** | ✅ Yes (default) |
| `HKDF-SHA384` | HKDF | HMAC-SHA-384 | Yes | **stable** | ✅ Yes |
| `HKDF-SHA512` | HKDF | HMAC-SHA-512 | Yes | **stable** | ✅ Yes |
| `KDF1-SHA256` | KDF1 | SHA-256 | Yes | legacy | ❌ No |
| `PBKDF2-SHA256` | PBKDF2 | HMAC-SHA-256 | No | not recommended | ❌ No |

### 7.1 KDF Selection Guidelines

**Default**: `HKDF-SHA256`
- RFC 5869 standard
- Provable security
- Widely implemented
- Used in TLS 1.3, Signal, etc.

**References**:
- RFC 5869: https://www.rfc-editor.org/rfc/rfc5869.html

## 8. Reserved Identifiers

The following identifiers are reserved and MUST NOT be used:

- `test-*` - Reserved for testing
- `experimental-*` - Reserved for experiments
- `deprecated-*` - Reserved for deprecated schemes
- `private-*` - Reserved for private use

## 9. Version History

### Version 1.0 (2025-01-04)
- Initial registry
- Added scheme identifiers for OpenABE schemes
- Added curve identifiers: bls12-381, bn254
- Added GE encoding formats 0-2
- Added hash identifiers: SHA-256, SHA-384, SHA-512
- Added KDF identifiers: HKDF variants

## 10. Registry Maintenance

### 10.1 Update Process

1. Propose change via GitHub issue
2. Discuss with community
3. Submit PR with:
   - Updated registry entry
   - Test vectors
   - Reference implementation (if new)
4. Review by maintainers
5. Merge and tag new registry version

### 10.2 Stability Levels

| Level | Meaning | Breaking Changes |
|-------|---------|------------------|
| **stable** | Production-ready, widely used | Requires deprecation period |
| **experimental** | Under development, may change | No guarantees |
| **draft** | Proposed, not yet implemented | May change or be removed |
| **legacy** | Deprecated, use only for compatibility | May be removed in future |
| **planned** | Roadmap item, not yet started | Not available |

### 10.3 Deprecation Policy

When deprecating an identifier:
1. Mark as `legacy` in registry
2. Announce deprecation timeline (minimum 6 months)
3. Provide migration guide
4. After deprecation period, remove from active support
5. Keep in registry as `deprecated-{old-id}` for historical reference

## 11. Interoperability Notes

### 11.1 Cross-Library Compatibility

To ensure interoperability between OpenABE, rabe, and other implementations:

1. **Always use registry identifiers** - Don't create custom strings
2. **Match encoding formats** - Same curve requires same encoding
3. **Verify test vectors** - Cross-validate with reference implementations
4. **Document deviations** - If you must deviate, document clearly

### 11.2 Known Issues

**MCL vs IETF Encoding**:
- MCL default is little-endian
- IETF standard is big-endian
- Must convert endianness when using IETF format with MCL

**BN254 Variants**:
- Multiple BN254 curves exist (different parameters)
- OpenABE uses "standard" BN254 (ALT_BN128)
- Specify exact parameters if interoperating

## 12. Contact

For registry updates, questions, or new identifier requests:

- **GitHub Issues**: https://github.com/zeutro/openabe/issues
- **Email**: openabe@zeutro.com
- **Label**: `registry` for registry-related issues

---

**Document Status**: Draft
**Version**: 1.0
**Last Updated**: 2025-01-04
**Maintainer**: OpenABE Project
**License**: Same as OpenABE (AGPL-3.0)
