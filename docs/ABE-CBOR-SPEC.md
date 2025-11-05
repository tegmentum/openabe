# ABE-CBOR v1 Specification

## Version: 1.0
## Date: 2025-01-04
## Status: Draft

## 1. Introduction

This document specifies ABE-CBOR v1, a portable, deterministic serialization format for Attribute-Based Encryption (ABE) cryptographic materials. The format is designed to enable interoperability between different ABE implementations (OpenABE, rabe, MCL-based libraries, etc.) while maintaining crypto-agility and supporting advanced features like multi-authority ABE.

### 1.1 Design Goals

1. **Deterministic**: Byte-for-byte reproducible encoding across implementations
2. **Crypto-agile**: Explicit cryptographic suite identification (scheme, curve, encodings)
3. **Extensible**: Support for multi-authority ABE (MA-ABE) and delegated ABE (DCPABE)
4. **Portable**: Cross-platform compatibility (native, WASM, mobile)
5. **Standards-based**: Built on CBOR (RFC 8949) with deterministic encoding rules

### 1.2 Terminology

- **ABE**: Attribute-Based Encryption
- **CP-ABE**: Ciphertext-Policy ABE
- **KP-ABE**: Key-Policy ABE
- **MA-ABE**: Multi-Authority ABE
- **CBOR**: Concise Binary Object Representation (RFC 8949)
- **CDDL**: CBOR Data Definition Language (RFC 8610)
- **MSK**: Master Secret Key
- **MPK**: Master Public Key
- **SK**: User Secret Key (attribute key)
- **CT**: Ciphertext
- **LSSS**: Linear Secret Sharing Scheme
- **MSP**: Monotone Span Program

## 2. CDDL Schema

### 2.1 Top-Level Structure

```cddl
; ABE-CBOR uses deterministic CBOR encoding (sorted integer keys, shortest forms)

ABE = #6.60001(ABE-Item)  ; Optional CBOR tag (private-use range)

ABE-Item = {
  0: uint .within 1..4,      ; kind: 1=MSK 2=MPK 3=SK 4=CT
  1: Suite,                  ; crypto suite descriptor
  2: uint .default 1,        ; version of this profile (current: 1)
  ?3: bstr,                  ; auth_id (UTF-8 bytes) for MA/DCPABE
  ?4: map,                   ; meta (free-form metadata for UX)
  * 5.. : any                ; kind-specific fields (see sections below)
}
```

### 2.2 Suite Descriptor

```cddl
Suite = {
  0: tstr,                   ; scheme_id (e.g., "cpabe-waters", "kpabe-gpsw")
  1: Curve,                  ; curve/field parameters
  2: GE,                     ; group element encoding profile
  ?3: HashKDF                ; hash/kdf suite ids (optional)
}

Curve = {
  0: tstr,                   ; curve_id (e.g., "bls12-381", "bn254")
  ?1: uint,                  ; security_level in bits (e.g., 128, 192, 256)
  ?2: map                    ; explicit params only if non-standard curve
}

GE = {
  0: uint,                   ; ge_enc_id (see registry for values)
  1: uint,                   ; endianness: 0=big-endian, 1=little-endian
  2: bool .default true,     ; subgroup_check required on decode
  ?3: map                    ; per-curve encoding options if needed
}

HashKDF = {
  0: tstr,                   ; hash_id (e.g., "SHA-256", "SHA-384", "BLAKE2s")
  ?1: tstr                   ; kdf_id (e.g., "HKDF-SHA256", "KDF1-SHA256")
}
```

### 2.3 ABE Types

#### 2.3.1 MSK (Master Secret Key)

```cddl
MSK = ABE-Item .and {
  0: 1,                      ; kind = MSK
  5: MSK-Body
}

MSK-Body = {
  0: GroupElems,             ; scheme-specific secret elements
  ?1: map                    ; delegation/authority secrets (MA/DCPABE)
}
```

#### 2.3.2 MPK (Master Public Key)

```cddl
MPK = ABE-Item .and {
  0: 2,                      ; kind = MPK
  5: MPK-Body
}

MPK-Body = {
  0: GroupElems              ; public elements (e.g., g, g^α, h, ...)
}
```

#### 2.3.3 SK (User Secret Key)

```cddl
SK = ABE-Item .and {
  0: 3,                      ; kind = SK
  5: SK-Body
}

SK-Body = {
  0: GroupElems,             ; key elements
  1: AttrSet,                ; bound attributes (canonicalized)
  ?2: DelegProof             ; MA/DCPABE provenance/signatures
}

DelegProof = {
  * tstr => any              ; flexible delegation proof structure
}
; Example fields: "issue_ts", "sig", "authority_chain", "epoch"
```

#### 2.3.4 CT (Ciphertext)

```cddl
CT = ABE-Item .and {
  0: 4,                      ; kind = CT
  5: CT-Body
}

CT-Body = {
  0: GroupElems,             ; header elements (C, C', C_i, ...)
  1: Policy,                 ; access policy
  ?2: bstr                   ; payload wrap (CEK-wrapped or KEM share)
}
```

### 2.4 Shared Primitives

#### 2.4.1 Group Elements

```cddl
GroupElems = [ +GE-Elem ]

GE-Elem = bstr               ; raw bytes for element (encoding per Suite.GE)
```

**Encoding rules:**
- Encoding format specified by `Suite.GE.ge_enc_id`
- Endianness specified by `Suite.GE.endianness`
- Must verify subgroup membership if `Suite.GE.subgroup_check = true`
- Identity/infinity points: represented as zero-length bstr `h''` unless encoding specifies otherwise

#### 2.4.2 Attribute Set

```cddl
AttrSet = {
  0: [ +Attr ],              ; array of attributes (sorted)
  ?1: map                    ; optional attribute domain metadata
}

Attr = {
  0: uint,                   ; type: 0=string 1=int 2=bytes 3=set 4=range
  1: any                     ; value per type (see attribute canonicalization)
}
```

**Attribute types:**

| Type | Value Format | Description |
|------|--------------|-------------|
| 0 (STRING) | `tstr` | UTF-8 NFC normalized string |
| 1 (INTEGER) | `int` | Signed integer (big-endian semantics) |
| 2 (BYTES) | `bstr` | Arbitrary byte string |
| 3 (SET) | `[+ any]` | Set represented as sorted array |
| 4 (RANGE) | `{0: int, 1: int, ?2: bool, ?3: bool}` | Range: min, max, min_inclusive, max_inclusive |

**Sorting rules:**
- Attributes in `AttrSet[0]` MUST be sorted by `(type, value_canonical_bytes)`
- For strings: bytewise comparison of UTF-8 NFC normalized form
- For integers: numerical comparison
- For bytes: bytewise comparison
- For sets: recursively sort elements, then bytewise comparison of CBOR encoding
- For ranges: compare by (min, max) tuple

#### 2.4.3 Policy

```cddl
Policy = {
  0: uint,                   ; encoding: 0=BoolAST 1=MSP
  1: any                     ; body: BoolAST or MSP (see below)
}
```

##### Boolean AST (RPN Token List)

```cddl
BoolAST = [ +Token ]

Token = {
  0: uint,                   ; kind: 0=ATTR 1=AND 2=OR 3=THRESH 4=NOT
  ?1: any                    ; payload (depends on kind)
}
```

**Token kinds:**

| Kind | Name | Payload (key 1) | Description |
|------|------|-----------------|-------------|
| 0 | ATTR | `AttrRef` | Attribute reference |
| 1 | AND | (none) | Logical AND |
| 2 | OR | (none) | Logical OR |
| 3 | THRESH | `{0: uint, 1: uint}` | Threshold: {k: threshold, n: total} |
| 4 | NOT | (none) | Logical NOT |

```cddl
AttrRef = {
  0: uint                    ; index into AttrSet[0] (0-based)
}
```

**Example:** Policy `(A AND B) OR C` in RPN:
```
[ {0:0, 1:{0:0}},    ; ATTR ref index 0 (A)
  {0:0, 1:{0:1}},    ; ATTR ref index 1 (B)
  {0:1},             ; AND
  {0:0, 1:{0:2}},    ; ATTR ref index 2 (C)
  {0:2} ]            ; OR
```

##### MSP (Monotone Span Program)

```cddl
MSP = {
  0: [ +[ +int ] ],          ; matrix rows (each row is vector over Z_p)
  1: [ +AttrRef ]            ; rho: row i -> attribute reference
}
```

**Encoding rules:**
- Matrix stored in row-major format
- Modulus p implied by curve field order
- Negative integers use CBOR negative integer encoding
- Matrix dimensions: M rows × N columns (N inferred from first row length)
- `|rho| = M` (one attribute reference per row)

**Example:** Identity MSP for 2 attributes:
```cbor
{
  0: [ [1, 0], [0, 1] ],     ; 2×2 identity matrix
  1: [ {0:0}, {0:1} ]        ; row 0 -> attr 0, row 1 -> attr 1
}
```

## 3. Deterministic Encoding Rules

To ensure byte-for-byte reproducibility, ABE-CBOR follows deterministic CBOR encoding rules based on CTAP2 Canonical CBOR and DAG-CBOR:

### 3.1 General Rules

1. **Shortest form**: Use shortest possible encoding for integers, lengths, etc.
2. **No indefinite lengths**: All arrays and maps must use definite-length encoding
3. **Sorted map keys**: Integer keys must be sorted in ascending order
4. **No duplicate keys**: Map keys must be unique
5. **Canonical floats**: Not used in ABE-CBOR (prefer fixed-point integers)

### 3.2 Integer Encoding

- Use shortest CBOR major type that fits the value
- Examples:
  - `0-23`: single byte (major type 0, additional info)
  - `24-255`: major type 0, additional info 24, 1 byte value
  - `256-65535`: major type 0, additional info 25, 2 bytes big-endian
  - Negative integers: major type 1, same rules for magnitude

### 3.3 String Encoding

- UTF-8 encoding required
- NFC normalization for attribute strings
- Shortest-form UTF-8 (no overlong sequences)

### 3.4 Byte String Encoding

- Raw bytes, no encoding transformation
- Deterministic if source is deterministic

### 3.5 Map Encoding

- Integer keys in ascending numerical order
- Text keys in bytewise lexicographic order (though ABE-CBOR uses integer keys)
- Encode keys before values

### 3.6 Array Encoding

- Elements in specified order
- For sorted arrays (AttrSet, sets), use canonical ordering

## 4. Attribute Canonicalization

### 4.1 String Attributes (type=0)

1. **UTF-8 NFC normalization**: Apply Unicode Normalization Form C
2. **Case sensitivity**: Preserve original case (case-insensitive matching is policy-dependent)
3. **Whitespace**: Preserve whitespace (trimming is application-specific)
4. **Empty strings**: Allowed if meaningful

**Example:**
```
Input:  "café" (UTF-8: 0x63 0x61 0x66 0xC3 0xA9)
Canonical: "café" (NFD then NFC: 0x63 0x61 0x66 0xC3 0xA9)
```

### 4.2 Integer Attributes (type=1)

1. **No leading zeros** in bignum representation
2. **Sign**: Use CBOR negative integer for negatives
3. **Range**: Any representable integer in CBOR

### 4.3 Bytes Attributes (type=2)

1. **No transformation**: Raw bytes as-is
2. **Sorting**: Bytewise lexicographic comparison

### 4.4 Set Attributes (type=3)

1. **Recursively canonicalize** each element
2. **Sort** elements by CBOR canonical encoding
3. **Remove duplicates** (sets are unique by definition)

### 4.5 Range Attributes (type=4)

1. **Normalize** to canonical form: `{min, max, min_inclusive, max_inclusive}`
2. **Validation**: Ensure `min ≤ max`
3. **Defaults**: `min_inclusive=true`, `max_inclusive=true` if not specified

## 5. Security Considerations

### 5.1 Subgroup Membership Checks

- **CRITICAL**: Always verify subgroup membership when decoding group elements
- Set `Suite.GE.subgroup_check = true` (default)
- Reject elements outside the prime-order subgroup
- Prevents small-subgroup attacks

### 5.2 Canonical Encodings

- **Reject non-canonical**: Refuse to decode non-canonical group element encodings
- Example: For compressed points, reject invalid compression flags
- Prevents malleability attacks

### 5.3 Identity Elements

- **Handle carefully**: Identity/infinity points may be valid in some schemes
- Document whether identity is allowed for each element position
- For SK and CT, typically identity in wrong position indicates attack

### 5.4 Attribute Security

- **Namespace attributes**: Use URI-like namespaces to avoid collisions
  - Example: `urn:example:role:admin`, `urn:org:dept:finance`
- **Avoid PII in attributes**: Consider privacy implications
- **Hash long attributes**: For efficiency, hash to fixed-size identifiers

### 5.5 Suite Binding

- **Bind suite to signatures**: When using COSE wrapping, include suite in signed data
- **Prevent suite confusion**: Validate suite matches expected parameters
- **Version checking**: Reject unknown profile versions for forward compatibility

## 6. Implementation Requirements

### 6.1 MUST Requirements

1. **Deterministic encoding**: Implementations MUST produce byte-identical output for same input
2. **Subgroup checks**: Implementations MUST verify subgroup membership by default
3. **Canonical rejection**: Implementations MUST reject non-canonical encodings
4. **Attribute sorting**: Implementations MUST sort attributes deterministically
5. **UTF-8 NFC**: Implementations MUST normalize string attributes to NFC

### 6.2 SHOULD Requirements

1. **Suite validation**: Implementations SHOULD validate suite compatibility
2. **Version checking**: Implementations SHOULD check profile version compatibility
3. **Metadata preservation**: Implementations SHOULD preserve metadata fields
4. **Error messages**: Implementations SHOULD provide clear error messages

### 6.3 MAY Requirements

1. **COSE wrapping**: Implementations MAY support COSE envelope for signatures
2. **MA-ABE support**: Implementations MAY implement multi-authority fields
3. **Extended attributes**: Implementations MAY support additional attribute types
4. **Compression**: Implementations MAY compress CBOR output (after encoding)

## 7. Test Vectors

See `ABE-CBOR-EXAMPLES.md` for complete test vectors including:
- Minimal MPK for BLS12-381
- SK with multiple attribute types
- CT with Boolean AST policy
- CT with MSP policy
- Cross-platform round-trip tests

## 8. Registry

See `ABE-CBOR-REGISTRY.md` for:
- Scheme identifiers
- Curve identifiers
- GE encoding formats
- Hash/KDF identifiers

## 9. References

### 9.1 Normative References

- **RFC 8949**: Concise Binary Object Representation (CBOR)
  https://www.rfc-editor.org/rfc/rfc8949.html

- **RFC 8610**: CBOR Data Definition Language (CDDL)
  https://www.rfc-editor.org/rfc/rfc8610.html

- **CTAP2 Canonical CBOR**: FIDO2 Client to Authenticator Protocol
  https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#ctap2-canonical-cbor-encoding-form

### 9.2 Informative References

- **BSW07**: Bethencourt, Sahai, Waters. "Ciphertext-Policy Attribute-Based Encryption"
  IEEE S&P 2007

- **GPSW06**: Goyal, Pandey, Sahai, Waters. "Attribute-Based Encryption for Fine-Grained Access Control"
  ACM CCS 2006

- **MCL**: https://github.com/herumi/mcl
  Cryptographic library for pairing-based cryptography

- **IETF Pairing-Friendly Curves**:
  https://datatracker.ietf.org/doc/draft-irtf-cfrg-pairing-friendly-curves/

## 10. Change Log

### Version 1.0 (2025-01-04)
- Initial specification
- Defined CDDL schema for all ABE types
- Specified deterministic encoding rules
- Documented attribute canonicalization
- Added security considerations

## Appendix A: CBOR Tag Registration

The ABE-CBOR tag `#6.60001` is in the private-use range (60000-6000). For production use, consider registering an official CBOR tag with IANA:

https://www.iana.org/assignments/cbor-tags/cbor-tags.xhtml

## Appendix B: CDDL Validation

To validate CBOR data against this specification, use a CDDL validator with the complete schema from Section 2.

Example tools:
- `cddl` Ruby gem: https://github.com/cabo/cddl
- Online validator: http://cbor.me/

## Appendix C: Migration from Legacy Formats

For migrating from OpenABE's legacy Base64 serialization:

1. **Auto-detect**: Check for CBOR major type at start of data
2. **Convert**: Parse legacy format, construct ABE-Item, encode to CBOR
3. **Validate**: Verify round-trip produces same cryptographic result
4. **Deprecate**: Set timeline for legacy format deprecation (recommend 2 versions)

---

**Document Status**: Draft
**Version**: 1.0
**Last Updated**: 2025-01-04
**Authors**: OpenABE Contributors
**License**: Same as OpenABE (AGPL-3.0)
