# ABE-CBOR Test Vectors and Examples

## Version: 1.0
## Date: 2025-01-04
## Status: Draft

## 1. Introduction

This document provides test vectors and examples for ABE-CBOR v1 serialization format. All examples use CBOR diagnostic notation (RFC 8949) and include hex encodings for verification.

## 2. Minimal Examples

### 2.1 Simple Integer Map

**CBOR Diagnostic:**
```cbor
{
  0: 1,
  1: "hello"
}
```

**Hex Encoding:**
```
A2          # map(2)
   00       # unsigned(0)
   01       # unsigned(1)
   01       # unsigned(1)
   65       # text(5)
      68656C6C6F  # "hello"
```

**Total bytes**: 10

### 2.2 Nested Structure

**CBOR Diagnostic:**
```cbor
{
  0: 2,
  1: {
    0: "bls12-381",
    1: 128
  }
}
```

**Hex Encoding:**
```
A2          # map(2)
   00       # unsigned(0)
   02       # unsigned(2)
   01       # unsigned(1)
   A2       # map(2)
      00    # unsigned(0)
      6A    # text(10)
         626C7331322D333831  # "bls12-381"
      01    # unsigned(1)
      1880  # unsigned(128)
```

## 3. Suite Descriptor Examples

### 3.1 Minimal Suite (CP-ABE on BLS12-381)

**CBOR Diagnostic:**
```cbor
{
  0: "cpabe-waters",
  1: {
    0: "bls12-381",
    1: 128
  },
  2: {
    0: 0,    ; IETF compressed
    1: 0,    ; big-endian
    2: true  ; subgroup check
  }
}
```

**Hex Encoding:**
```
A3                    # map(3)
   00                 # unsigned(0) - scheme_id
   6C                 # text(12)
      637061626520D77617465727320  # "cpabe-waters"
   01                 # unsigned(1) - curve
   A2                 # map(2)
      00              # unsigned(0) - curve_id
      6A              # text(10)
         626C7331322D333831  # "bls12-381"
      01              # unsigned(1) - security_level
      1880            # unsigned(128)
   02                 # unsigned(2) - GE encoding
   A3                 # map(3)
      00              # unsigned(0) - encoding_id
      00              # unsigned(0) IETF compressed
      01              # unsigned(1) - endianness
      00              # unsigned(0) big-endian
      02              # unsigned(2) - subgroup_check
      F5              # true
```

**Total bytes**: 51

### 3.2 Full Suite with Hash/KDF

**CBOR Diagnostic:**
```cbor
{
  0: "cpabe-waters",
  1: {0: "bls12-381", 1: 128},
  2: {0: 0, 1: 0, 2: true},
  3: {
    0: "SHA-256",
    1: "HKDF-SHA256"
  }
}
```

**Hex Encoding:**
```
A4                    # map(4)
   00                 # scheme_id
   6C637061626520D77617465727320
   01                 # curve
   A2
      00 6A 626C7331322D333831
      01 1880
   02                 # GE
   A3
      00 00
      01 00
      02 F5
   03                 # hash/kdf
   A2                 # map(2)
      00              # hash_id
      67              # text(7)
         5348412D323536  # "SHA-256"
      01              # kdf_id
      6C              # text(12)
         484B44462D534841323536  # "HKDF-SHA256"
```

## 4. Attribute Examples

### 4.1 String Attributes

**CBOR Diagnostic:**
```cbor
{
  0: [
    {0: 0, 1: "urn:role:admin"},
    {0: 0, 1: "urn:dept:finance"}
  ]
}
```

**Hex Encoding:**
```
A1                    # map(1)
   00                 # unsigned(0) - attributes array
   82                 # array(2)
      A2              # map(2) - first attribute
         00           # type
         00           # STRING
         01           # value
         6E           # text(14)
            75726E3A726F6C653A61646D696E  # "urn:role:admin"
      A2              # map(2) - second attribute
         00 00
         01
         70           # text(16)
            75726E3A646570743A66696E616E6365  # "urn:dept:finance"
```

### 4.2 Mixed Attribute Types

**CBOR Diagnostic:**
```cbor
{
  0: [
    {0: 0, 1: "department"},        ; string
    {0: 1, 1: 42},                  ; integer
    {0: 2, 1: h'DEADBEEF'},         ; bytes
    {0: 4, 1: {0: 18, 1: 65, 2: true, 3: true}}  ; range [18, 65]
  ]
}
```

**Hex Encoding:**
```
A1                    # map(1)
   00                 # attributes array
   84                 # array(4)
      A2              # string attr
         00 00
         01 6A 6465706172746D656E74
      A2              # integer attr
         00 01
         01 182A     # unsigned(42)
      A2              # bytes attr
         00 02
         01 44 DEADBEEF
      A2              # range attr
         00 04
         01           # value
         A4           # map(4)
            00 1812   # min = 18
            01 1841   # max = 65
            02 F5     # min_inclusive = true
            03 F5     # max_inclusive = true
```

## 5. Policy Examples

### 5.1 Simple Boolean Policy: (A AND B)

**CBOR Diagnostic:**
```cbor
{
  0: 0,              ; Boolean AST encoding
  1: [
    {0: 0, 1: {0: 0}},   ; ATTR ref index 0 (A)
    {0: 0, 1: {0: 1}},   ; ATTR ref index 1 (B)
    {0: 1}               ; AND
  ]
}
```

**Hex Encoding:**
```
A2                    # map(2)
   00 00              # encoding = BoolAST
   01                 # body
   83                 # array(3) tokens
      A2              # token 1: ATTR
         00 00        # kind = ATTR
         01 A1 00 00  # payload = {0: 0} (ref index 0)
      A2              # token 2: ATTR
         00 00
         01 A1 00 01  # payload = {0: 1} (ref index 1)
      A1              # token 3: AND
         00 01        # kind = AND
```

### 5.2 Complex Boolean Policy: ((A AND B) OR C)

**CBOR Diagnostic:**
```cbor
{
  0: 0,
  1: [
    {0: 0, 1: {0: 0}},   ; ATTR A (index 0)
    {0: 0, 1: {0: 1}},   ; ATTR B (index 1)
    {0: 1},              ; AND
    {0: 0, 1: {0: 2}},   ; ATTR C (index 2)
    {0: 2}               ; OR
  ]
}
```

**Hex Encoding:**
```
A2                    # map(2)
   00 00
   01                 # body
   85                 # array(5) tokens (RPN order)
      A2 00 00 01 A1 00 00
      A2 00 00 01 A1 00 01
      A1 00 01
      A2 00 00 01 A1 00 02
      A1 00 02
```

### 5.3 Threshold Policy: (2-of-3)

**CBOR Diagnostic:**
```cbor
{
  0: 0,
  1: [
    {0: 0, 1: {0: 0}},   ; ATTR A
    {0: 0, 1: {0: 1}},   ; ATTR B
    {0: 0, 1: {0: 2}},   ; ATTR C
    {0: 3, 1: {0: 2, 1: 3}}  ; THRESH k=2, n=3
  ]
}
```

**Hex Encoding:**
```
A2
   00 00
   01
   84                 # array(4)
      A2 00 00 01 A1 00 00
      A2 00 00 01 A1 00 01
      A2 00 00 01 A1 00 02
      A2              # threshold token
         00 03        # kind = THRESH
         01           # payload
         A2           # map(2)
            00 02     # k = 2
            01 03     # n = 3
```

### 5.4 MSP Policy (Identity Matrix)

**CBOR Diagnostic:**
```cbor
{
  0: 1,              ; MSP encoding
  1: {
    0: [             ; matrix
      [1, 0],
      [0, 1]
    ],
    1: [             ; rho (row -> attribute mapping)
      {0: 0},        ; row 0 -> attr 0
      {0: 1}         ; row 1 -> attr 1
    ]
  }
}
```

**Hex Encoding:**
```
A2                    # map(2)
   00 01              # encoding = MSP
   01                 # body
   A2                 # map(2)
      00              # matrix
      82              # array(2) rows
         82 01 00     # [1, 0]
         82 00 01     # [0, 1]
      01              # rho
      82              # array(2)
         A1 00 00     # {0: 0}
         A1 00 01     # {0: 1}
```

## 6. Complete ABE Examples

### 6.1 Minimal MPK (CP-ABE, BLS12-381)

**CBOR Diagnostic:**
```cbor
#6.60001({           ; ABE-CBOR tag
  0: 2,              ; kind = MPK
  1: {               ; suite
    0: "cpabe-waters",
    1: {0: "bls12-381", 1: 128},
    2: {0: 0, 1: 0, 2: true}
  },
  2: 1,              ; version = 1
  5: {               ; MPK body
    0: [             ; public elements
      h'97F1D3A73197D7942695638C4FA9AC0FC3688C4F9774B905A14E3A3F171BAC586C55E83FF97A1AEFFB3AF00ADB22C6BB',  ; g (G1, 48 bytes compressed)
      h'93E02B6052719F607DACD3A088274F65596BD0D09920B61AB5DA61BBDC7F5049334CF11213945D57E5AC7D055D042B7E024AA2B2F08F0A91260805272DC51051C6E47AD4FA403B02B4510B647AE3D1770BAC0326A805BBEFD48056C8C121BDB8'   ; h (G2, 96 bytes compressed)
    ]
  }
})
```

**Hex Encoding:**
```
D9 EA61               # tag(60001) ABE-CBOR
A4                    # map(4)
   00 02              # kind = MPK
   01                 # suite
   A3
      00 6C 63706162652D7761746572
      01 A2 00 6A 626C7331322D333831 01 1880
      02 A3 00 00 01 00 02 F5
   02 01              # version = 1
   05                 # body
   A1
      00              # group elements
      82              # array(2)
         58 30        # bytes(48) - G1 element
            97F1D3A73197D7942695638C4FA9AC0FC3688C4F9774B905A14E3A3F171BAC586C55E83FF97A1AEFFB3AF00ADB22C6BB
         58 60        # bytes(96) - G2 element
            93E02B6052719F607DACD3A088274F65596BD0D09920B61AB5DA61BBDC7F5049334CF11213945D57E5AC7D055D042B7E024AA2B2F08F0A91260805272DC51051C6E47AD4FA403B02B4510B647AE3D1770BAC0326A805BBEFD48056C8C121BDB8
```

**Total bytes**: ~250 bytes

### 6.2 User Secret Key with Attributes

**CBOR Diagnostic:**
```cbor
#6.60001({
  0: 3,              ; kind = SK
  1: {               ; suite (same as above)
    0: "cpabe-waters",
    1: {0: "bls12-381", 1: 128},
    2: {0: 0, 1: 0, 2: true}
  },
  2: 1,
  3: h'6F72672E6578616D706C65',  ; auth_id = "org.example"
  5: {               ; SK body
    0: [             ; secret key elements (simplified: 2 elements)
      h'ABCD...',    ; K (G1)
      h'EF01...'     ; L (G1)
    ],
    1: {             ; attributes
      0: [
        {0: 0, 1: "urn:role:admin"},
        {0: 0, 1: "urn:dept:finance"}
      ]
    },
    2: {             ; delegation proof
      "issue_ts": 1704067200,
      "authority": "org.example"
    }
  }
})
```

### 6.3 Ciphertext with Boolean Policy

**CBOR Diagnostic:**
```cbor
#6.60001({
  0: 4,              ; kind = CT
  1: {               ; suite
    0: "cpabe-waters",
    1: {0: "bls12-381", 1: 128},
    2: {0: 0, 1: 0, 2: true}
  },
  2: 1,
  5: {               ; CT body
    0: [             ; header elements
      h'...',        ; C (GT, 576 bytes)
      h'...',        ; C' (G1, 48 bytes)
      h'...',        ; C_1 (G2, 96 bytes)
      h'...'         ; C_2 (G2, 96 bytes)
    ],
    1: {             ; policy: (admin AND finance)
      0: 0,          ; BoolAST
      1: [
        {0: 0, 1: {0: 0}},  ; admin
        {0: 0, 1: {0: 1}},  ; finance
        {0: 1}              ; AND
      ]
    },
    2: h'...'        ; encrypted session key (32 bytes)
  }
})
```

## 7. Test Vectors for Validation

### 7.1 Determinism Test

**Input** (same data, encoded twice):
```cbor
{0: 1, 1: "test", 2: h'DEADBEEF'}
```

**Expected hex** (both encodings must match exactly):
```
A3 00 01 01 64 74657374 02 44 DEADBEEF
```

**Validation**: Both encodings produce identical bytes.

### 7.2 Map Key Ordering Test

**Input** (keys intentionally out of order):
```cbor
{5: "e", 1: "a", 3: "c", 2: "b", 4: "d"}
```

**Expected hex** (keys sorted 1, 2, 3, 4, 5):
```
A5
   01 61 61  ; 1: "a"
   02 61 62  ; 2: "b"
   03 61 63  ; 3: "c"
   04 61 64  ; 4: "d"
   05 61 65  ; 5: "e"
```

### 7.3 Shortest Form Test

**Input**:
```cbor
{0: 0, 1: 24, 2: 256, 3: 65536}
```

**Expected hex**:
```
A4
   00 00        ; 0: 0 (single byte)
   01 1818      ; 1: 24 (uint8)
   02 190100    ; 2: 256 (uint16)
   03 1A00010000  ; 3: 65536 (uint32)
```

## 8. Cross-Platform Test Vectors

### 8.1 Native C++ to WASM

**Test**: Encode same data on native C++ and WASM, compare bytes.

**Input**: MPK from section 6.1

**Expected**: Byte-for-byte identical

**Validation script**:
```bash
# Native
./test_cbor_encode > native_mpk.cbor
xxd native_mpk.cbor > native_mpk.hex

# WASM
node test_cbor_wasm.js > wasm_mpk.cbor
xxd wasm_mpk.cbor > wasm_mpk.hex

# Compare
diff native_mpk.hex wasm_mpk.hex
# Should output: (no differences)
```

### 8.2 Round-Trip Test

**Test**: Encode → Decode → Encode, compare original and final encodings.

**Input**: Any ABE object (MSK, MPK, SK, CT)

**Expected**: Identical bytes

**C++ pseudocode**:
```cpp
ABE_Item original = createMPK();
ByteString encoded1 = encodeCBOR(original);
ABE_Item decoded = decodeCBOR(encoded1);
ByteString encoded2 = encodeCBOR(decoded);
assert(encoded1 == encoded2);  // Must be identical
```

## 9. Error Cases

### 9.1 Non-Canonical Encoding (Should Reject)

**Input** (indefinite-length array):
```
9F 01 02 03 FF  ; indefinite array [1, 2, 3]
```

**Expected**: Decoder MUST reject (non-canonical)

### 9.2 Unsorted Map Keys (Should Reject)

**Input**:
```
A2 01 61 61 00 61 62  ; {1: "a", 0: "b"} - wrong order
```

**Expected**: Decoder MUST reject (keys not sorted)

### 9.3 Wrong Subgroup (Should Reject)

**Input**: Group element not in prime-order subgroup

**Expected**: Decoder MUST reject when `subgroup_check = true`

## 10. Interoperability Tests

### 10.1 OpenABE ↔ rabe

**Test**: Create SK in OpenABE, decrypt CT in rabe

**Steps**:
1. OpenABE: Generate MSK/MPK
2. OpenABE: Export MPK as CBOR → `mpk.cbor`
3. rabe: Import `mpk.cbor`
4. rabe: Encrypt message → `ct.cbor`
5. OpenABE: Import `ct.cbor`
6. OpenABE: Generate SK → `sk.cbor`
7. rabe: Import `sk.cbor`, decrypt CT

**Expected**: Successful decryption, plaintext matches

## 11. Performance Benchmarks

### 11.1 Encoding Speed

**Target**: <1ms for typical ABE objects

| Object | Size | Encode Time | Decode Time |
|--------|------|-------------|-------------|
| MPK | ~250 bytes | <0.1ms | <0.1ms |
| SK | ~500 bytes | <0.2ms | <0.2ms |
| CT | ~1KB | <0.5ms | <0.5ms |

### 11.2 Size Overhead

**Target**: <10% vs legacy format

| Object | Legacy | CBOR | Overhead |
|--------|--------|------|----------|
| MPK | 220 bytes | ~250 bytes | +13% |
| SK | 450 bytes | ~500 bytes | +11% |
| CT | 950 bytes | ~1050 bytes | +10% |

## 12. Validation Checklist

For each test vector:
- [ ] Hex encoding matches exactly
- [ ] CBOR diagnostic notation is correct
- [ ] Deterministic encoding verified
- [ ] Map keys are sorted
- [ ] Shortest forms used
- [ ] Round-trip encode/decode succeeds
- [ ] Cross-platform compatibility verified
- [ ] Subgroup checks pass

---

**Document Status**: Draft
**Version**: 1.0
**Last Updated**: 2025-01-04
**Maintainer**: OpenABE Project
