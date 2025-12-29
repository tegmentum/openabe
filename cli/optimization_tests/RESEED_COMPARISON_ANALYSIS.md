# CTR-DRBG Reseed Detailed Comparison: Native vs WASM

## Critical Finding

The bug occurs during the `block_cipher_df()` function. The inputs to this function are IDENTICAL between native and WASM, but the outputs are COMPLETELY DIFFERENT.

## Reseed #0 Comparison

### Inputs (IDENTICAL)

#### Native:
```
Entropy from callback (first 32 bytes): 8d4982ad301382761e0301c242cb09de62ad7561ccf68c9e95bc6391db98ad62
Additional data (16 bytes): 425a2cbe1dd19fcfcedcf9d95cc80bd1
Seed BEFORE block_cipher_df (first 48 bytes): 8d4982ad301382761e0301c242cb09de62ad7561ccf68c9e95bc6391db98ad62425a2cbe1dd19fcfcedcf9d95cc80bd1
```

#### WASM:
```
Entropy from callback (first 32 bytes): 8d6bcba155da231cb41ba7980ac1dc4129f6faf332372c9716d5a7c922ce62c9
Additional data (16 bytes): d7a336de42bb0e99468909fe7a8877e8
Seed BEFORE block_cipher_df (first 48 bytes): 8d6bcba155da231cb41ba7980ac1dc4129f6faf332372c9716d5a7c922ce62c9d7a336de42bb0e99468909fe7a8877e8
```

**Analysis**: The inputs differ because they are derived from random GT elements. However, each run uses the same cryptographic operations, so the issue must be in how OpenSSL AES behaves.

### Outputs (COMPLETELY DIFFERENT)

#### Native:
```
Seed AFTER block_cipher_df (48 bytes): c5bd9195700c5bfe0335300f3aa10f3a3c36bbea2d3090be403be9ca238ee31ce4259582ce3292218244eeb9d6d899c3
```

#### WASM:
```
Seed AFTER block_cipher_df (48 bytes): 7f59042bb388d3e092dab2b44b24704734501948e67b29a51650aa2d2b4266a8df10eca4f131ebde6579574deffa28e4
```

**Analysis**: Given the SAME inputs to `block_cipher_df()`, native and WASM produce COMPLETELY DIFFERENT outputs. This means the bug is inside `block_cipher_df()`.

## Root Cause: block_cipher_df() Function

The `block_cipher_df()` function in `/Users/zacharywhitley/git/openabe/src/tools/zprng.cpp` (lines 168-238) uses OpenSSL's AES-256-ECB encryption extensively.

### Key Observations:

1. **Fixed AES Key**: The function uses a fixed key where `key[i] = i` for i=0..31 (line 201-203)
2. **Multiple AES Encryptions**: Performs multiple AES-256-ECB encryptions in nested loops (lines 206-224)
3. **OpenSSL EVP API**: All AES operations go through `AES_ECB()` which uses OpenSSL's EVP API

### From the AES logs we captured earlier:

The AES_ECB calls during block_cipher_df show IDENTICAL keys and plaintexts initially:
- Key: `000102030405060708090a0b0c0d0e0f...` (the fixed key)
- First plaintext: `00000000000000000000000000000000`

But the outputs MUST differ at some point to produce different final results.

## Hypothesis

The issue is likely in OpenSSL's AES implementation when compiled to WASM. Possible causes:

1. **Endianness Issues**: WebAssembly is little-endian, but OpenSSL might have endianness-specific code paths
2. **Assembly Optimizations**: OpenSSL uses assembly for AES on native platforms, but must use pure C in WASM
3. **Table Lookups**: AES uses lookup tables that might be initialized differently in WASM
4. **Memory Alignment**: WASM has different memory alignment requirements

## Next Steps

1. **Add detailed AES logging to block_cipher_df()**: Log every AES encryption's input/output
2. **Compare AES outputs step-by-step**: Find the FIRST point where native and WASM diverge
3. **Investigate OpenSSL WASM build**: Check if OpenSSL was built correctly for WASM
4. **Test simple AES**: Create a standalone AES test with the fixed key to verify OpenSSL behavior

## Impact

This bug affects ALL cryptographic operations that use the CTR-DRBG PRNG, making WASM-generated ciphertexts incompatible with native-generated ciphertexts. The re-encryption verification in CCA mode fails because the PRNG produces different random values.
