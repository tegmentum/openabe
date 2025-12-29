# BREAKTHROUGH: AES is NOT the Problem!

## Critical Discovery

The AES-256-ECB encryption is working **IDENTICALLY** between native and WASM!

### Evidence

From the captured logs, the first AES_ECB call produces:
- **Native**: `f29000b62a499fd0a9f39a6add2e7780`
- **WASM**: `f29000b62a499fd0a9f39a6add2e7780`

**IDENTICAL!**

## Then What's the Problem?

The issue must be in the **data flow** around the AES calls in `block_cipher_df()`. Let me trace through the function:

### block_cipher_df() Overview

1. **Construct buffer** (lines 181-199): Create IV and S structure
2. **First loop** (lines 206-224): XOR and encrypt data multiple times to reduce it to 48 bytes
3. **Second loop** (lines 231-236): Final encryption with reduced data

### Hypothesis: XOR/Chain Operations

The `block_cipher_df()` function does:
```cpp
for (j = 0; j < OpenABE_CTR_DRBG_SEEDLEN; j += OpenABE_CTR_DRBG_BLOCKSIZE) {
    p = buf;
    memset(chain, 0, OpenABE_CTR_DRBG_BLOCKSIZE);
    use_len = buf_len;

    while (use_len > 0) {
        for (i = 0; i < OpenABE_CTR_DRBG_BLOCKSIZE; i++)
            chain[i] ^= p[i];  // <-- XOR operation
        p += OpenABE_CTR_DRBG_BLOCKSIZE;
        use_len -= ...;
        AES_ECB(key, chain, chain, OpenABE_CTR_DRBG_BLOCKSIZE);
    }

    memcpy(tmp + j, chain, OpenABE_CTR_DRBG_BLOCKSIZE);
    buf[3]++;  // <-- Counter increment
}
```

## Likely Root Cause

Given that:
1. AES produces identical outputs
2. The final `block_cipher_df()` output differs

The problem must be in:
- **Buffer initialization** (`memset(buf, 0, max_buf_len)`)
- **Data copying** (`memcpy(p, data, data_len)`)
- **XOR operations** (`chain[i] ^= p[i]`)
- **Buffer indexing** (pointer arithmetic: `p += OpenABE_CTR_DRBG_BLOCKSIZE`)

Most likely: **Uninitialized memory** or **buffer overflow** in WASM that doesn't occur in native.

## Next Steps

1. **Add logging to block_cipher_df()** to capture:
   - Initial `buf` contents after memset
   - Data after memcpy
   - Chain values before/after XOR
   - AES inputs/outputs for each iteration

2. **Compare step-by-step** between native and WASM to find the exact point of divergence

3. **Check for memory issues**:
   - Buffer sizes
   - Pointer arithmetic
   - Alignment issues in WASM

## Impact

This is actually GOOD NEWS! The AES implementation is correct. The bug is likely a simple memory management issue in the data flow, which should be easier to fix than reimplementing AES.
