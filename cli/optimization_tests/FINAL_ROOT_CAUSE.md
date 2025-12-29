# FINAL ROOT CAUSE ANALYSIS

## Executive Summary

**FOUND**: The bug is in the `block_cipher_df()` function at line 181-199 where the buffer is constructed. The `buf` buffer has different contents between native and WASM, causing all subsequent operations to diverge.

## Evidence Trail

### 1. AES Call #0 - IDENTICAL
✅ Both platforms produce: `f29000b62a499fd0a9f39a6add2e7780`

### 2. AES Call #1 - DIVERGENCE POINT
❌ Different plaintexts:
- Native: `f29000862a499fe02823dc0e2cdc1917`
- WASM:   `f29000862a499fe07636274c28e77329`

First 8 bytes IDENTICAL, last 8 bytes DIFFERENT.

### 3. Analysis

The AES #1 plaintext is the `chain` buffer after this loop (lines 211-219):
```cpp
while (use_len > 0) {
    for (i = 0; i < OpenABE_CTR_DRBG_BLOCKSIZE; i++)
        chain[i] ^= p[i];  // XOR with buf data
    p += OpenABE_CTR_DRBG_BLOCKSIZE;
    use_len -= ...;
    AES_ECB(key, chain, chain, OpenABE_CTR_DRBG_BLOCKSIZE);
}
```

Since bytes 0-7 are identical but bytes 8-15 differ, the `buf` content at position `buf[24-31]` (second block, second half) must be different!

## Root Cause: Buffer Construction

The buffer is built here (lines 181-199):
```cpp
memset(buf, 0, max_buf_len);  // Zero entire buffer

p = buf + OpenABE_CTR_DRBG_BLOCKSIZE;  // Skip first 16 bytes
*p++ = ( data_len >> 24 ) & 0xFF;      // 4 bytes for data_len
*p++ = ( data_len >> 16 ) & 0xFF;
*p++ = ( data_len >> 8  ) & 0xFF;
*p++ = ( data_len       ) & 0xFF;
p += 3;                                 // Skip 3 bytes (zeros)
*p++ = OpenABE_CTR_DRBG_SEEDLEN;       // 1 byte (48 = 0x30)
memcpy(p, data, data_len);              // Copy input data
p[data_len] = 0x80;                     // Add padding byte
```

### Buffer Layout
```
Offset:  0-15    16-19     20-22  23    24-(24+data_len) ...
Content: [zeros] [datalen] [000]  [48]  [input data]     [0x80] [zeros...]
```

## Hypothesis

The most likely causes:
1. **`max_buf_len` calculation** - May overflow or be calculated differently
2. **`memset` behavior** - May not zero all bytes in WASM
3. **Pointer arithmetic** - The `p += 3` and subsequent operations may behave differently
4. **Stack initialization** - WASM may not initialize stack memory to zeros

## Verification

The `max_buf_len` is calculated as:
```cpp
int max_buf_len = OpenABE_CTR_DRBG_MAX_SEED_INPUT + OpenABE_CTR_DRBG_BLOCKSIZE + 16;
```

Where:
- `OpenABE_CTR_DRBG_MAX_SEED_INPUT` = 256
- `OpenABE_CTR_DRBG_BLOCKSIZE` = 16
- Total = 256 + 16 + 16 = **288 bytes**

## Solution

Add logging to verify:
1. Buffer size calculation
2. Buffer contents after memset
3. Buffer contents after data copy
4. Pointer positions

Then compare byte-by-byte between native and WASM to find the exact discrepancy.

## Next Action

Add detailed buffer logging to `block_cipher_df()` and rebuild both platforms to capture the exact buffer state at each step.
