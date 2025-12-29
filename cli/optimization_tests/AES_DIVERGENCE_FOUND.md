# EXACT POINT OF DIVERGENCE FOUND!

## AES Call #0 (IDENTICAL)
**Native**:
- Plaintext: `00000000000000000000000000000000`
- Ciphertext: `f29000b62a499fd0a9f39a6add2e7780`

**WASM**:
- Plaintext: `00000000000000000000000000000000`
- Ciphertext: `f29000b62a499fd0a9f39a6add2e7780`

✅ **IDENTICAL** - AES working correctly

## AES Call #1 (DIVERGENCE BEGINS HERE!)
**Native**:
- Plaintext: `f29000862a499fe02823dc0e2cdc1917`
- Ciphertext: `36c622990a8b2bb8ca5b030219c41d98`

**WASM**:
- Plaintext: `f29000862a499fe07636274c28e77329` ❌
- Ciphertext: `0343be970d7ab4e18a9d1d2a9804651e`

⚠️ **DIFFERENT PLAINTEXTS!**

## Analysis

The AES encryption is working correctly! But the **INPUT** to AES call #1 is DIFFERENT between native and WASM.

Looking at the plaintexts:
```
Native: f29000862a499fe0 2823dc0e2cdc1917
WASM:   f29000862a499fe0 7636274c28e77329
        ^^^^^^^^^^^^^^^^ ^^^^^^^^^^^^^^^^^^
        SAME (16 bytes)  DIFFERENT
```

The first 8 bytes are identical, but the last 8 bytes differ!

## Root Cause

In `block_cipher_df()`, the plaintext for AES call #1 is the `chain` buffer after XOR operations.

The chain is constructed as:
```cpp
memset(chain, 0, OpenABE_CTR_DRBG_BLOCKSIZE);  // Initialize to zeros
while (use_len > 0) {
    for (i = 0; i < OpenABE_CTR_DRBG_BLOCKSIZE; i++)
        chain[i] ^= p[i];  // XOR with buffer data
    ...
}
```

Since the first 8 bytes of the plaintext are the same, the XOR operations up to that point are identical. But the last 8 bytes differ, meaning the `p[i]` values being XORed are different!

This means the **`buf` buffer** has different contents between native and WASM!

## The Smoking Gun

The `buf` buffer is initialized and filled here:
```cpp
memset(buf, 0, max_buf_len);  // Line 181
...
p = buf + OpenABE_CTR_DRBG_BLOCKSIZE;  // Line 189
*p++ = ( data_len >> 24 ) & 0xFF;  // Lines 190-197
...
memcpy(p, data, data_len);  // Line 196
p[data_len] = 0x80;  // Line 197
```

The issue must be in how the buffer is constructed! Likely:
1. **Uninitialized stack memory** - The `memset` might not be zeroing all bytes in WASM
2. **Buffer overflow** - Some write operation is going beyond bounds
3. **Endianness** - The bit shift operations for `data_len` might produce different results

Most likely: **Stack memory initialization** differs between native and WASM!

## Solution

Add explicit initialization or check for memory corruption in the buffer construction phase.
