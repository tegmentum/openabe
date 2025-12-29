# CTR-DRBG update_internal() Native vs WASM Comparison

## Summary

**KEY FINDING**: The tmp buffer values differ between native and WASM from the VERY FIRST call to `update_internal()`. This means the bug occurs BEFORE the first update_internal call, in the initialization or the first AES encryption operations.

## Call #0 Comparison

### Native
```
tmp buffer (48 bytes): 38eb67b5b11f93e5f9f9755b5e52264cd2244b3031d1b6819bd9a576d3c77d19800a291322a43b84fc8b3a7438797d69
tmp[0..31] (new key): 38eb67b5b11f93e5f9f9755b5e52264cd2244b3031d1b6819bd9a576d3c77d19
tmp[32..47] (new counter): 800a291322a43b84fc8b3a7438797d69
```

### WASM
```
tmp buffer (48 bytes): 807cb7126f82f7a97e6641197958795793cccc0e2de7a2ee511f1d0954b97056e4fe0de81bc4d76df096b0bcd10c9a68
tmp[0..31] (new key): 807cb7126f82f7a97e6641197958795793cccc0e2de7a2ee511f1d0954b97056
tmp[32..47] (new counter): e4fe0de81bc4d76df096b0bcd10c9a68
```

### Analysis
**COMPLETELY DIFFERENT** - Not a single byte matches!

This means the issue is NOT in the update_internal function itself, but in:
1. The initialization of the CTR-DRBG state
2. The entropy/nonce input
3. Or the very first AES operations that generate the tmp buffer

##  Root Cause Location

The divergence happens in the initial `update_internal()` call during CTR-DRBG instantiation. Looking at the `update_internal` function:

```cpp
static int update_internal(OpenABECtrDrbg& ctx, const uint8_t data[OpenABE_CTR_DRBG_SEEDLEN]) {
    unsigned char tmp[OpenABE_CTR_DRBG_SEEDLEN];  // 48 bytes
    unsigned char *p = tmp;

    // Generate 48 bytes by encrypting counter 3 times
    for (j = 0; j < 48; j += 16) {
        // Increment counter
        for (i = 16; i > 0; i--)
            if (++ctx->counter[i - 1] != 0)
                break;

        // Encrypt counter -> p
        AES_ECB(ctx->key, ctx->counter, p, 16);
        p += 16;
    }

    // XOR with input data
    for (i = 0; i < 48; i++) {
        tmp[i] ^= data[i];
    }

    // Copy to key and counter
    memcpy(ctx->key, tmp, 32);
    memcpy(ctx->counter, tmp + 32, 16);
}
```

Since the tmp buffer is completely different from the start, one of these must differ between native and WASM:

1. **Initial counter value** - Set during CTR-DRBG instantiation
2. **Initial key value** - Set during CTR-DRBG instantiation
3. **AES_ECB encryption** - OpenSSL's AES implementation behaves differently in WASM
4. **Input data parameter** - The entropy/nonce passed to update_internal

## Next Steps

1. Add logging to CTR-DRBG instantiation to capture:
   - Initial entropy value
   - Initial nonce value
   - Initial key after derivation
   - Initial counter after derivation

2. Add logging INSIDE the update_internal loop to capture:
   - Counter value before each increment
   - Counter value after each increment
   - AES output for each 16-byte block

3. Compare these values between native and WASM to pinpoint exact divergence

## Hypothesis

Most likely causes (in order of probability):
1. **OpenSSL AES in WASM** - The AES-256-ECB implementation produces different outputs
2. **Entropy source** - Different random bytes from OpenSSL's RAND_bytes() in WASM
3. **Memory initialization** - Uninitialized memory being used differently

Least likely:
- Counter increment logic (too simple to have platform-specific bugs)
- XOR operation (impossible to behave differently)
- memcpy (impossible to behave differently)
