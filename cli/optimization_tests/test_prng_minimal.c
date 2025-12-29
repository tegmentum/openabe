/*
 * Minimal CTR-DRBG PRNG test to isolate optimization bug
 * This extracts the core CTR-DRBG functions from zprng.cpp
 * and tests them with fixed inputs to see if optimization level affects output
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <openssl/evp.h>

#define OpenABE_CTR_DRBG_BLOCKSIZE   16
#define OpenABE_CTR_DRBG_KEYSIZE_BYTES 32

typedef struct {
    uint8_t counter[OpenABE_CTR_DRBG_BLOCKSIZE];
    uint8_t key[OpenABE_CTR_DRBG_KEYSIZE_BYTES];
    int reseed_counter;
} OpenABECtrDrbgContext;

/* AES-256-ECB encryption (from zprng.cpp:59-80) */
static void AesEvpBlockEncrypt(const EVP_CIPHER *cipher, const uint8_t* key,
                        const uint8_t* pl_ptr, uint8_t *ct_ptr, size_t pl_len)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "EVP_CIPHER_CTX_new failed\n");
        return;
    }

    EVP_CIPHER_CTX_init(ctx);

    int ret = EVP_EncryptInit_ex(ctx, cipher, NULL, key, NULL);
    if (ret != 1) {
        fprintf(stderr, "EVP_EncryptInit_ex failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return;
    }

    EVP_CIPHER_CTX_set_padding(ctx, 0);

    int len = 0;
    ret = EVP_EncryptUpdate(ctx, ct_ptr, &len, pl_ptr, (int)pl_len);
    if (ret != 1) {
        fprintf(stderr, "EVP_EncryptUpdate failed\n");
    }

    ret = EVP_EncryptFinal_ex(ctx, ct_ptr + len, &len);
    if (ret != 1) {
        fprintf(stderr, "EVP_EncryptFinal_ex failed\n");
    }

    EVP_CIPHER_CTX_free(ctx);
}

/* AES-ECB wrapper (from zprng.cpp:82-114, without debug logging) */
static void AES_ECB(const uint8_t *key, const uint8_t *plaintext, uint8_t *ciphertext, size_t len) {
    const EVP_CIPHER *cipher = EVP_aes_256_ecb();
    AesEvpBlockEncrypt(cipher, key, plaintext, ciphertext, len);
}

/* Counter increment (from zprng.cpp:360-366) */
static void increment_counter(OpenABECtrDrbgContext *ctx) {
    size_t i;
#ifdef __wasm__
    __asm__ volatile("" ::: "memory");
#endif
    for (i = OpenABE_CTR_DRBG_BLOCKSIZE; i > 0; i--) {
        if(++ctx->counter[i - 1] != 0)
            break;
    }
#ifdef __wasm__
    __asm__ volatile("" ::: "memory");
#endif
}

/* Generate one block (simplified from zprng.cpp:352-399) */
static void generate_block(OpenABECtrDrbgContext *ctx, uint8_t *output) {
    increment_counter(ctx);
    AES_ECB(ctx->key, ctx->counter, output, OpenABE_CTR_DRBG_BLOCKSIZE);
}

/* Initialize context with fixed values */
static void init_context(OpenABECtrDrbgContext *ctx) {
    /* Use fixed test vector */
    /* Key: all 0x42 */
    memset(ctx->key, 0x42, OpenABE_CTR_DRBG_KEYSIZE_BYTES);

    /* Counter: 0, 1, 2, 3, ... 15 */
    for (int i = 0; i < OpenABE_CTR_DRBG_BLOCKSIZE; i++) {
        ctx->counter[i] = (uint8_t)i;
    }

    ctx->reseed_counter = 1;
}

/* Print hex */
static void print_hex(const char *label, const uint8_t *data, size_t len) {
    printf("%s", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

int main() {
    OpenABECtrDrbgContext ctx;
    uint8_t output[OpenABE_CTR_DRBG_BLOCKSIZE];

    printf("=== CTR-DRBG PRNG Optimization Test ===\n");
    printf("Testing if compiler optimization affects PRNG output\n\n");

    /* Initialize with fixed values */
    init_context(&ctx);

    printf("Initial state:\n");
    print_hex("  Key:     ", ctx.key, OpenABE_CTR_DRBG_KEYSIZE_BYTES);
    print_hex("  Counter: ", ctx.counter, OpenABE_CTR_DRBG_BLOCKSIZE);
    printf("\n");

    /* Generate 10 blocks and print each */
    printf("Generated blocks:\n");
    for (int i = 0; i < 10; i++) {
        generate_block(&ctx, output);
        printf("Block %2d: ", i);
        for (int j = 0; j < OpenABE_CTR_DRBG_BLOCKSIZE; j++) {
            printf("%02x", output[j]);
        }
        printf("\n");
    }

    printf("\nFinal counter state:\n");
    print_hex("  Counter: ", ctx.counter, OpenABE_CTR_DRBG_BLOCKSIZE);

    return 0;
}
