#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>

// Test OpenSSL AES-256-ECB with fixed key and plaintext
int main() {
    // Fixed key: 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
    uint8_t key[32];
    for (int i = 0; i < 32; i++) {
        key[i] = i;
    }

    // Test plaintext: all zeros
    uint8_t plaintext[16] = {0};
    uint8_t ciphertext[16];

    // Setup EVP context for AES-256-ECB
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_set_padding(ctx, 0);  // No padding

    const EVP_CIPHER *cipher = EVP_aes_256_ecb();
    EVP_EncryptInit_ex(ctx, cipher, NULL, key, NULL);

    int olen = 512, tmp_len = 0, out_len = 0;
    uint8_t out[olen];
    memset(out, 0, olen);

    EVP_EncryptUpdate(ctx, out, &tmp_len, plaintext, 16);
    EVP_EncryptFinal_ex(ctx, out + tmp_len, &out_len);

    memcpy(ciphertext, out, 16);

    // Print results
    printf("Key: ");
    for (int i = 0; i < 32; i++) {
        printf("%02x", key[i]);
    }
    printf("\n");

    printf("Plaintext: ");
    for (int i = 0; i < 16; i++) {
        printf("%02x", plaintext[i]);
    }
    printf("\n");

    printf("Ciphertext: ");
    for (int i = 0; i < 16; i++) {
        printf("%02x", ciphertext[i]);
    }
    printf("\n");

    // Cleanup
    EVP_CIPHER_CTX_free(ctx);

    // Expected result from NIST test vectors:
    // Key: 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
    // Plaintext: 00000000000000000000000000000000
    // Expected: dc95c078a2408989ad48a21492842087
    printf("\nExpected (NIST): dc95c078a2408989ad48a21492842087\n");

    return 0;
}
