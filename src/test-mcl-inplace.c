// Test if MCL correctly handles in-place operations
// Specifically: z = z * y (where result pointer equals first operand)

#include <stdio.h>
#include <string.h>
#define MCLBN_FP_UNIT_SIZE 4
#include <mcl/bn.h>

void printHex(const char* label, const void* data, size_t len) {
    const uint8_t* bytes = (const uint8_t*)data;
    printf("%s: ", label);
    for (size_t i = 0; i < (len > 32 ? 32 : len); i++) {
        printf("%02x", bytes[i]);
    }
    if (len > 32) printf("...");
    printf("\n");
}

int main() {
    printf("Testing MCL in-place operations\n");
    printf("=================================\n\n");

    // Initialize MCL for BN254
    if (mclBn_init(MCL_BN254, MCLBN_COMPILED_TIME_VAR) != 0) {
        printf("Failed to initialize MCL\n");
        return 1;
    }

    mclBnG1 P, Q;
    mclBnG2 R, S;
    mclBnGT A, B;

    // Generate random points
    mclBnG1_hashAndMapTo(&P, "P", 1);
    mclBnG1_hashAndMapTo(&Q, "Q", 1);
    mclBnG2_hashAndMapTo(&R, "R", 1);
    mclBnG2_hashAndMapTo(&S, "S", 1);

    // Test GT in-place multiplication
    printf("=== Test 1: GT in-place multiplication ===\n");
    mclBn_pairing(&A, &P, &R);
    mclBn_pairing(&B, &Q, &S);

    // Save A for comparison
    mclBnGT A_copy;
    memcpy(&A_copy, &A, sizeof(mclBnGT));

    // Compute A_expected = A * B using temporary
    mclBnGT A_expected;
    mclBnGT_mul(&A_expected, &A_copy, &B);

    // Compute A = A * B in-place
    mclBnGT_mul(&A, &A, &B);

    // Compare
    if (mclBnGT_isEqual(&A, &A_expected)) {
        printf("✓ GT in-place multiplication works correctly\n");
    } else {
        printf("✗ GT in-place multiplication FAILS!\n");
        uint8_t buf1[576], buf2[576];
        size_t len1 = mclBnGT_serialize(buf1, sizeof(buf1), &A);
        size_t len2 = mclBnGT_serialize(buf2, sizeof(buf2), &A_expected);
        printHex("  In-place result", buf1, len1);
        printHex("  Expected result", buf2, len2);
        return 1;
    }

    // Test GT division in-place
    printf("\n=== Test 2: GT in-place division ===\n");
    mclBn_pairing(&A, &P, &R);
    mclBn_pairing(&B, &Q, &S);

    // Save A for comparison
    memcpy(&A_copy, &A, sizeof(mclBnGT));

    // Compute A_expected = A / B using temporary
    mclBnGT B_inv;
    mclBnGT_inv(&B_inv, &B);
    mclBnGT_mul(&A_expected, &A_copy, &B_inv);

    // Compute A = A / B in-place
    mclBnGT_inv(&B_inv, &B);
    mclBnGT_mul(&A, &A, &B_inv);

    // Compare
    if (mclBnGT_isEqual(&A, &A_expected)) {
        printf("✓ GT in-place division works correctly\n");
    } else {
        printf("✗ GT in-place division FAILS!\n");
        uint8_t buf1[576], buf2[576];
        size_t len1 = mclBnGT_serialize(buf1, sizeof(buf1), &A);
        size_t len2 = mclBnGT_serialize(buf2, sizeof(buf2), &A_expected);
        printHex("  In-place result", buf1, len1);
        printHex("  Expected result", buf2, len2);
        return 1;
    }

    // Test G1 in-place addition
    printf("\n=== Test 3: G1 in-place addition ===\n");
    mclBnG1_hashAndMapTo(&P, "P", 1);
    mclBnG1_hashAndMapTo(&Q, "Q", 1);

    // Save P for comparison
    mclBnG1 P_copy;
    memcpy(&P_copy, &P, sizeof(mclBnG1));

    // Compute P_expected = P + Q using temporary
    mclBnG1 P_expected;
    mclBnG1_add(&P_expected, &P_copy, &Q);

    // Compute P = P + Q in-place
    mclBnG1_add(&P, &P, &Q);

    // Compare
    if (mclBnG1_isEqual(&P, &P_expected)) {
        printf("✓ G1 in-place addition works correctly\n");
    } else {
        printf("✗ G1 in-place addition FAILS!\n");
        return 1;
    }

    printf("\n=== All tests PASSED ===\n");
    printf("MCL correctly handles in-place operations\n");
    return 0;
}
