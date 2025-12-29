/*
 * Pure MCL Test - G1/G2 Derived Element Pairing
 *
 * Test MCL handling of derived elements in CP-ABE-like patterns
 * Uses only MCL C API, no OpenABE wrapper
 */

#include <stdio.h>
#include <string.h>
#include <mcl/bn_c384_256.h>

void printGT(const char* label, const mclBnGT* gt) {
    uint8_t buf[384 * 12];
    size_t len = mclBnGT_serialize(buf, sizeof(buf), gt);
    printf("%s", label);
    for (size_t i = 0; i < 16 && i < len; i++) {
        printf("%02x", buf[i]);
    }
    printf("... (%zu bytes)\n", len);
}

void printFr(const char* label, const mclBnFr* fr) {
    char buf[1024];
    mclBnFr_getStr(buf, sizeof(buf), fr, 16);
    printf("%s%s\n", label, buf);
}

int main() {
    printf("\n=== Pure MCL G1/G2 Derived Element Test ===\n");

    // Initialize MCL
    if (mclBn_init(MCL_BN254, MCLBN_COMPILED_TIME_VAR) != 0) {
        fprintf(stderr, "ERROR: Failed to initialize MCL\n");
        return 1;
    }
    printf("✓ MCL BN254 initialized\n");

    // Get generators
    mclBnG1 g1;
    mclBnG2 g2;
    mclBnG1_hashAndMapTo(&g1, "g1", 2);
    mclBnG2_hashAndMapTo(&g2, "g2", 2);
    printf("✓ Generators created\n");

    // Test 1: Basic pairing bilinearity
    printf("\n--- Test 1: e(g1^a, g2) = e(g1, g2)^a ---\n");

    mclBnFr a;
    mclBnFr_setByCSPRNG(&a);
    printFr("Exponent a: ", &a);

    mclBnG1 g1_a;
    mclBnG1_mul(&g1_a, &g1, &a);

    mclBnGT gt1, gt_base, gt2;
    mclBn_pairing(&gt1, &g1_a, &g2);
    mclBn_pairing(&gt_base, &g1, &g2);
    mclBnGT_pow(&gt2, &gt_base, &a);

    printGT("e(g1^a, g2) = ", &gt1);
    printGT("e(g1, g2)^a = ", &gt2);

    if (mclBnGT_isEqual(&gt1, &gt2)) {
        printf("✓ PASS: Bilinearity holds\n");
    } else {
        printf("✗ FAIL: Bilinearity violated!\n");
        return 1;
    }

    // Test 2: Double derivation e(g1^s, g2^r) = e(g1, g2)^(sr)
    printf("\n--- Test 2: e(g1^s, g2^r) = e(g1, g2)^(sr) ---\n");

    mclBnFr r, s;
    mclBnFr_setByCSPRNG(&r);
    mclBnFr_setByCSPRNG(&s);
    printFr("s: ", &s);
    printFr("r: ", &r);

    mclBnG1 g1_s;
    mclBnG2 g2_r;
    mclBnG1_mul(&g1_s, &g1, &s);
    mclBnG2_mul(&g2_r, &g2, &r);

    mclBnGT gt_derived;
    mclBn_pairing(&gt_derived, &g1_s, &g2_r);
    printGT("e(g1^s, g2^r) = ", &gt_derived);

    mclBnFr sr;
    mclBnFr_mul(&sr, &s, &r);
    mclBnGT gt_expected;
    mclBnGT_pow(&gt_expected, &gt_base, &sr);
    printGT("e(g1, g2)^(sr) = ", &gt_expected);

    if (mclBnGT_isEqual(&gt_derived, &gt_expected)) {
        printf("✓ PASS: Double derivation works\n");
    } else {
        printf("✗ FAIL: Double derivation failed!\n");
        return 1;
    }

    // Test 3: CP-ABE decryption pattern
    printf("\n--- Test 3: CP-ABE Pattern: e(g1^s, g2^r) / (A * e(g1^x, g2^y)) ---\n");

    mclBnFr x, y, alpha;
    mclBnFr_setByCSPRNG(&x);
    mclBnFr_setByCSPRNG(&y);
    mclBnFr_setByCSPRNG(&alpha);
    printFr("x: ", &x);
    printFr("y: ", &y);
    printFr("alpha: ", &alpha);

    // Create derived elements
    mclBnG1 g1_x;
    mclBnG2 g2_y;
    mclBnG1_mul(&g1_x, &g1, &x);
    mclBnG2_mul(&g2_y, &g2, &y);

    // Compute pairings
    mclBnGT e_g1s_g2r, e_g1x_g2y;
    mclBn_pairing(&e_g1s_g2r, &g1_s, &g2_r);
    mclBn_pairing(&e_g1x_g2y, &g1_x, &g2_y);

    // A = e(g1, g2)^alpha
    mclBnGT A;
    mclBnGT_pow(&A, &gt_base, &alpha);
    printGT("A = e(g1,g2)^alpha = ", &A);

    // denominator = A * e(g1^x, g2^y)
    mclBnGT denominator;
    mclBnGT_mul(&denominator, &A, &e_g1x_g2y);
    printGT("denom = A * e(g1^x,g2^y) = ", &denominator);

    // result = e(g1^s, g2^r) / denominator
    mclBnGT denom_inv, result;
    mclBnGT_inv(&denom_inv, &denominator);
    mclBnGT_mul(&result, &e_g1s_g2r, &denom_inv);
    printGT("result = numerator / denom = ", &result);

    // Expected: e(g1, g2)^(sr - alpha - xy)
    mclBnFr xy, alpha_xy, expected_exp;
    mclBnFr_mul(&xy, &x, &y);
    mclBnFr_add(&alpha_xy, &alpha, &xy);
    mclBnFr_sub(&expected_exp, &sr, &alpha_xy);

    mclBnGT expected;
    mclBnGT_pow(&expected, &gt_base, &expected_exp);
    printGT("expected = e(g1,g2)^(sr-alpha-xy) = ", &expected);

    if (mclBnGT_isEqual(&result, &expected)) {
        printf("✓ PASS: CP-ABE pattern works correctly!\n");
    } else {
        printf("✗ FAIL: CP-ABE pattern produces wrong result!\n");
        printf("\nThis indicates MCL may have issues with complex formulas!\n");
        return 1;
    }

    // Test 4: Even more complex pattern with multiple GT terms
    printf("\n--- Test 4: Complex pattern with GT product ---\n");
    printf("Testing: e(g1^s, g2^r) / (prod_GT * e(g1^x, g2^y))\n");

    mclBnFr beta, gamma;
    mclBnFr_setByCSPRNG(&beta);
    mclBnFr_setByCSPRNG(&gamma);

    // prod_GT = e(g1,g2)^beta * e(g1,g2)^gamma
    mclBnGT temp_beta, temp_gamma, prod_GT;
    mclBnGT_pow(&temp_beta, &gt_base, &beta);
    mclBnGT_pow(&temp_gamma, &gt_base, &gamma);
    mclBnGT_mul(&prod_GT, &temp_beta, &temp_gamma);
    printGT("prod_GT = e(g1,g2)^beta * e(g1,g2)^gamma = ", &prod_GT);

    // denominator2 = prod_GT * e(g1^x, g2^y)
    mclBnGT denominator2;
    mclBnGT_mul(&denominator2, &prod_GT, &e_g1x_g2y);
    printGT("denom2 = prod_GT * e(g1^x,g2^y) = ", &denominator2);

    // final = e(g1^s, g2^r) / denominator2
    mclBnGT denom2_inv, final;
    mclBnGT_inv(&denom2_inv, &denominator2);
    mclBnGT_mul(&final, &e_g1s_g2r, &denom2_inv);
    printGT("final = numerator / denom2 = ", &final);

    // Expected: e(g1, g2)^(sr - beta - gamma - xy)
    mclBnFr beta_gamma, beta_gamma_xy, final_exp;
    mclBnFr_add(&beta_gamma, &beta, &gamma);
    mclBnFr_add(&beta_gamma_xy, &beta_gamma, &xy);
    mclBnFr_sub(&final_exp, &sr, &beta_gamma_xy);

    mclBnGT expected_final;
    mclBnGT_pow(&expected_final, &gt_base, &final_exp);
    printGT("expected = e(g1,g2)^(sr-beta-gamma-xy) = ", &expected_final);

    if (mclBnGT_isEqual(&final, &expected_final)) {
        printf("✓ PASS: Complex GT product pattern works!\n");
    } else {
        printf("✗ FAIL: Complex pattern produces wrong result!\n");
        printf("\n!!! This could be the CP-ABE bug !!!\n");
        return 1;
    }

    printf("\n=== All Tests PASSED ===\n");
    printf("\nConclusion: MCL correctly handles all tested patterns\n");
    printf("Including complex CP-ABE-like formulas.\n");

    return 0;
}
