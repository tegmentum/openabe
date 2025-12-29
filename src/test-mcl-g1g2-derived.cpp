/*
 * Test MCL G1/G2 Derived Element Pairing
 *
 * Purpose: Test if G1/G2 elements created via scalar multiplication
 *          behave correctly in pairings - critical for CP-ABE
 *
 * Waters CP-ABE creates many elements like:
 *   - K = g2^r (where r is random)
 *   - L = g2^beta_inv (where beta_inv = beta^-1)
 *   - D_i = (H(attr_i)^r) (hash to G1, then exponentiate)
 *   - Cprime = g1^s (where s is random)
 *
 * Then it pairs these derived elements:
 *   - e(Cprime, K) = e(g1^s, g2^r)
 *   - e(D_i, something)
 *
 * This test verifies MCL handles these patterns correctly.
 */

#include <iostream>
#include <iomanip>
#include <cstring>
#include <openabe/openabe.h>

extern "C" {
#include <mcl/bn_c384_256.h>
}

using namespace std;
using namespace oabe;

void printGT(const char* label, const mclBnGT* gt) {
    uint8_t buf[384 * 12];
    size_t len = mclBnGT_serialize(buf, sizeof(buf), gt);
    cout << label;
    for (size_t i = 0; i < min(len, (size_t)16); i++) {
        cout << hex << setw(2) << setfill('0') << (int)buf[i];
    }
    cout << "... (" << dec << len << " bytes)" << endl;
}

void printFr(const char* label, const mclBnFr* fr) {
    char buf[1024];
    mclBnFr_getStr(buf, sizeof(buf), fr, 16);
    cout << label << buf << endl;
}

int main() {
    cout << "\n=== MCL G1/G2 Derived Element Pairing Test ===" << endl;

    // Initialize MCL with BN254
    if (mclBn_init(MCL_BN254, MCLBN_COMPILED_TIME_VAR) != 0) {
        cerr << "ERROR: Failed to initialize MCL with BN254" << endl;
        return 1;
    }
    cout << "✓ MCL BN254 initialized" << endl;

    // Get generators
    mclBnG1 g1;
    mclBnG2 g2;
    mclBnG1_hashAndMapTo(&g1, "generator_g1", 12);
    mclBnG2_hashAndMapTo(&g2, "generator_g2", 12);
    cout << "✓ Generators created" << endl;

    // Test 1: Basic pairing property e(g1^a, g2) = e(g1, g2)^a
    cout << "\n--- Test 1: Pairing Bilinearity with Derived G1 ---" << endl;

    mclBnFr a;
    mclBnFr_setByCSPRNG(&a);
    printFr("Exponent a: ", &a);

    // Compute g1^a
    mclBnG1 g1_a;
    mclBnG1_mul(&g1_a, &g1, &a);
    cout << "✓ Computed g1^a" << endl;

    // Method 1: e(g1^a, g2)
    mclBnGT gt1;
    mclBn_pairing(&gt1, &g1_a, &g2);
    printGT("e(g1^a, g2) = ", &gt1);

    // Method 2: e(g1, g2)^a
    mclBnGT gt_base, gt2;
    mclBn_pairing(&gt_base, &g1, &g2);
    mclBnGT_pow(&gt2, &gt_base, &a);
    printGT("e(g1, g2)^a = ", &gt2);

    if (mclBnGT_isEqual(&gt1, &gt2)) {
        cout << "✓ PASS: e(g1^a, g2) == e(g1, g2)^a" << endl;
    } else {
        cout << "✗ FAIL: Bilinearity violated!" << endl;
        return 1;
    }

    // Test 2: Pairing with both G1 and G2 derived
    cout << "\n--- Test 2: Pairing with Both Elements Derived ---" << endl;

    mclBnFr r, s;
    mclBnFr_setByCSPRNG(&r);
    mclBnFr_setByCSPRNG(&s);
    printFr("Exponent r: ", &r);
    printFr("Exponent s: ", &s);

    // Compute g1^s and g2^r
    mclBnG1 g1_s;
    mclBnG2 g2_r;
    mclBnG1_mul(&g1_s, &g1, &s);
    mclBnG2_mul(&g2_r, &g2, &r);
    cout << "✓ Computed g1^s and g2^r" << endl;

    // Method 1: e(g1^s, g2^r)
    mclBnGT gt_derived;
    mclBn_pairing(&gt_derived, &g1_s, &g2_r);
    printGT("e(g1^s, g2^r) = ", &gt_derived);

    // Method 2: e(g1, g2)^(s*r)
    mclBnFr sr;
    mclBnFr_mul(&sr, &s, &r);
    mclBnGT gt_expected;
    mclBn_pairing(&gt_base, &g1, &g2);
    mclBnGT_pow(&gt_expected, &gt_base, &sr);
    printGT("e(g1, g2)^(s*r) = ", &gt_expected);

    if (mclBnGT_isEqual(&gt_derived, &gt_expected)) {
        cout << "✓ PASS: e(g1^s, g2^r) == e(g1, g2)^(s*r)" << endl;
    } else {
        cout << "✗ FAIL: Double derivation violated bilinearity!" << endl;
        return 1;
    }

    // Test 3: Waters CP-ABE pattern - multiple derived elements
    cout << "\n--- Test 3: Waters CP-ABE Pattern ---" << endl;
    cout << "Simulating: e(g1^s, g2^r) / (e(g1^x, g2^y))" << endl;

    mclBnFr x, y;
    mclBnFr_setByCSPRNG(&x);
    mclBnFr_setByCSPRNG(&y);
    printFr("Exponent x: ", &x);
    printFr("Exponent y: ", &y);

    // Compute elements
    mclBnG1 g1_x;
    mclBnG2 g2_y;
    mclBnG1_mul(&g1_x, &g1, &x);
    mclBnG2_mul(&g2_y, &g2, &y);

    // Compute pairings
    mclBnGT e_g1s_g2r, e_g1x_g2y;
    mclBn_pairing(&e_g1s_g2r, &g1_s, &g2_r);
    mclBn_pairing(&e_g1x_g2y, &g1_x, &g2_y);

    printGT("e(g1^s, g2^r) = ", &e_g1s_g2r);
    printGT("e(g1^x, g2^y) = ", &e_g1x_g2y);

    // Compute division
    mclBnGT e_inv, result;
    mclBnGT_inv(&e_inv, &e_g1x_g2y);
    mclBnGT_mul(&result, &e_g1s_g2r, &e_inv);
    printGT("result = e(g1^s, g2^r) / e(g1^x, g2^y) = ", &result);

    // Expected: e(g1, g2)^(sr - xy)
    mclBnFr xy, sr_minus_xy;
    mclBnFr_mul(&xy, &x, &y);
    mclBnFr_sub(&sr_minus_xy, &sr, &xy);

    mclBnGT expected_result;
    mclBn_pairing(&gt_base, &g1, &g2);
    mclBnGT_pow(&expected_result, &gt_base, &sr_minus_xy);
    printGT("expected = e(g1, g2)^(sr - xy) = ", &expected_result);

    if (mclBnGT_isEqual(&result, &expected_result)) {
        cout << "✓ PASS: Division of pairings with derived elements works correctly" << endl;
    } else {
        cout << "✗ FAIL: Division pattern failed!" << endl;
        return 1;
    }

    // Test 4: Element identity after operations
    cout << "\n--- Test 4: Element Identity Preservation ---" << endl;

    // Create element, pair it, serialize it, then pair again
    mclBnFr t;
    mclBnFr_setByCSPRNG(&t);

    mclBnG1 g1_t;
    mclBnG1_mul(&g1_t, &g1, &t);

    // First pairing
    mclBnGT gt_first;
    mclBn_pairing(&gt_first, &g1_t, &g2);
    printGT("First pairing e(g1^t, g2) = ", &gt_first);

    // Serialize and deserialize g1_t
    uint8_t g1_buf[256];
    size_t g1_len = mclBnG1_serialize(g1_buf, sizeof(g1_buf), &g1_t);

    mclBnG1 g1_t_restored;
    mclBnG1_deserialize(&g1_t_restored, g1_buf, g1_len);
    cout << "✓ Serialized and restored G1 element" << endl;

    // Second pairing with restored element
    mclBnGT gt_second;
    mclBn_pairing(&gt_second, &g1_t_restored, &g2);
    printGT("Second pairing e(g1^t_restored, g2) = ", &gt_second);

    if (mclBnGT_isEqual(&gt_first, &gt_second)) {
        cout << "✓ PASS: Serialization preserves element identity in pairings" << endl;
    } else {
        cout << "✗ FAIL: Serialization corrupted element!" << endl;
        return 1;
    }

    // Test 5: Complex formula like CP-ABE
    cout << "\n--- Test 5: Complex CP-ABE-like Formula ---" << endl;
    cout << "Testing: final = e(g1^s, g2^r) / (GT_prod * e(g1^x, g2^y))" << endl;

    // Create a GT product term (like prodT in CP-ABE)
    mclBnFr alpha, beta;
    mclBnFr_setByCSPRNG(&alpha);
    mclBnFr_setByCSPRNG(&beta);

    mclBnGT GT_prod;
    mclBn_pairing(&gt_base, &g1, &g2);

    mclBnGT temp1, temp2;
    mclBnGT_pow(&temp1, &gt_base, &alpha);
    mclBnGT_pow(&temp2, &gt_base, &beta);
    mclBnGT_mul(&GT_prod, &temp1, &temp2);

    printGT("GT_prod = e(g1,g2)^alpha * e(g1,g2)^beta = ", &GT_prod);

    // Denominator: GT_prod * e(g1^x, g2^y)
    mclBnGT denominator;
    mclBnGT_mul(&denominator, &GT_prod, &e_g1x_g2y);
    printGT("denominator = GT_prod * e(g1^x, g2^y) = ", &denominator);

    // Final: e(g1^s, g2^r) / denominator
    mclBnGT denom_inv, final;
    mclBnGT_inv(&denom_inv, &denominator);
    mclBnGT_mul(&final, &e_g1s_g2r, &denom_inv);
    printGT("final = e(g1^s, g2^r) / denominator = ", &final);

    // Expected: e(g1, g2)^(sr - alpha - beta - xy)
    mclBnFr alpha_beta, alpha_beta_xy, expected_exp;
    mclBnFr_add(&alpha_beta, &alpha, &beta);
    mclBnFr_add(&alpha_beta_xy, &alpha_beta, &xy);
    mclBnFr_sub(&expected_exp, &sr, &alpha_beta_xy);

    mclBnGT expected_final;
    mclBnGT_pow(&expected_final, &gt_base, &expected_exp);
    printGT("expected = e(g1,g2)^(sr-alpha-beta-xy) = ", &expected_final);

    if (mclBnGT_isEqual(&final, &expected_final)) {
        cout << "✓ PASS: Complex CP-ABE-like formula works correctly!" << endl;
    } else {
        cout << "✗ FAIL: Complex formula produces wrong result!" << endl;
        cout << "\n!!! This could be related to the CP-ABE bug !!!" << endl;
        return 1;
    }

    cout << "\n=== All Tests Passed ===" << endl;
    cout << "\nConclusion:" << endl;
    cout << "MCL correctly handles:" << endl;
    cout << "  ✓ Pairing with derived G1 elements" << endl;
    cout << "  ✓ Pairing with derived G2 elements" << endl;
    cout << "  ✓ Pairing with both elements derived" << endl;
    cout << "  ✓ Division of pairings" << endl;
    cout << "  ✓ Element serialization/deserialization" << endl;
    cout << "  ✓ Complex formulas similar to CP-ABE" << endl;

    return 0;
}
