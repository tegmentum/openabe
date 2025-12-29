#include <iostream>
#include <mcl/bn.h>

// Test that millerLoop + finalExp gives same result as pairing
// And that product of miller loops + final exp equals product of pairings

int main() {
    // Initialize MCL
    if (mclBn_init(MCL_BN254, MCLBN_COMPILED_TIME_VAR) != 0) {
        std::cerr << "Failed to initialize MCL" << std::endl;
        return 1;
    }

    std::cout << "MCL initialized for BN254" << std::endl;

    // Create some test points
    mclBnG1 P1, P2;
    mclBnG2 Q1, Q2;
    mclBnGT result1, result2, result3, result4, temp;
    mclBnFr r;

    // Hash to create points
    mclBnG1_hashAndMapTo(&P1, "test1", 5);
    mclBnG1_hashAndMapTo(&P2, "test2", 5);
    mclBnG2_hashAndMapTo(&Q1, "test3", 5);
    mclBnG2_hashAndMapTo(&Q2, "test4", 5);

    // Test 1: Verify that pairing(P1, Q1) == finalExp(millerLoop(P1, Q1))
    std::cout << "\n=== Test 1: Single pairing ===" << std::endl;
    mclBn_pairing(&result1, &P1, &Q1);
    mclBn_millerLoop(&temp, &P1, &Q1);
    mclBn_finalExp(&result2, &temp);

    if (mclBnGT_isEqual(&result1, &result2)) {
        std::cout << "✓ pairing(P1,Q1) == finalExp(millerLoop(P1,Q1))" << std::endl;
    } else {
        std::cout << "✗ FAIL: pairing(P1,Q1) != finalExp(millerLoop(P1,Q1))" << std::endl;
        return 1;
    }

    // Test 2: Compare two methods for computing e(P1,Q1) * e(P2,Q2)
    std::cout << "\n=== Test 2: Multi-pairing ===" << std::endl;

    // Method 1 (WRONG): pairing(P1,Q1) * pairing(P2,Q2)
    mclBnGT e1, e2;
    mclBn_pairing(&e1, &P1, &Q1);
    mclBn_pairing(&e2, &P2, &Q2);
    mclBnGT_mul(&result3, &e1, &e2);
    std::cout << "Method 1 (multiply pairings): computed" << std::endl;

    // Method 2 (CORRECT): finalExp(millerLoop(P1,Q1) * millerLoop(P2,Q2))
    mclBnGT m1, m2, m_prod;
    mclBn_millerLoop(&m1, &P1, &Q1);
    mclBn_millerLoop(&m2, &P2, &Q2);
    mclBnGT_mul(&m_prod, &m1, &m2);
    mclBn_finalExp(&result4, &m_prod);
    std::cout << "Method 2 (miller loops then final exp): computed" << std::endl;

    if (mclBnGT_isEqual(&result3, &result4)) {
        std::cout << "✓ Both methods give same result!" << std::endl;
        std::cout << "  This means finalExp IS distributive (unexpected!)" << std::endl;
    } else {
        std::cout << "✗ Methods give DIFFERENT results" << std::endl;
        std::cout << "  Method 2 is the CORRECT one for multi-pairing" << std::endl;
        std::cout << "  This confirms finalExp is NOT distributive" << std::endl;
    }

    // Test 3: Verify bilinearity with method 2
    std::cout << "\n=== Test 3: Bilinearity test with method 2 ===" << std::endl;
    mclBnFr_setByCSPRNG(&r);

    mclBnG1 rP1;
    mclBnG2 rQ2;
    mclBnG1_mul(&rP1, &P1, &r);
    mclBnG2_mul(&rQ2, &Q2, &r);

    // e(rP1, Q1) * e(P2, rQ2) using method 2
    mclBnGT m3, m4, m_prod2;
    mclBn_millerLoop(&m3, &rP1, &Q1);
    mclBn_millerLoop(&m4, &P2, &rQ2);
    mclBnGT_mul(&m_prod2, &m3, &m4);
    mclBnGT test_left;
    mclBn_finalExp(&test_left, &m_prod2);

    // e(P1, Q1) * e(P2, Q2))^r
    mclBnGT test_right;
    mclBnGT_pow(&test_right, &result4, &r);

    if (mclBnGT_isEqual(&test_left, &test_right)) {
        std::cout << "✓ Bilinearity verified!" << std::endl;
    } else {
        std::cout << "✗ Bilinearity test FAILED" << std::endl;
        return 1;
    }

    std::cout << "\n=== All tests passed! ===" << std::endl;
    return 0;
}
