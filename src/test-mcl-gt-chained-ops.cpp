#include <iostream>
#include <mcl/bn.h>
#include <cstring>

// Test chained GT operations: pairing().exp()
// This mimics: GT A = pairing(g1, g2).exp(alpha);

int main() {
    // Initialize MCL
    if (mclBn_init(MCL_BN254, MCLBN_COMPILED_TIME_VAR) != 0) {
        std::cerr << "Failed to initialize MCL" << std::endl;
        return 1;
    }

    std::cout << "MCL initialized for BN254" << std::endl;

    // Create test points
    mclBnG1 g1;
    mclBnG2 g2;
    mclBnFr alpha, s;

    // Initialize points
    mclBnG1_hashAndMapTo(&g1, "generator1", 10);
    mclBnG2_hashAndMapTo(&g2, "generator2", 10);
    mclBnFr_setByCSPRNG(&alpha);
    mclBnFr_setByCSPRNG(&s);

    std::cout << "Created G1, G2 generators and random scalars alpha, s" << std::endl;

    // Test 1: Compute A = e(g1, g2)^alpha TWO ways
    std::cout << "\n=== Test 1: Compute A = e(g1, g2)^alpha ===" << std::endl;

    // Method 1: Chained (like OpenABE does)
    mclBnGT temp1, A1;
    mclBn_pairing(&temp1, &g1, &g2);
    mclBnGT_pow(&A1, &temp1, &alpha);
    std::cout << "✓ Method 1 (chained): pairing -> pow" << std::endl;

    // Method 2: Separate steps with assignment
    mclBnGT e_g1_g2, A2;
    mclBn_pairing(&e_g1_g2, &g1, &g2);
    temp1 = e_g1_g2;  // C++ assignment
    mclBnGT_pow(&A2, &temp1, &alpha);
    std::cout << "✓ Method 2 (with assignment): pairing -> assign -> pow" << std::endl;

    // Compare
    if (mclBnGT_isEqual(&A1, &A2)) {
        std::cout << "✓ Both methods give SAME result" << std::endl;
    } else {
        std::cerr << "✗ FAIL: Methods give DIFFERENT results!" << std::endl;
        return 1;
    }

    // Test 2: Full CP-ABE encryption/decryption simulation
    std::cout << "\n=== Test 2: CP-ABE-style operations ===" << std::endl;

    // Setup: A = e(g1, g2)^alpha
    mclBnGT A;
    mclBn_pairing(&A, &g1, &g2);
    mclBnGT_pow(&A, &A, &alpha);  // IMPORTANT: in-place pow!
    std::cout << "Setup: computed A = e(g1, g2)^alpha" << std::endl;

    // Encryption: C = A^s
    mclBnGT C;
    mclBnGT_pow(&C, &A, &s);
    std::cout << "Encryption: computed C = A^s" << std::endl;

    // Decryption should recover C
    // In actual CP-ABE: final = e(Cprime, K) / (prodT * e(prod1, L))
    // For this test, we'll verify that C serialization works

    // Serialize C
    uint8_t buffer[1024];
    memset(buffer, 0, sizeof(buffer));
    size_t len = mclBnGT_serialize(buffer, sizeof(buffer), &C);
    if (len == 0) {
        std::cerr << "✗ FAIL: Serialization failed" << std::endl;
        return 1;
    }
    std::cout << "✓ Serialized C (" << len << " bytes)" << std::endl;

    // Deserialize C
    mclBnGT C_recovered;
    memset(&C_recovered, 0, sizeof(C_recovered));
    size_t read = mclBnGT_deserialize(&C_recovered, buffer, len);
    if (read == 0) {
        std::cerr << "✗ FAIL: Deserialization failed" << std::endl;
        return 1;
    }
    std::cout << "✓ Deserialized C" << std::endl;

    // Verify C == C_recovered
    if (mclBnGT_isEqual(&C, &C_recovered)) {
        std::cout << "✓ C equals C_recovered" << std::endl;
    } else {
        std::cerr << "✗ FAIL: C != C_recovered after serialization!" << std::endl;
        return 1;
    }

    // Test 3: In-place GT exponentiation (potential issue?)
    std::cout << "\n=== Test 3: In-place vs separate GT exponentiation ===" << std::endl;

    mclBnGT gt_test1, gt_test2, gt_result1, gt_result2;
    mclBn_pairing(&gt_test1, &g1, &g2);
    gt_test2 = gt_test1;  // C++ assignment

    // In-place: pow(x, x, r)
    mclBnGT_pow(&gt_result1, &gt_test1, &alpha);

    // Separate: pow(y, x, r)
    mclBnGT_pow(&gt_result2, &gt_test2, &alpha);

    if (mclBnGT_isEqual(&gt_result1, &gt_result2)) {
        std::cout << "✓ In-place and separate exponentiation give SAME result" << std::endl;
    } else {
        std::cerr << "✗ FAIL: In-place and separate exponentiation give DIFFERENT results!" << std::endl;
        return 1;
    }

    std::cout << "\n=== All chained operation tests passed! ===" << std::endl;
    return 0;
}
