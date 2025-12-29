#include <iostream>
#include <mcl/bn.h>
#include <cstring>

// Test GT element serialization/deserialization
// This tests if GT elements can be serialized and deserialized correctly

int main() {
    // Initialize MCL
    if (mclBn_init(MCL_BN254, MCLBN_COMPILED_TIME_VAR) != 0) {
        std::cerr << "Failed to initialize MCL" << std::endl;
        return 1;
    }

    std::cout << "MCL initialized for BN254" << std::endl;

    // Create test points
    mclBnG1 P;
    mclBnG2 Q;
    mclBnGT gt1, gt2;

    // Hash to create points
    mclBnG1_hashAndMapTo(&P, "testP", 5);
    mclBnG2_hashAndMapTo(&Q, "testQ", 5);

    // Compute pairing
    mclBn_pairing(&gt1, &P, &Q);
    std::cout << "Computed GT element via pairing" << std::endl;

    // Serialize gt1
    uint8_t buffer[1024];
    memset(buffer, 0, sizeof(buffer));
    size_t serialized_len = mclBnGT_serialize(buffer, sizeof(buffer), &gt1);

    if (serialized_len == 0) {
        std::cerr << "✗ FAIL: Serialization failed" << std::endl;
        return 1;
    }

    std::cout << "✓ Serialized GT element (" << serialized_len << " bytes)" << std::endl;

    // Deserialize into gt2
    memset(&gt2, 0, sizeof(gt2));
    size_t deserialized_len = mclBnGT_deserialize(&gt2, buffer, serialized_len);

    if (deserialized_len == 0) {
        std::cerr << "✗ FAIL: Deserialization failed" << std::endl;
        return 1;
    }

    std::cout << "✓ Deserialized GT element (" << deserialized_len << " bytes)" << std::endl;

    // Check if they're equal
    if (mclBnGT_isEqual(&gt1, &gt2)) {
        std::cout << "✓ Original and deserialized GT elements are EQUAL" << std::endl;
    } else {
        std::cerr << "✗ FAIL: Original and deserialized GT elements are DIFFERENT" << std::endl;
        return 1;
    }

    // Test 2: Multiply gt1 by itself, then serialize/deserialize
    std::cout << "\n=== Test 2: GT multiplication + serialization ===" << std::endl;

    mclBnGT gt3, gt4;
    mclBnGT_mul(&gt3, &gt1, &gt1);  // gt3 = gt1^2
    std::cout << "Computed gt3 = gt1 * gt1" << std::endl;

    // Serialize gt3
    memset(buffer, 0, sizeof(buffer));
    serialized_len = mclBnGT_serialize(buffer, sizeof(buffer), &gt3);
    if (serialized_len == 0) {
        std::cerr << "✗ FAIL: Serialization of gt3 failed" << std::endl;
        return 1;
    }
    std::cout << "✓ Serialized gt3 (" << serialized_len << " bytes)" << std::endl;

    // Deserialize into gt4
    memset(&gt4, 0, sizeof(gt4));
    deserialized_len = mclBnGT_deserialize(&gt4, buffer, serialized_len);
    if (deserialized_len == 0) {
        std::cerr << "✗ FAIL: Deserialization of gt3 failed" << std::endl;
        return 1;
    }
    std::cout << "✓ Deserialized into gt4" << std::endl;

    // Check if they're equal
    if (mclBnGT_isEqual(&gt3, &gt4)) {
        std::cout << "✓ gt3 and gt4 are EQUAL" << std::endl;
    } else {
        std::cerr << "✗ FAIL: gt3 and gt4 are DIFFERENT" << std::endl;
        return 1;
    }

    // Test 3: GT division + serialization
    std::cout << "\n=== Test 3: GT division + serialization ===" << std::endl;

    mclBnGT gt5, gt6, gt7;
    mclBnG1_hashAndMapTo(&P, "testP2", 6);
    mclBnG2_hashAndMapTo(&Q, "testQ2", 6);
    mclBn_pairing(&gt5, &P, &Q);

    // Compute gt6 = gt5 / gt1
    mclBnGT gt1_inv;
    mclBnGT_inv(&gt1_inv, &gt1);
    mclBnGT_mul(&gt6, &gt5, &gt1_inv);
    std::cout << "Computed gt6 = gt5 / gt1" << std::endl;

    // Serialize and deserialize gt6
    memset(buffer, 0, sizeof(buffer));
    serialized_len = mclBnGT_serialize(buffer, sizeof(buffer), &gt6);
    if (serialized_len == 0) {
        std::cerr << "✗ FAIL: Serialization of gt6 failed" << std::endl;
        return 1;
    }

    memset(&gt7, 0, sizeof(gt7));
    deserialized_len = mclBnGT_deserialize(&gt7, buffer, serialized_len);
    if (deserialized_len == 0) {
        std::cerr << "✗ FAIL: Deserialization of gt6 failed" << std::endl;
        return 1;
    }

    if (mclBnGT_isEqual(&gt6, &gt7)) {
        std::cout << "✓ GT division result serializes/deserializes correctly" << std::endl;
    } else {
        std::cerr << "✗ FAIL: GT division result does NOT serialize/deserialize correctly" << std::endl;
        return 1;
    }

    std::cout << "\n=== All GT serialization tests passed! ===" << std::endl;
    return 0;
}
