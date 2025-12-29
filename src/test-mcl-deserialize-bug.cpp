// Test if mclBnFr_deserialize handles values >= order correctly
#include <iostream>
#include <cstring>

extern "C" {
#include <mcl/bn.h>
}

using namespace std;

int main() {
    cout << "=== Testing mclBnFr_deserialize with large values ===" << endl;

    // Initialize MCL for BN254
    int ret = mclBn_init(MCL_BN254, MCLBN_COMPILED_TIME_VAR);
    if (ret != 0) {
        cerr << "mclBn_init failed: " << ret << endl;
        return 1;
    }

    // Get curve order
    char order_str[256];
    mclBn_getCurveOrder(order_str, sizeof(order_str));
    cout << "Curve order: " << order_str << endl;

    mclBnFr order_fr;
    mclBnFr_setStr(&order_fr, order_str, strlen(order_str), 10);

    // Test 1: Deserialize a value that's definitely < order (all zeros except last byte)
    cout << "\n=== Test 1: Small value (last byte = 0x42) ===" << endl;
    uint8_t buf_small[32];
    memset(buf_small, 0, 32);
    buf_small[31] = 0x42;

    mclBnFr fr_small;
    int result = mclBnFr_deserialize(&fr_small, buf_small, 32);
    cout << "Deserialize result: " << result << " (0 = success)" << endl;

    char fr_str[256];
    mclBnFr_getStr(fr_str, sizeof(fr_str), &fr_small, 10);
    cout << "Value: " << fr_str << endl;

    // Test 2: Deserialize a value that's likely > order (all 0xFF)
    cout << "\n=== Test 2: Large value (all 0xFF) ===" << endl;
    uint8_t buf_large[32];
    memset(buf_large, 0xFF, 32);

    mclBnFr fr_large;
    result = mclBnFr_deserialize(&fr_large, buf_large, 32);
    cout << "Deserialize result: " << result << " (0 = success)" << endl;

    if (result != 0) {
        cout << "ERROR: mclBnFr_deserialize failed! This might be the bug." << endl;
        cout << "OpenABE assumes deserialize always succeeds and doesn't check return value!" << endl;
        return 1;
    }

    mclBnFr_getStr(fr_str, sizeof(fr_str), &fr_large, 10);
    cout << "Value: " << fr_str << endl;

    // Check if it's been reduced modulo order
    int cmp = mclBnFr_isEqual(&fr_large, &order_fr);
    if (cmp) {
        cout << "Value == order (should be reduced to 0)" << endl;
    }

    // Test 3: Set from large value using setLittleEndian (alternative API)
    cout << "\n=== Test 3: setLittleEndian with large value ===" << endl;
    mclBnFr fr_le;
    ret = mclBnFr_setLittleEndian(&fr_le, buf_large, 32);
    cout << "setLittleEndian result: " << ret << " (0 = success)" << endl;

    mclBnFr_getStr(fr_str, sizeof(fr_str), &fr_le, 10);
    cout << "Value: " << fr_str << endl;

    // Test 4: The problematic pattern from OpenABE
    cout << "\n=== Test 4: OpenABE pattern (random bytes -> deserialize -> no mod) ===" << endl;

    for (int i = 0; i < 5; i++) {
        cout << "\nIteration " << (i+1) << ":" << endl;

        // Generate "random" bytes (using simple pattern for reproducibility)
        uint8_t buf[32];
        for (int j = 0; j < 32; j++) {
            buf[j] = (uint8_t)((i * 37 + j * 13) & 0xFF);
        }

        cout << "First 4 bytes: " << hex << (int)buf[0] << " " << (int)buf[1]
             << " " << (int)buf[2] << " " << (int)buf[3] << dec << endl;

        mclBnFr fr;
        result = mclBnFr_deserialize(&fr, buf, 32);

        if (result == 0) {
            mclBnFr_getStr(fr_str, sizeof(fr_str), &fr, 10);
            cout << "Deserialized successfully: " << fr_str << endl;

            // Now test scalar multiplication
            mclBnG1 g, result_g;
            mclBnG1_hashAndMapTo(&g, "test", 4);

            mclBnG1_mul(&result_g, &g, &fr);
            cout << "Scalar mult: OK" << endl;
        } else {
            cout << "ERROR: Deserialize failed with code " << result << endl;
            cout << "This leaves Fr in undefined state!" << endl;
        }
    }

    return 0;
}
