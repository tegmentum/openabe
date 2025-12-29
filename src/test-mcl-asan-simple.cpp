// Minimal test to run MCL with AddressSanitizer
#include <iostream>
#include <cstring>

extern "C" {
#include <mcl/bn.h>
}

using namespace std;

int main() {
    cout << "=== MCL AddressSanitizer Test ===" << endl;

    // Initialize MCL for BN254
    int ret = mclBn_init(MCL_BN254, MCLBN_COMPILED_TIME_VAR);
    if (ret != 0) {
        cerr << "mclBn_init failed: " << ret << endl;
        return 1;
    }

    cout << "MCL initialized successfully" << endl;

    // Create test point
    mclBnG1 g;
    mclBnG1_hashAndMapTo(&g, "test", 4);
    cout << "Created test point g" << endl;

    // Create test scalar
    mclBnFr r;
    mclBnFr_setInt(&r, 12345);
    cout << "Created scalar r = 12345" << endl;

    // Compute r*g
    mclBnG1 rg;
    mclBnG1_mul(&rg, &g, &r);
    cout << "Computed r*g" << endl;

    // Compute -r
    mclBnFr neg_r;
    mclBnFr_neg(&neg_r, &r);
    cout << "Computed -r" << endl;

    // Compute (-r)*g
    mclBnG1 neg_rg;
    mclBnG1_mul(&neg_rg, &g, &neg_r);
    cout << "Computed (-r)*g" << endl;

    // Compute r*g + (-r)*g
    mclBnG1 result;
    mclBnG1_add(&result, &rg, &neg_rg);
    cout << "Computed r*g + (-r)*g" << endl;

    // Check if result is zero (identity)
    bool is_zero = mclBnG1_isZero(&result);
    cout << "Result is zero? " << (is_zero ? "YES ✓" : "NO ✗ BUG!") << endl;

    if (!is_zero) {
        cout << "*** DETECTED BUG: r*g + (-r)*g should equal identity ***" << endl;

        // Check if it equals g
        bool equals_g = mclBnG1_isEqual(&result, &g);
        cout << "Result equals g? " << (equals_g ? "YES" : "NO") << endl;
    }

    return is_zero ? 0 : 1;
}
