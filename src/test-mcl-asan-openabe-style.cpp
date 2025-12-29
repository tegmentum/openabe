// Test MCL with AddressSanitizer using OpenABE's random number generation approach
#include <iostream>
#include <cstring>
#include <cstdlib>
#include <ctime>

extern "C" {
#include <mcl/bn.h>
}

using namespace std;

// Mimic OpenABE's approach: generate random bytes, deserialize to Fr, then mod reduce
void generate_random_fr_openabe_style(mclBnFr* fr) {
    // Get 32 bytes of random data (256 bits for BN254 field)
    uint8_t buf[32];
    for (int i = 0; i < 32; i++) {
        buf[i] = rand() & 0xFF;
    }

    // Deserialize (this is what OpenABE does)
    int ret = mclBnFr_deserialize(fr, buf, 32);
    if (ret == 0) {
        // If deserialization failed, fall back to setting from bytes directly
        mclBnFr_setLittleEndian(fr, buf, 32);
    }

    // Get curve order for modular reduction
    char order_str[256];
    mclBn_getCurveOrder(order_str, sizeof(order_str));

    mclBnFr order_fr;
    mclBnFr_setStr(&order_fr, order_str, strlen(order_str), 10);

    // Reduce modulo order (this is what OpenABE does with zml_bignum_mod)
    // Note: Fr elements are automatically reduced, but let's be explicit
    // Actually, Fr elements are always < order, so this shouldn't be needed
    // But OpenABE does it, so let's mimic it
}

void print_fr_hex(const char* label, const mclBnFr* fr) {
    char buf[256];
    size_t len = mclBnFr_getStr(buf, sizeof(buf), fr, 16);
    cout << label << " (hex): 0x" << buf << endl;
}

int main() {
    cout << "=== MCL AddressSanitizer Test (OpenABE Style) ===" << endl;

    // Initialize MCL for BN254
    int ret = mclBn_init(MCL_BN254, MCLBN_COMPILED_TIME_VAR);
    if (ret != 0) {
        cerr << "mclBn_init failed: " << ret << endl;
        return 1;
    }

    cout << "MCL initialized successfully" << endl;

    // Seed RNG
    srand(time(NULL));

    int failures = 0;
    int successes = 0;

    // Run multiple iterations to catch non-deterministic bugs
    for (int iteration = 1; iteration <= 10; iteration++) {
        cout << "\n=== Iteration " << iteration << " ===" << endl;

        // Create test point
        mclBnG1 g;
        char point_seed[32];
        snprintf(point_seed, sizeof(point_seed), "test_point_%d", iteration);
        mclBnG1_hashAndMapTo(&g, point_seed, strlen(point_seed));

        // Create random scalar using OpenABE approach
        mclBnFr r;
        generate_random_fr_openabe_style(&r);

        print_fr_hex("Random scalar r", &r);

        // Compute r*g
        mclBnG1 rg;
        mclBnG1_mul(&rg, &g, &r);

        // Compute -r
        mclBnFr neg_r;
        mclBnFr_neg(&neg_r, &r);
        print_fr_hex("Negated scalar -r", &neg_r);

        // Verify r + (-r) = 0
        mclBnFr sum;
        mclBnFr_add(&sum, &r, &neg_r);
        if (!mclBnFr_isZero(&sum)) {
            cout << "ERROR: r + (-r) is not zero!" << endl;
            failures++;
            continue;
        }

        // Compute (-r)*g
        mclBnG1 neg_rg;
        mclBnG1_mul(&neg_rg, &g, &neg_r);

        // Compute r*g + (-r)*g
        mclBnG1 result;
        mclBnG1_add(&result, &rg, &neg_rg);

        // Check if result is zero (identity)
        bool is_zero = mclBnG1_isZero(&result);
        cout << "r*g + (-r)*g == identity? " << (is_zero ? "YES ✓" : "NO ✗ BUG!") << endl;

        if (!is_zero) {
            cout << "*** DETECTED BUG in iteration " << iteration << " ***" << endl;

            // Check if it equals g
            bool equals_g = mclBnG1_isEqual(&result, &g);
            cout << "Result equals g? " << (equals_g ? "YES" : "NO") << endl;

            failures++;
        } else {
            successes++;
        }
    }

    cout << "\n=== Summary ===" << endl;
    cout << "Successes: " << successes << "/10" << endl;
    cout << "Failures: " << failures << "/10" << endl;

    if (failures > 0) {
        cout << "\n*** NON-DETERMINISTIC BUG DETECTED ***" << endl;
        cout << "Same operation produces different results across runs!" << endl;
    }

    return failures > 0 ? 1 : 0;
}
