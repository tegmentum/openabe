/// Simple RNG Determinism Test
/// Tests whether OpenABERNG produces deterministic output with same seed

#include <stdio.h>
#include <string.h>
#include <iostream>
#include <openabe/openabe.h>

using namespace std;
using namespace oabe;

int main(int argc, char **argv) {
    cout << "========================================" << endl;
    cout << "  Simple RNG Determinism Test" << endl;
    cout << "========================================" << endl;
    cout << endl;

    // Test 1: Basic RNG determinism
    cout << "=== Test 1: RNG with Same Seed ===" << endl;

    OpenABEByteString seed1, seed2;
    seed1.fillBuffer(0xAA, 32);
    seed2.fillBuffer(0xAA, 32);

    OpenABECTR_DRBG rng1(seed1);
    OpenABECTR_DRBG rng2(seed2);

    OpenABEByteString nonce;
    nonce.fillBuffer(0xBB, 16);
    rng1.setSeed(nonce);
    rng2.setSeed(nonce);

    cout << "Created two RNGs with identical seeds" << endl;

    OpenABEByteString bytes1, bytes2;
    rng1.getRandomBytes(&bytes1, 32);
    rng2.getRandomBytes(&bytes2, 32);

    cout << "RNG1: " << bytes1.toHex() << endl;
    cout << "RNG2: " << bytes2.toHex() << endl;

    if (bytes1 == bytes2) {
        cout << "✅ PASS: RNG is deterministic" << endl;
    } else {
        cout << "❌ FAIL: RNG is non-deterministic!" << endl;
        return 1;
    }

    // Test 2: Sequential calls
    cout << "\n=== Test 2: Sequential RNG Calls ===" << endl;

    OpenABEByteString seed3;
    seed3.fillBuffer(0xCC, 32);

    OpenABECTR_DRBG rng3(seed3);
    OpenABECTR_DRBG rng4(seed3);

    OpenABEByteString nonce2;
    nonce2.fillBuffer(0xDD, 16);
    rng3.setSeed(nonce2);
    rng4.setSeed(nonce2);

    bool all_match = true;
    for (int i = 0; i < 5; i++) {
        OpenABEByteString b1, b2;
        rng3.getRandomBytes(&b1, 32);
        rng4.getRandomBytes(&b2, 32);

        cout << "Round " << i << ":" << endl;
        cout << "  RNG3: " << b1.toHex().substr(0, 16) << "..." << endl;
        cout << "  RNG4: " << b2.toHex().substr(0, 16) << "..." << endl;

        if (b1 == b2) {
            cout << "  ✅ Match" << endl;
        } else {
            cout << "  ❌ DIFFER" << endl;
            all_match = false;
        }
    }

    if (all_match) {
        cout << "\n✅ PASS: Sequential calls are deterministic" << endl;
    } else {
        cout << "\n❌ FAIL: Sequential calls differ!" << endl;
        return 1;
    }

    cout << "\n========================================" << endl;
    cout << "  All Tests PASSED" << endl;
    cout << "========================================" << endl;

    return 0;
}
