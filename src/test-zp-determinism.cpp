/// Test ZP Element Determinism
/// Creates ZP elements from same random bytes twice to check if values match

#include <stdio.h>
#include <string.h>
#include <iostream>
#include <openabe/openabe.h>

using namespace std;
using namespace oabe;

int main(int argc, char **argv) {
    cout << "========================================" << endl;
    cout << "  ZP Element Determinism Test" << endl;
    cout << "========================================" << endl;
    cout << endl;

    InitializeOpenABE();

    // Create a pairing to get the order
    unique_ptr<OpenABEPairing> pairing(new OpenABEPairing("BN254"));

    cout << "=== Test 1: Same Random Bytes → Same ZP? ===" << endl;

    // Create two RNGs with identical seeds
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

    // Get the group order from pairing
    bignum_t order;
    zml_bignum_init(&order);
    pairing->getGroupOrder(order);

    // Create two ZP elements from same random bytes
    ZP zp1(order);
    ZP zp2(order);

    cout << "\nCreating ZP element #1..." << endl;
    zp1.setRandom(&rng1, order);

    cout << "\nCreating ZP element #2..." << endl;
    zp2.setRandom(&rng2, order);

    cout << "\n=== Comparing ZP Elements ===" << endl;
    cout << "ZP1: " << zp1 << endl;
    cout << "ZP2: " << zp2 << endl;

    if (zp1 == zp2) {
        cout << "\n✅ PASS: ZP elements are IDENTICAL" << endl;
        cout << "Same random bytes → same ZP value" << endl;
    } else {
        cout << "\n❌ FAIL: ZP elements DIFFER!" << endl;
        cout << "Same random bytes → DIFFERENT ZP values" << endl;
        cout << "\nThis is the source of Bug #2!" << endl;
    }

    // Test with more values
    cout << "\n=== Test 2: Sequential ZP Elements ===" << endl;

    // Reset RNGs
    OpenABEByteString seed3, seed4;
    seed3.fillBuffer(0xCC, 32);
    seed4.fillBuffer(0xCC, 32);

    OpenABECTR_DRBG rng3(seed3);
    OpenABECTR_DRBG rng4(seed4);

    OpenABEByteString nonce2;
    nonce2.fillBuffer(0xDD, 16);
    rng3.setSeed(nonce2);
    rng4.setSeed(nonce2);

    bool all_match = true;
    for (int i = 0; i < 5; i++) {
        ZP a(order), b(order);

        cout << "\nRound " << i << ":" << endl;
        a.setRandom(&rng3, order);
        b.setRandom(&rng4, order);

        if (a == b) {
            cout << "  ✅ Match" << endl;
        } else {
            cout << "  ❌ DIFFER" << endl;
            all_match = false;
        }
    }

    if (all_match) {
        cout << "\n✅ PASS: All sequential ZP elements match" << endl;
    } else {
        cout << "\n❌ FAIL: Sequential ZP elements differ!" << endl;
    }

    zml_bignum_free(order);
    ShutdownOpenABE();

    cout << "\n========================================" << endl;
    cout << "  Test Complete" << endl;
    cout << "========================================" << endl;

    return (zp1 == zp2 && all_match) ? 0 : 1;
}
