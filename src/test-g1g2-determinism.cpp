///
/// Copyright (c) 2018 Zeutro, LLC. All rights reserved.
///
/// This file is part of OpenABE.
///
/// Test program to verify Bug #2 fix - G1/G2::setRandom() determinism
///
/// This program tests whether the fix for MCL Bug #2 works correctly.
///

#include <iostream>
#include <string>
#include <cassert>
#include <openabe/openabe.h>
#include <openabe/zsymcrypto.h>
#include <openabe/zml/zpairing.h>

using namespace std;
using namespace oabe;
using namespace oabe::crypto;

void print_separator(const char* title) {
    cout << "\n========================================" << endl;
    cout << title << endl;
    cout << "========================================" << endl;
}

bool test_g1_determinism() {
    print_separator("TEST: G1::setRandom() Determinism");

    // Create two identical RNGs
    OpenABEByteString seed1, seed2;
    seed1.fillBuffer(0xCC, 32);
    seed2.fillBuffer(0xCC, 32);

    unique_ptr<OpenABERNG> rng1(new OpenABECTR_DRBG(seed1));
    unique_ptr<OpenABERNG> rng2(new OpenABECTR_DRBG(seed2));

    OpenABEByteString nonce;
    nonce.fillBuffer(0xDD, 16);
    rng1->setSeed(nonce);
    rng2->setSeed(nonce);

    // Initialize pairing
    unique_ptr<OpenABEPairing> pairing(new OpenABEPairing(DEFAULT_BP_PARAM));

    // Generate two G1 elements with identical seeds using the pairing's randomG1 method
    G1 g1_a = pairing->randomG1(rng1.get());
    G1 g1_b = pairing->randomG1(rng2.get());

    // Serialize to compare
    OpenABEByteString g1_a_bytes, g1_b_bytes;
    g1_a.serialize(g1_a_bytes);
    g1_b.serialize(g1_b_bytes);

    if (g1_a_bytes == g1_b_bytes) {
        cout << "✅ PASS: G1 elements are identical" << endl;
        cout << "   Length: " << g1_a_bytes.size() << " bytes" << endl;
        cout << "   First 8 bytes: " << g1_a_bytes.toHex().substr(0, 16) << endl;
        return true;
    } else {
        cout << "❌ FAIL: G1 elements differ" << endl;
        cout << "   G1_A length: " << g1_a_bytes.size() << " bytes" << endl;
        cout << "   G1_B length: " << g1_b_bytes.size() << " bytes" << endl;
        cout << "   G1_A bytes: " << g1_a_bytes.toHex().substr(0, 32) << "..." << endl;
        cout << "   G1_B bytes: " << g1_b_bytes.toHex().substr(0, 32) << "..." << endl;
        return false;
    }
}

bool test_g2_determinism() {
    print_separator("TEST: G2::setRandom() Determinism");

    // Create two identical RNGs
    OpenABEByteString seed1, seed2;
    seed1.fillBuffer(0xEE, 32);
    seed2.fillBuffer(0xEE, 32);

    unique_ptr<OpenABERNG> rng1(new OpenABECTR_DRBG(seed1));
    unique_ptr<OpenABERNG> rng2(new OpenABECTR_DRBG(seed2));

    OpenABEByteString nonce;
    nonce.fillBuffer(0xFF, 16);
    rng1->setSeed(nonce);
    rng2->setSeed(nonce);

    // Initialize pairing
    unique_ptr<OpenABEPairing> pairing(new OpenABEPairing(DEFAULT_BP_PARAM));

    // Generate two G2 elements with identical seeds
    G2 g2_a = pairing->randomG2(rng1.get());
    G2 g2_b = pairing->randomG2(rng2.get());

    // Serialize to compare
    OpenABEByteString g2_a_bytes, g2_b_bytes;
    g2_a.serialize(g2_a_bytes);
    g2_b.serialize(g2_b_bytes);

    if (g2_a_bytes == g2_b_bytes) {
        cout << "✅ PASS: G2 elements are identical" << endl;
        cout << "   Length: " << g2_a_bytes.size() << " bytes" << endl;
        cout << "   First 8 bytes: " << g2_a_bytes.toHex().substr(0, 16) << endl;
        return true;
    } else {
        cout << "❌ FAIL: G2 elements differ" << endl;
        cout << "   G2_A length: " << g2_a_bytes.size() << " bytes" << endl;
        cout << "   G2_B length: " << g2_b_bytes.size() << " bytes" << endl;
        cout << "   G2_A bytes: " << g2_a_bytes.toHex().substr(0, 32) << "..." << endl;
        cout << "   G2_B bytes: " << g2_b_bytes.toHex().substr(0, 32) << "..." << endl;
        return false;
    }
}

bool test_multiple_g1_calls() {
    print_separator("TEST: Multiple G1::setRandom() Calls");

    // Test that multiple calls with same RNG seed produce same sequence
    OpenABEByteString seed1, seed2;
    seed1.fillBuffer(0x11, 32);
    seed2.fillBuffer(0x11, 32);

    unique_ptr<OpenABERNG> rng1(new OpenABECTR_DRBG(seed1));
    unique_ptr<OpenABERNG> rng2(new OpenABECTR_DRBG(seed2));

    OpenABEByteString nonce;
    nonce.fillBuffer(0x22, 16);
    rng1->setSeed(nonce);
    rng2->setSeed(nonce);

    unique_ptr<OpenABEPairing> pairing(new OpenABEPairing(DEFAULT_BP_PARAM));

    bool all_match = true;
    for (int i = 0; i < 5; i++) {
        G1 g1_a = pairing->randomG1(rng1.get());
        G1 g1_b = pairing->randomG1(rng2.get());

        OpenABEByteString bytes_a, bytes_b;
        g1_a.serialize(bytes_a);
        g1_b.serialize(bytes_b);

        if (bytes_a != bytes_b) {
            cout << "❌ FAIL: Call #" << i << " produced different G1 elements" << endl;
            all_match = false;
            break;
        }
    }

    if (all_match) {
        cout << "✅ PASS: All 5 G1 pairs are identical" << endl;
        return true;
    }
    return false;
}

bool test_gt_determinism() {
    print_separator("TEST: GT Element Determinism via Pairing");

    // Create two identical RNGs
    OpenABEByteString seed1, seed2;
    seed1.fillBuffer(0x33, 32);
    seed2.fillBuffer(0x33, 32);

    unique_ptr<OpenABERNG> rng1(new OpenABECTR_DRBG(seed1));
    unique_ptr<OpenABERNG> rng2(new OpenABECTR_DRBG(seed2));

    OpenABEByteString nonce;
    nonce.fillBuffer(0x44, 16);
    rng1->setSeed(nonce);
    rng2->setSeed(nonce);

    unique_ptr<OpenABEPairing> pairing(new OpenABEPairing(DEFAULT_BP_PARAM));

    // Generate G1 and G2 elements
    G1 g1_a = pairing->randomG1(rng1.get());
    G2 g2_a = pairing->randomG2(rng1.get());

    G1 g1_b = pairing->randomG1(rng2.get());
    G2 g2_b = pairing->randomG2(rng2.get());

    // Compute pairings
    GT gt_a = pairing->pairing(g1_a, g2_a);
    GT gt_b = pairing->pairing(g1_b, g2_b);

    // Compare
    OpenABEByteString gt_a_bytes, gt_b_bytes;
    gt_a.serialize(gt_a_bytes);
    gt_b.serialize(gt_b_bytes);

    if (gt_a_bytes == gt_b_bytes) {
        cout << "✅ PASS: GT elements from pairing are identical" << endl;
        cout << "   Length: " << gt_a_bytes.size() << " bytes" << endl;
        return true;
    } else {
        cout << "❌ FAIL: GT elements differ" << endl;
        cout << "   GT_A length: " << gt_a_bytes.size() << " bytes" << endl;
        cout << "   GT_B length: " << gt_b_bytes.size() << " bytes" << endl;
        return false;
    }
}

int main(int argc, char **argv) {
    // Initialize the library
    InitializeOpenABE();

    cout << "\n╔════════════════════════════════════════════════════════════╗" << endl;
    cout << "║  MCL Bug #2 Fix Verification - G1/G2 Determinism Test     ║" << endl;
    cout << "║                                                            ║" << endl;
    cout << "║  This test verifies that G1::setRandom() and              ║" << endl;
    cout << "║  G2::setRandom() now use the provided RNG parameter       ║" << endl;
    cout << "║  instead of MCL's internal CSPRNG.                        ║" << endl;
    cout << "║                                                            ║" << endl;
    cout << "║  Expected: All tests should PASS after Bug #2 fix         ║" << endl;
    cout << "╚════════════════════════════════════════════════════════════╝" << endl;

    int passed = 0;
    int total = 4;

    try {
        // Test 1: G1 determinism (CRITICAL - tests Bug #2 fix)
        if (test_g1_determinism()) passed++;

        // Test 2: G2 determinism (CRITICAL - tests Bug #2 fix)
        if (test_g2_determinism()) passed++;

        // Test 3: Multiple G1 calls with same seed
        if (test_multiple_g1_calls()) passed++;

        // Test 4: GT elements via pairing
        if (test_gt_determinism()) passed++;

    } catch (const exception& e) {
        cout << "\n❌ EXCEPTION: " << e.what() << endl;
    }

    // Summary
    print_separator("TEST SUMMARY");
    cout << "Passed: " << passed << " / " << total << endl;

    if (passed == total) {
        cout << "\n🎉 SUCCESS! Bug #2 fix is working correctly!" << endl;
        cout << "G1/G2::setRandom() now use the provided RNG." << endl;
        cout << "This means CP-ABE CCA verification should work with MCL." << endl;
        ShutdownOpenABE();
        return 0;
    } else {
        cout << "\n⚠️  FAILURE: Some tests failed." << endl;
        cout << "Bug #2 fix may not be working correctly." << endl;
        ShutdownOpenABE();
        return 1;
    }
}
