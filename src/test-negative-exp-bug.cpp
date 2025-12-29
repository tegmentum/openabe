// Test for negative exponent bug with random ZP values
#include <iostream>
#include <openabe/openabe.h>

using namespace oabe;
using namespace std;

int main() {
    InitializeOpenABE();

    cout << "=== Testing Negative Exponent with Random ZP ===" << endl;

    unique_ptr<OpenABERNG> rng(new OpenABERNG);
    OpenABEPairing pairing("BN_P254");

    // Test with G1 elements
    cout << "\n[TEST 1] G1: g1^r * g1^(-r) = identity" << endl;
    G1 g1 = pairing.randomG1(rng.get());
    ZP r = pairing.randomZP(rng.get());
    cout << "g1: " << g1 << endl;
    cout << "r: " << r << endl;

    G1 g1_exp_r = g1.exp(r);
    cout << "g1^r: " << g1_exp_r << endl;

    ZP neg_r = -r;
    cout << "-r: " << neg_r << endl;

    G1 g1_exp_neg_r = g1.exp(neg_r);
    cout << "g1^(-r): " << g1_exp_neg_r << endl;

    G1 product_g1 = g1_exp_r * g1_exp_neg_r;
    cout << "g1^r * g1^(-r): " << product_g1 << endl;

    G1 g1_identity = pairing.initG1();
    cout << "G1 identity: " << g1_identity << endl;

    bool test1 = (product_g1 == g1_identity);
    cout << "Result: " << (test1 ? "PASS ✓" : "FAIL ✗") << endl;
    if (!test1) {
        cout << "ERROR: Product equals g1? " << (product_g1 == g1 ? "YES - BUG!" : "NO") << endl;
    }

    // Test with GT elements
    cout << "\n[TEST 2] GT: A^r * A^(-r) = identity" << endl;
    G1 g1_test = pairing.randomG1(rng.get());
    G2 g2_test = pairing.randomG2(rng.get());
    GT A = pairing.pairing(g1_test, g2_test);
    ZP r2 = pairing.randomZP(rng.get());

    cout << "A: " << A << endl;
    cout << "r: " << r2 << endl;

    GT a_exp_r = A.exp(r2);
    cout << "A^r: " << a_exp_r << endl;

    ZP neg_r2 = -r2;
    cout << "-r: " << neg_r2 << endl;

    GT a_exp_neg_r = A.exp(neg_r2);
    cout << "A^(-r): " << a_exp_neg_r << endl;

    GT product_gt = a_exp_r * a_exp_neg_r;
    cout << "A^r * A^(-r): " << product_gt << endl;

    GT gt_identity = pairing.initGT();
    cout << "GT identity: " << gt_identity << endl;

    bool test2 = (product_gt == gt_identity);
    cout << "Result: " << (test2 ? "PASS ✓" : "FAIL ✗") << endl;
    if (!test2) {
        cout << "ERROR: Product equals A? " << (product_gt == A ? "YES - BUG!" : "NO") << endl;
    }

    // Test the exact Waters CP-ABE pattern
    cout << "\n[TEST 3] Waters pattern: g1a^share * hash^(-ri)" << endl;

    ZP a = pairing.randomZP(rng.get());
    ZP share = pairing.randomZP(rng.get());
    ZP ri = pairing.randomZP(rng.get());

    G1 g1a = g1.exp(a);
    G1 hash = pairing.randomG1(rng.get());

    cout << "g1a: " << g1a << endl;
    cout << "share: " << share << endl;
    cout << "hash: " << hash << endl;
    cout << "ri: " << ri << endl;

    G1 g1a_exp_share = g1a.exp(share);
    cout << "g1a^share: " << g1a_exp_share << endl;

    ZP neg_ri = -ri;
    cout << "-ri: " << neg_ri << endl;

    G1 hash_exp_neg_ri = hash.exp(neg_ri);
    cout << "hash^(-ri): " << hash_exp_neg_ri << endl;

    G1 ci = g1a_exp_share * hash_exp_neg_ri;
    cout << "Ci = g1a^share * hash^(-ri): " << ci << endl;

    // Now verify inverse: hash^ri should undo hash^(-ri)
    G1 hash_exp_ri = hash.exp(ri);
    cout << "hash^ri: " << hash_exp_ri << endl;

    G1 product_inv = hash_exp_ri * hash_exp_neg_ri;
    cout << "hash^ri * hash^(-ri): " << product_inv << endl;

    bool test3 = (product_inv == g1_identity);
    cout << "Result: " << (test3 ? "PASS ✓" : "FAIL ✗") << endl;
    if (!test3) {
        cout << "ERROR: Product equals hash? " << (product_inv == hash ? "YES - BUG!" : "NO") << endl;
    }

    // Summary
    cout << "\n=== Test Summary ===" << endl;
    int passed = test1 + test2 + test3;
    cout << "Passed: " << passed << "/3" << endl;

    if (passed < 3) {
        cout << "\n🔴 CRITICAL BUG CONFIRMED: Negative exponents with random ZP values are broken!" << endl;
        cout << "This explains why Waters CP-ABE decryption fails." << endl;
    } else {
        cout << "\n✓ All tests passed - negative exponents work correctly" << endl;
    }

    ShutdownOpenABE();
    return (passed == 3) ? 0 : 1;
}
