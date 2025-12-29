// Test MCL pairing bilinearity properties
// Verifies: e(A^x, B) = e(A, B)^x and other bilinearity properties

#include <iostream>
#include <openabe/openabe.h>

using namespace oabe;
using namespace std;

int main() {
    // Initialize OpenABE
    InitializeOpenABE();

    cout << "=== Testing MCL Pairing Bilinearity ===" << endl;

    // Create pairing context
    unique_ptr<OpenABERNG> rng(new OpenABERNG);
    OpenABEPairing pairing("BN_P254");

    // Test 1: e(A^x, B) = e(A, B)^x
    cout << "\n[TEST 1] e(A^x, B) = e(A, B)^x" << endl;
    G1 g1 = pairing.randomG1(rng.get());
    G2 g2 = pairing.randomG2(rng.get());
    ZP x = pairing.randomZP(rng.get());

    cout << "g1: " << g1 << endl;
    cout << "g2: " << g2 << endl;
    cout << "x: " << x << endl;

    G1 g1_exp_x = g1.exp(x);
    cout << "g1^x: " << g1_exp_x << endl;

    GT left = pairing.pairing(g1_exp_x, g2);
    cout << "e(g1^x, g2): " << left << endl;

    GT eg1g2 = pairing.pairing(g1, g2);
    cout << "e(g1, g2): " << eg1g2 << endl;

    GT right = eg1g2.exp(x);
    cout << "e(g1, g2)^x: " << right << endl;

    bool test1_pass = (left == right);
    cout << "Result: " << (test1_pass ? "PASS ✓" : "FAIL ✗") << endl;

    // Test 2: e(A, B^y) = e(A, B)^y
    cout << "\n[TEST 2] e(A, B^y) = e(A, B)^y" << endl;
    ZP y = pairing.randomZP(rng.get());
    cout << "y: " << y << endl;

    G2 g2_exp_y = g2.exp(y);
    cout << "g2^y: " << g2_exp_y << endl;

    GT left2 = pairing.pairing(g1, g2_exp_y);
    cout << "e(g1, g2^y): " << left2 << endl;

    GT right2 = eg1g2.exp(y);
    cout << "e(g1, g2)^y: " << right2 << endl;

    bool test2_pass = (left2 == right2);
    cout << "Result: " << (test2_pass ? "PASS ✓" : "FAIL ✗") << endl;

    // Test 3: e(A^x, B^y) = e(A, B)^(x*y)
    cout << "\n[TEST 3] e(A^x, B^y) = e(A, B)^(x*y)" << endl;
    GT left3 = pairing.pairing(g1_exp_x, g2_exp_y);
    cout << "e(g1^x, g2^y): " << left3 << endl;

    ZP xy = x * y;
    cout << "x*y: " << xy << endl;

    GT right3 = eg1g2.exp(xy);
    cout << "e(g1, g2)^(x*y): " << right3 << endl;

    bool test3_pass = (left3 == right3);
    cout << "Result: " << (test3_pass ? "PASS ✓" : "FAIL ✗") << endl;

    // Test 4: GT division/multiplication
    cout << "\n[TEST 4] GT division: A / A = identity" << endl;
    GT gt1 = pairing.pairing(g1, g2);
    cout << "GT element: " << gt1 << endl;

    GT quotient = gt1 / gt1;
    cout << "GT / GT: " << quotient << endl;

    GT identity = pairing.initGT();
    cout << "GT identity: " << identity << endl;

    bool test4_pass = (quotient == identity);
    cout << "Result: " << (test4_pass ? "PASS ✓" : "FAIL ✗") << endl;

    // Test 5: GT multiplication/division inverse
    cout << "\n[TEST 5] (A * B) / B = A" << endl;
    G1 g1_temp = pairing.randomG1(rng.get());
    G2 g2_temp = pairing.randomG2(rng.get());
    GT gt2 = pairing.pairing(g1_temp, g2_temp);
    cout << "A: " << gt1 << endl;
    cout << "B: " << gt2 << endl;

    GT product = gt1 * gt2;
    cout << "A * B: " << product << endl;

    GT quotient2 = product / gt2;
    cout << "(A * B) / B: " << quotient2 << endl;

    bool test5_pass = (quotient2 == gt1);
    cout << "Result: " << (test5_pass ? "PASS ✓" : "FAIL ✗") << endl;

    // Test 6: Exponentiation with negative values
    cout << "\n[TEST 6] A^x * A^(-x) = identity" << endl;
    GT gt_exp_x = gt1.exp(x);
    cout << "A^x: " << gt_exp_x << endl;

    ZP neg_x = -x;
    cout << "-x: " << neg_x << endl;

    GT gt_exp_neg_x = gt1.exp(neg_x);
    cout << "A^(-x): " << gt_exp_neg_x << endl;

    GT product2 = gt_exp_x * gt_exp_neg_x;
    cout << "A^x * A^(-x): " << product2 << endl;

    bool test6_pass = (product2 == identity);
    cout << "Result: " << (test6_pass ? "PASS ✓" : "FAIL ✗") << endl;

    // Summary
    cout << "\n=== Test Summary ===" << endl;
    int passed = test1_pass + test2_pass + test3_pass + test4_pass + test5_pass + test6_pass;
    cout << "Passed: " << passed << "/6" << endl;

    if (passed == 6) {
        cout << "✓ All pairing bilinearity tests PASSED" << endl;
    } else {
        cout << "✗ Some tests FAILED - MCL pairing has issues!" << endl;
    }

    ShutdownOpenABE();
    return (passed == 6) ? 0 : 1;
}
