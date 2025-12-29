// Test GT identity element behavior
#include <iostream>
#include <openabe/openabe.h>

using namespace oabe;
using namespace std;

int main() {
    InitializeOpenABE();

    cout << "=== Testing GT Identity Element ===" << endl;

    unique_ptr<OpenABERNG> rng(new OpenABERNG);
    OpenABEPairing pairing("BN_P254");

    // Get GT identity
    GT identity = pairing.initGT();
    cout << "\n[IDENTITY] GT identity from initGT(): " << identity << endl;

    // Test: identity * A = A
    G1 g1 = pairing.randomG1(rng.get());
    G2 g2 = pairing.randomG2(rng.get());
    GT A = pairing.pairing(g1, g2);
    cout << "\n[TEST 1] identity * A = A" << endl;
    cout << "A: " << A << endl;

    GT result1 = identity * A;
    cout << "identity * A: " << result1 << endl;
    bool test1 = (result1 == A);
    cout << "Result: " << (test1 ? "PASS ✓" : "FAIL ✗") << endl;

    // Test: A / A = identity
    cout << "\n[TEST 2] A / A = identity" << endl;
    GT quotient = A / A;
    cout << "A / A: " << quotient << endl;
    cout << "Expected identity: " << identity << endl;
    bool test2 = (quotient == identity);
    cout << "Result: " << (test2 ? "PASS ✓" : "FAIL ✗") << endl;

    // Test: A^0 = identity
    cout << "\n[TEST 3] A^0 = identity" << endl;
    ZP zero = pairing.initZP();
    pairing.initZP(zero, 0);
    cout << "Zero: " << zero << endl;
    GT a_to_zero = A.exp(zero);
    cout << "A^0: " << a_to_zero << endl;
    cout << "Expected identity: " << identity << endl;
    bool test3 = (a_to_zero == identity);
    cout << "Result: " << (test3 ? "PASS ✓" : "FAIL ✗") << endl;

    // Test: A^1 * A^(-1) = identity
    cout << "\n[TEST 4] A^1 * A^(-1) = identity" << endl;
    ZP one = pairing.initZP();
    pairing.initZP(one, 1);
    cout << "One: " << one << endl;

    ZP neg_one = -one;
    cout << "Negative one: " << neg_one << endl;

    GT a_to_1 = A.exp(one);
    cout << "A^1: " << a_to_1 << endl;

    GT a_to_neg1 = A.exp(neg_one);
    cout << "A^(-1): " << a_to_neg1 << endl;

    GT product = a_to_1 * a_to_neg1;
    cout << "A^1 * A^(-1): " << product << endl;
    cout << "Expected identity: " << identity << endl;
    bool test4 = (product == identity);
    cout << "Result: " << (test4 ? "PASS ✓" : "FAIL ✗") << endl;

    // Test: Check if A^1 equals A
    cout << "\n[TEST 5] A^1 = A" << endl;
    bool test5 = (a_to_1 == A);
    cout << "Result: " << (test5 ? "PASS ✓" : "FAIL ✗") << endl;

    // Test: What is identity value?
    cout << "\n[ANALYSIS] Checking identity representation" << endl;
    cout << "Is A equal to identity? " << (A == identity ? "YES" : "NO") << endl;
    cout << "Is A^0 equal to A? " << (a_to_zero == A ? "YES" : "NO") << endl;
    cout << "Is A/A equal to A? " << (quotient == A ? "YES" : "NO") << endl;

    // Summary
    cout << "\n=== Test Summary ===" << endl;
    int passed = test1 + test2 + test3 + test4 + test5;
    cout << "Passed: " << passed << "/5" << endl;

    ShutdownOpenABE();
    return 0;
}
