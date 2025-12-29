// Test basic MCL operations to isolate the bug
#include <iostream>
#include <openabe/openabe.h>

using namespace oabe;
using namespace std;

int main() {
    InitializeOpenABE();

    unique_ptr<OpenABERNG> rng(new OpenABERNG);
    OpenABEPairing pairing("BN_P254");

    cout << "=== Testing Basic MCL Operations ===" << endl;

    // Test 1: Check if g + g = 2g (point doubling)
    cout << "\n[TEST 1] Point Addition: g + g = 2g" << endl;
    G1 g = pairing.randomG1(rng.get());
    G1 g_plus_g = g * g;  // In code, * means addition

    ZP two(2);
    two.setOrder(pairing.order);
    G1 two_g = g.exp(two);

    cout << "g: " << g << endl;
    cout << "g + g: " << g_plus_g << endl;
    cout << "2*g: " << two_g << endl;
    cout << "g + g == 2*g? " << (g_plus_g == two_g ? "YES ✓" : "NO ✗") << endl;

    // Test 2: Check if g - g = identity
    cout << "\n[TEST 2] Point Subtraction: g - g = identity" << endl;
    G1 neg_g = -g;
    G1 g_minus_g = g * neg_g;
    G1 identity = pairing.initG1();

    cout << "g: " << g << endl;
    cout << "-g: " << neg_g << endl;
    cout << "g + (-g): " << g_minus_g << endl;
    cout << "identity: " << identity << endl;
    cout << "g - g == identity? " << (g_minus_g == identity ? "YES ✓" : "NO ✗") << endl;

    // Test 3: Check if r*g + (-r)*g = 0*g
    cout << "\n[TEST 3] Scalar Multiplication: r*g + (-r)*g = 0" << endl;
    ZP r = pairing.randomZP(rng.get());
    ZP neg_r = -r;
    ZP zero = r + neg_r;

    cout << "r: " << r << endl;
    cout << "-r: " << neg_r << endl;
    cout << "r + (-r): " << zero << endl;

    G1 rg = g.exp(r);
    G1 neg_rg = g.exp(neg_r);
    G1 sum = rg * neg_rg;
    G1 zero_g = g.exp(zero);

    cout << "r*g: " << rg << endl;
    cout << "(-r)*g: " << neg_rg << endl;
    cout << "r*g + (-r)*g: " << sum << endl;
    cout << "0*g (should be identity): " << zero_g << endl;
    cout << "r*g + (-r)*g == 0*g? " << (sum == zero_g ? "YES ✓" : "NO ✗") << endl;
    cout << "r*g + (-r)*g == identity? " << (sum == identity ? "YES ✓" : "NO ✗") << endl;

    ShutdownOpenABE();
    return 0;
}
