// Test MCL's handling of zero scalar
#include <iostream>
#include <openabe/openabe.h>

extern "C" {
#include <mcl/bn.h>
}

using namespace oabe;
using namespace std;

int main() {
    InitializeOpenABE();

    unique_ptr<OpenABERNG> rng(new OpenABERNG);
    OpenABEPairing pairing("BN_P254");

    cout << "=== Testing MCL Zero Scalar ===" << endl;

    // Create a test point
    G1 g = pairing.randomG1(rng.get());
    cout << "\nTest point g: " << g << endl;

    // Create zero scalar
    ZP zero;
    zero.setOrder(pairing.order);
    zml_bignum_setzero(zero.m_ZP);

    cout << "Zero scalar: " << zero << endl;

    // Compute 0*g
    G1 zero_g = g.exp(zero);
    cout << "0*g: " << zero_g << endl;

    G1 identity = pairing.initG1();
    cout << "identity: " << identity << endl;

    cout << "0*g == identity? " << (zero_g == identity ? "YES ✓" : "NO ✗") << endl;

    // Direct MCL test
    cout << "\n--- Direct MCL Test ---" << endl;
    mclBnFr zero_fr;
    mclBnFr_clear(&zero_fr);  // Set to 0

    mclBnG1 g_mcl, result_mcl;
    memcpy(&g_mcl, g.m_G1, sizeof(mclBnG1));

    mclBnG1_mul(&result_mcl, &g_mcl, &zero_fr);

    cout << "mclBnG1_mul(g, 0) is zero? " << (mclBnG1_isZero(&result_mcl) ? "YES ✓" : "NO ✗") << endl;
    cout << "mclBnG1_mul(g, 0) equals g? " << (mclBnG1_isEqual(&result_mcl, &g_mcl) ? "YES" : "NO") << endl;

    // Test with 1
    cout << "\n=== Testing MCL Unit Scalar ===" << endl;
    ZP one;
    one.setOrder(pairing.order);
    zml_bignum_setuint(one.m_ZP, 1);

    cout << "One scalar: " << one << endl;

    G1 one_g = g.exp(one);
    cout << "1*g: " << one_g << endl;
    cout << "1*g == g? " << (one_g == g ? "YES ✓" : "NO ✗") << endl;

    // Test with 2
    cout << "\n=== Testing 1*g + 1*g vs 2*g ===" << endl;
    ZP two;
    two.setOrder(pairing.order);
    zml_bignum_setuint(two.m_ZP, 2);

    G1 one_g_2 = g.exp(one);
    G1 sum = one_g * one_g_2;  // 1*g + 1*g
    G1 two_g = g.exp(two);     // 2*g

    cout << "1*g + 1*g: " << sum << endl;
    cout << "2*g: " << two_g << endl;
    cout << "1*g + 1*g == 2*g? " << (sum == two_g ? "YES ✓" : "NO ✗") << endl;

    ShutdownOpenABE();
    return 0;
}
