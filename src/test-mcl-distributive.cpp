// Test if a*g + b*g = (a+b)*g holds in MCL
#include <iostream>
#include <openabe/openabe.h>

extern "C" {
#include <mcl/bn.h>
}

using namespace oabe;
using namespace std;

void print_g1(const char* label, const G1& g) {
    cout << label << ": " << g << endl;
}

void test_distributive(G1& g, const ZP& a, const ZP& b, const char* test_name) {
    cout << "\n=== " << test_name << " ===" << endl;
    cout << "a: " << a << endl;
    cout << "b: " << b << endl;

    // Compute a*g
    G1 ag = g.exp(a);
    cout << "a*g computed" << endl;

    // Compute b*g
    G1 bg = g.exp(b);
    cout << "b*g computed" << endl;

    // Compute a*g + b*g
    G1 ag_plus_bg = ag * bg;
    print_g1("a*g + b*g", ag_plus_bg);

    // Compute a + b
    ZP a_plus_b = a + b;
    cout << "a + b: " << a_plus_b << endl;

    // Compute (a+b)*g
    G1 ab_g = g.exp(a_plus_b);
    print_g1("(a+b)*g", ab_g);

    // Check if they're equal
    bool equal = (ag_plus_bg == ab_g);
    cout << "a*g + b*g == (a+b)*g? " << (equal ? "YES ✓" : "NO ✗ BUG!") << endl;

    if (!equal) {
        cout << "*** DISTRIBUTIVE PROPERTY VIOLATION ***" << endl;
    }
}

int main() {
    InitializeOpenABE();

    unique_ptr<OpenABERNG> rng(new OpenABERNG);
    OpenABEPairing pairing("BN_P254");

    G1 g = pairing.randomG1(rng.get());
    print_g1("\nBase point g", g);

    // Test 1: Simple values
    ZP a1, b1;
    a1.setOrder(pairing.order);
    b1.setOrder(pairing.order);
    zml_bignum_setuint(a1.m_ZP, 5);
    zml_bignum_setuint(b1.m_ZP, 7);
    test_distributive(g, a1, b1, "Test 1: a=5, b=7");

    // Test 2: The problematic case - r and -r
    cout << "\n\n=== CRITICAL TEST: r and -r ===" << endl;
    ZP r;
    r.setOrder(pairing.order);
    zml_bignum_fromHex(r.m_ZP, "3711a528ce24116d7f4264a80c78770e2cbefe429e75ff12fa923ce9c068774", 63);

    ZP neg_r = -r;

    test_distributive(g, r, neg_r, "Test 2: r and -r");

    // Test 3: Two random values
    ZP a3 = pairing.randomZP(rng.get());
    ZP b3 = pairing.randomZP(rng.get());
    test_distributive(g, a3, b3, "Test 3: Random a and b");

    // Test 4: The exact values from our failing test
    cout << "\n\n=== Reproducing Original Failure ===" << endl;
    ZP r_orig = pairing.randomZP(rng.get());

    // Make it large if needed
    bignum_t half_order;
    zml_bignum_init(&half_order);
    zml_bignum_copy(half_order, pairing.order);
    zml_bignum_rshift(half_order, half_order, 1);
    if (zml_bignum_cmp(r_orig.m_ZP, half_order) == BN_CMP_LT) {
        zml_bignum_add(r_orig.m_ZP, r_orig.m_ZP, half_order, pairing.order);
    }
    zml_bignum_free(half_order);

    ZP neg_r_orig = -r_orig;
    test_distributive(g, r_orig, neg_r_orig, "Test 4: Original failing case");

    ShutdownOpenABE();
    return 0;
}
