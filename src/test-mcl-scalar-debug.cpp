// Deep dive into MCL scalar multiplication behavior
#include <iostream>
#include <openabe/openabe.h>

extern "C" {
#include <mcl/bn.h>
}

using namespace oabe;
using namespace std;

void print_fr_hex(const char* label, const mclBnFr* fr) {
    char buf[256];
    size_t len = mclBnFr_getStr(buf, sizeof(buf), fr, 16);
    cout << label << " (hex): 0x" << buf << endl;
}

void print_fr_dec(const char* label, const mclBnFr* fr) {
    char buf[256];
    size_t len = mclBnFr_getStr(buf, sizeof(buf), fr, 10);
    cout << label << " (dec): " << buf << endl;
}

int main() {
    InitializeOpenABE();

    unique_ptr<OpenABERNG> rng(new OpenABERNG);
    OpenABEPairing pairing("BN_P254");

    cout << "=== MCL Scalar Multiplication Debug ===" << endl;

    // Get the curve order
    char order_str[256];
    mclBn_getCurveOrder(order_str, sizeof(order_str));
    cout << "\nBN254 Curve Order: " << order_str << endl;

    // Create a test point
    G1 g = pairing.randomG1(rng.get());
    cout << "\nTest point g: " << g << endl;

    // Create a large scalar (> order/2)
    ZP r = pairing.randomZP(rng.get());

    // Make sure it's large by adding order/2 if needed
    bignum_t half_order;
    zml_bignum_init(&half_order);
    zml_bignum_copy(half_order, pairing.order);
    zml_bignum_rshift(half_order, half_order, 1);

    if (zml_bignum_cmp(r.m_ZP, half_order) == BN_CMP_LT) {
        // r is small, make it large
        zml_bignum_add(r.m_ZP, r.m_ZP, half_order, pairing.order);
    }

    cout << "\nScalar r: " << r << endl;
    print_fr_dec("r", r.m_ZP);
    print_fr_hex("r", r.m_ZP);

    // Compute -r
    ZP neg_r = -r;
    cout << "\nScalar -r: " << neg_r << endl;
    print_fr_dec("-r", neg_r.m_ZP);
    print_fr_hex("-r", neg_r.m_ZP);

    // Verify r + (-r) = 0
    ZP sum = r + neg_r;
    cout << "\nr + (-r): " << sum << endl;
    print_fr_dec("r + (-r)", sum.m_ZP);

    // Now test scalar multiplication
    cout << "\n--- Scalar Multiplication Test ---" << endl;

    G1 rg = g.exp(r);
    cout << "r*g: " << rg << endl;

    G1 neg_rg = g.exp(neg_r);
    cout << "(-r)*g: " << neg_rg << endl;

    G1 result = rg * neg_rg;
    cout << "r*g + (-r)*g: " << result << endl;

    G1 identity = pairing.initG1();
    cout << "identity: " << identity << endl;

    G1 zero_g = g.exp(sum);
    cout << "0*g: " << zero_g << endl;

    // Check if result equals identity
    bool equals_identity = (result == identity);
    bool equals_zero_g = (result == zero_g);
    bool equals_g = (result == g);

    cout << "\nresult == identity? " << (equals_identity ? "YES" : "NO") << endl;
    cout << "result == 0*g? " << (equals_zero_g ? "YES" : "NO") << endl;
    cout << "result == g? " << (equals_g ? "YES" : "NO") << endl;

    // Direct MCL API test
    cout << "\n--- Direct MCL API Test ---" << endl;

    mclBnG1 g_mcl, rg_mcl, neg_rg_mcl, result_mcl;
    memcpy(&g_mcl, g.m_G1, sizeof(mclBnG1));

    cout << "Calling mclBnG1_mul with r..." << endl;
    mclBnG1_mul(&rg_mcl, &g_mcl, r.m_ZP);

    cout << "Calling mclBnG1_mul with -r..." << endl;
    mclBnG1_mul(&neg_rg_mcl, &g_mcl, neg_r.m_ZP);

    cout << "Adding results..." << endl;
    mclBnG1_add(&result_mcl, &rg_mcl, &neg_rg_mcl);

    cout << "Is result zero (identity)? " << (mclBnG1_isZero(&result_mcl) ? "YES" : "NO") << endl;
    cout << "Is result equal to g? " << (mclBnG1_isEqual(&result_mcl, &g_mcl) ? "YES" : "NO") << endl;

    zml_bignum_free(half_order);
    ShutdownOpenABE();
    return 0;
}
