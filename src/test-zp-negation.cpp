// Test ZP negation to verify r + (-r) = 0
#include <iostream>
#include <openabe/openabe.h>

extern "C" {
#include <mcl/bn.h>
}

using namespace oabe;
using namespace std;

void print_fr_dec(const char* label, const mclBnFr* fr) {
    char buf[256];
    mclBnFr_getStr(buf, sizeof(buf), fr, 10);
    cout << label << ": " << buf << endl;
}

int main() {
    InitializeOpenABE();

    unique_ptr<OpenABERNG> rng(new OpenABERNG);
    OpenABEPairing pairing("BN_P254");

    cout << "=== Testing ZP Negation ===" << endl;

    // Get the curve order
    char order_str[256];
    mclBn_getCurveOrder(order_str, sizeof(order_str));
    cout << "\nCurve Order: " << order_str << endl;

    // Create a test scalar
    ZP r;
    r.setOrder(pairing.order);
    zml_bignum_setuint(r.m_ZP, 12345);  // Simple test value

    cout << "\nTest with r = 12345:" << endl;
    print_fr_dec("r", r.m_ZP);

    // Negate using our operator
    ZP neg_r = -r;
    print_fr_dec("-r", neg_r.m_ZP);

    // Add them
    ZP sum = r + neg_r;
    print_fr_dec("r + (-r)", sum.m_ZP);

    // Check if sum is zero
    bool is_zero = zml_bignum_is_zero(sum.m_ZP);
    cout << "r + (-r) == 0? " << (is_zero ? "YES ✓" : "NO ✗") << endl;

    // Now test with MCL's negation directly
    cout << "\n--- Direct MCL Negation Test ---" << endl;
    mclBnFr r_mcl, neg_r_mcl, sum_mcl;

    mclBnFr_setInt(&r_mcl, 12345);
    print_fr_dec("r (MCL)", &r_mcl);

    mclBnFr_neg(&neg_r_mcl, &r_mcl);
    print_fr_dec("-r (MCL)", &neg_r_mcl);

    mclBnFr_add(&sum_mcl, &r_mcl, &neg_r_mcl);
    print_fr_dec("r + (-r) (MCL)", &sum_mcl);

    cout << "MCL: r + (-r) == 0? " << (mclBnFr_isZero(&sum_mcl) ? "YES ✓" : "NO ✗") << endl;

    // Now test with a larger value (the problematic one from earlier)
    cout << "\n=== Testing with Large Value ===" << endl;

    ZP r2;
    r2.setOrder(pairing.order);
    zml_bignum_fromHex(r2.m_ZP, "3711a528ce24116d7f4264a80c78770e2cbefe429e75ff12fa923ce9c068774", 63);

    print_fr_dec("r2", r2.m_ZP);

    ZP neg_r2 = -r2;
    print_fr_dec("-r2", neg_r2.m_ZP);

    ZP sum2 = r2 + neg_r2;
    print_fr_dec("r2 + (-r2)", sum2.m_ZP);

    bool is_zero2 = zml_bignum_is_zero(sum2.m_ZP);
    cout << "r2 + (-r2) == 0? " << (is_zero2 ? "YES ✓" : "NO ✗") << endl;

    // Verify the identity: order - r should equal -r
    cout << "\n--- Verifying order - r == -r ---" << endl;
    ZP order_zp;
    order_zp.setOrder(pairing.order);
    zml_bignum_copy(order_zp.m_ZP, pairing.order);

    print_fr_dec("order", order_zp.m_ZP);
    print_fr_dec("r2", r2.m_ZP);

    // Compute order - r2 using subtraction
    bignum_t diff;
    zml_bignum_init(&diff);
    zml_bignum_sub_order(diff, order_zp.m_ZP, r2.m_ZP, pairing.order);
    print_fr_dec("order - r2", diff);
    print_fr_dec("-r2 (from operator-)", neg_r2.m_ZP);

    cout << "order - r2 == -r2? " << (zml_bignum_cmp(diff, neg_r2.m_ZP) == BN_CMP_EQ ? "YES ✓" : "NO ✗") << endl;

    zml_bignum_free(diff);
    ShutdownOpenABE();
    return 0;
}
