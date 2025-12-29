/**
 * Test G1/G2/GT exponentiation with negative exponents
 * g^(-x) should equal (g^x)^(-1)
 */

#include <iostream>
#include <string>
#include <openabe/openabe.h>

using namespace std;
using namespace oabe;

int main() {
    cout << "=== Negative Exponent Test ===" << endl;

    InitializeOpenABE();

    // Create pairing group
    OpenABEPairing pairing("BLS12_P381");
    OpenABERNG rng;

    // Create test elements
    G1 g1 = pairing.randomG1(&rng);
    G2 g2 = pairing.randomG2(&rng);
    GT gt = pairing.pairing(g1, g2);

    // Create scalar x and -x
    ZP x = pairing.randomZP(&rng);
    ZP neg_x = -x;

    cout << "Created random elements and scalar x" << endl;

    // Test G1: g1^(-x) should equal (g1^x)^(-1)
    cout << "\n=== G1 Test ===" << endl;
    G1 g1_negx = g1.exp(neg_x);        // g1^(-x)
    G1 g1_x = g1.exp(x);               // g1^x
    G1 g1_x_inv = -g1_x;               // (g1^x)^(-1) = -(g1^x)

    OpenABEByteString g1_negx_bytes, g1_x_inv_bytes;
    g1_negx.serialize(g1_negx_bytes);
    g1_x_inv.serialize(g1_x_inv_bytes);

    bool g1_test = (g1_negx_bytes == g1_x_inv_bytes);
    cout << "g1^(-x) == (g1^x)^(-1): " << (g1_test ? "TRUE" : "FALSE") << endl;

    if (!g1_test) {
        cout << "g1^(-x):     ";
        for (size_t i = 0; i < min(g1_negx_bytes.size(), (size_t)32); i++) {
            printf("%02x", g1_negx_bytes[i]);
        }
        cout << endl;

        cout << "(g1^x)^(-1): ";
        for (size_t i = 0; i < min(g1_x_inv_bytes.size(), (size_t)32); i++) {
            printf("%02x", g1_x_inv_bytes[i]);
        }
        cout << endl;
    }

    // Test G2: g2^(-x) should equal (g2^x)^(-1)
    cout << "\n=== G2 Test ===" << endl;
    G2 g2_negx = g2.exp(neg_x);
    G2 g2_x = g2.exp(x);
    G2 g2_x_inv = -g2_x;

    OpenABEByteString g2_negx_bytes, g2_x_inv_bytes;
    g2_negx.serialize(g2_negx_bytes);
    g2_x_inv.serialize(g2_x_inv_bytes);

    bool g2_test = (g2_negx_bytes == g2_x_inv_bytes);
    cout << "g2^(-x) == (g2^x)^(-1): " << (g2_test ? "TRUE" : "FALSE") << endl;

    if (!g2_test) {
        cout << "g2^(-x):     ";
        for (size_t i = 0; i < min(g2_negx_bytes.size(), (size_t)32); i++) {
            printf("%02x", g2_negx_bytes[i]);
        }
        cout << endl;

        cout << "(g2^x)^(-1): ";
        for (size_t i = 0; i < min(g2_x_inv_bytes.size(), (size_t)32); i++) {
            printf("%02x", g2_x_inv_bytes[i]);
        }
        cout << endl;
    }

    // Test GT: gt^(-x) should equal (gt^x)^(-1)
    cout << "\n=== GT Test ===" << endl;
    GT gt_negx = gt.exp(neg_x);
    GT gt_x = gt.exp(x);
    GT gt_x_inv = gt / gt_x / gt_x;  // gt / gt^x / gt^x should give gt^(-x+1)... wrong approach

    // Actually test: gt^x * gt^(-x) should equal identity
    GT product = gt.exp(x) * gt.exp(neg_x);
    bool gt_identity_test = product.isInfinity();
    cout << "gt^x * gt^(-x) == identity: " << (gt_identity_test ? "TRUE" : "FALSE") << endl;

    // Also test bilinearity: e(g1^(-x), g2) == e(g1, g2)^(-x)
    cout << "\n=== Pairing with negative exponent ===" << endl;
    GT left_pair = pairing.pairing(g1_negx, g2);
    GT right_pair = gt.exp(neg_x);

    OpenABEByteString left_bytes, right_bytes;
    left_pair.serialize(left_bytes);
    right_pair.serialize(right_bytes);

    bool pair_test = (left_bytes == right_bytes);
    cout << "e(g1^(-x), g2) == e(g1,g2)^(-x): " << (pair_test ? "TRUE" : "FALSE") << endl;

    if (!pair_test) {
        cout << "e(g1^(-x), g2):   ";
        for (size_t i = 0; i < min(left_bytes.size(), (size_t)32); i++) {
            printf("%02x", left_bytes[i]);
        }
        cout << endl;

        cout << "e(g1,g2)^(-x):    ";
        for (size_t i = 0; i < min(right_bytes.size(), (size_t)32); i++) {
            printf("%02x", right_bytes[i]);
        }
        cout << endl;
    }

    ShutdownOpenABE();

    bool allPassed = g1_test && g2_test && gt_identity_test && pair_test;
    cout << "\n=== ALL TESTS: " << (allPassed ? "PASSED" : "FAILED") << " ===" << endl;

    return allPassed ? 0 : 1;
}
