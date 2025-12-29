/**
 * Test RABE pairing bilinearity
 */
#include <iostream>
#include <openabe/openabe.h>

using namespace std;
using namespace oabe;

int main() {
    cout << "=== RABE Pairing Bilinearity Test ===" << endl;

    InitializeOpenABE();

    // Get a pairing context and an RNG
    unique_ptr<OpenABEPairing> pairing(new OpenABEPairing("BLS12_P381"));
    unique_ptr<OpenABERNG> rng(new OpenABECTR_DRBG);

    // Get the group order
    ZP order = pairing->initZP();
    order = pairing->getOrder();
    cout << "Group order: " << order << endl;

    // Test 1: e(g1, g2)^a = e(g1^a, g2)
    cout << "\n--- Test 1: e(g1, g2)^a == e(g1^a, g2) ---" << endl;

    ZP a = pairing->initZP();
    a.setRandom(rng.get());
    cout << "Random scalar a = " << a << endl;

    // g1 = generator of G1
    G1 g1 = pairing->initG1();
    g1.setRandom(rng.get());
    cout << "Random G1 point g1" << endl;

    // g2 = generator of G2
    G2 g2 = pairing->initG2();
    g2.setRandom(rng.get());
    cout << "Random G2 point g2" << endl;

    // Compute e(g1, g2)
    GT e_g1_g2 = pairing->pairing(g1, g2);
    cout << "Computed e(g1, g2)" << endl;

    // Compute e(g1, g2)^a
    GT lhs = e_g1_g2.exp(a);
    cout << "Computed e(g1, g2)^a" << endl;

    // Compute g1^a
    G1 g1_a = g1.exp(a);
    cout << "Computed g1^a" << endl;

    // Compute e(g1^a, g2)
    GT rhs = pairing->pairing(g1_a, g2);
    cout << "Computed e(g1^a, g2)" << endl;

    // Compare
    cout << "LHS (e(g1,g2)^a) first bytes: ";
    OpenABEByteString lhs_bytes;
    lhs.serialize(lhs_bytes);
    for (int i = 0; i < 16 && i < (int)lhs_bytes.size(); i++) {
        printf("%02x", lhs_bytes[i]);
    }
    cout << "..." << endl;

    cout << "RHS (e(g1^a,g2)) first bytes: ";
    OpenABEByteString rhs_bytes;
    rhs.serialize(rhs_bytes);
    for (int i = 0; i < 16 && i < (int)rhs_bytes.size(); i++) {
        printf("%02x", rhs_bytes[i]);
    }
    cout << "..." << endl;

    if (lhs == rhs) {
        cout << "PASS: e(g1, g2)^a == e(g1^a, g2)" << endl;
    } else {
        cout << "FAIL: e(g1, g2)^a != e(g1^a, g2)" << endl;
        ShutdownOpenABE();
        return 1;
    }

    // Test 2: e(g1, g2^b) = e(g1, g2)^b
    cout << "\n--- Test 2: e(g1, g2^b) == e(g1, g2)^b ---" << endl;

    ZP b = pairing->initZP();
    b.setRandom(rng.get());
    cout << "Random scalar b = " << b << endl;

    // Compute e(g1, g2)^b
    GT lhs2 = e_g1_g2.exp(b);
    cout << "Computed e(g1, g2)^b" << endl;

    // Compute g2^b
    G2 g2_b = g2.exp(b);
    cout << "Computed g2^b" << endl;

    // Compute e(g1, g2^b)
    GT rhs2 = pairing->pairing(g1, g2_b);
    cout << "Computed e(g1, g2^b)" << endl;

    // Compare
    cout << "LHS (e(g1,g2)^b) first bytes: ";
    OpenABEByteString lhs2_bytes;
    lhs2.serialize(lhs2_bytes);
    for (int i = 0; i < 16 && i < (int)lhs2_bytes.size(); i++) {
        printf("%02x", lhs2_bytes[i]);
    }
    cout << "..." << endl;

    cout << "RHS (e(g1,g2^b)) first bytes: ";
    OpenABEByteString rhs2_bytes;
    rhs2.serialize(rhs2_bytes);
    for (int i = 0; i < 16 && i < (int)rhs2_bytes.size(); i++) {
        printf("%02x", rhs2_bytes[i]);
    }
    cout << "..." << endl;

    if (lhs2 == rhs2) {
        cout << "PASS: e(g1, g2)^b == e(g1, g2^b)" << endl;
    } else {
        cout << "FAIL: e(g1, g2)^b != e(g1, g2^b)" << endl;
        ShutdownOpenABE();
        return 1;
    }

    // Test 3: e(g1^a, g2^b) = e(g1, g2)^(a*b)
    cout << "\n--- Test 3: e(g1^a, g2^b) == e(g1, g2)^(a*b) ---" << endl;

    ZP ab = a * b;
    cout << "Computed a * b" << endl;

    GT lhs3 = e_g1_g2.exp(ab);
    cout << "Computed e(g1, g2)^(a*b)" << endl;

    GT rhs3 = pairing->pairing(g1_a, g2_b);
    cout << "Computed e(g1^a, g2^b)" << endl;

    // Compare
    cout << "LHS (e(g1,g2)^(a*b)) first bytes: ";
    OpenABEByteString lhs3_bytes;
    lhs3.serialize(lhs3_bytes);
    for (int i = 0; i < 16 && i < (int)lhs3_bytes.size(); i++) {
        printf("%02x", lhs3_bytes[i]);
    }
    cout << "..." << endl;

    cout << "RHS (e(g1^a,g2^b)) first bytes: ";
    OpenABEByteString rhs3_bytes;
    rhs3.serialize(rhs3_bytes);
    for (int i = 0; i < 16 && i < (int)rhs3_bytes.size(); i++) {
        printf("%02x", rhs3_bytes[i]);
    }
    cout << "..." << endl;

    if (lhs3 == rhs3) {
        cout << "PASS: e(g1^a, g2^b) == e(g1, g2)^(a*b)" << endl;
    } else {
        cout << "FAIL: e(g1^a, g2^b) != e(g1, g2)^(a*b)" << endl;
        ShutdownOpenABE();
        return 1;
    }

    // Test 4: Multi-pairing: e(g1, g2) * e(h1, h2) = e_multi([g1, h1], [g2, h2])
    cout << "\n--- Test 4: Multi-pairing consistency ---" << endl;

    G1 h1 = pairing->initG1();
    h1.setRandom(rng.get());

    G2 h2 = pairing->initG2();
    h2.setRandom(rng.get());

    // Compute e(g1, g2) * e(h1, h2) individually
    GT e_h1_h2 = pairing->pairing(h1, h2);
    GT lhs4 = e_g1_g2 * e_h1_h2;
    cout << "Computed e(g1, g2) * e(h1, h2)" << endl;

    // Compute using multi_pairing
    vector<G1> g1s = {g1, h1};
    vector<G2> g2s = {g2, h2};
    GT rhs4 = pairing->initGT();
    pairing->multi_pairing(rhs4, g1s, g2s);
    cout << "Computed multi_pairing([g1, h1], [g2, h2])" << endl;

    // Compare
    cout << "LHS (individual products) first bytes: ";
    OpenABEByteString lhs4_bytes;
    lhs4.serialize(lhs4_bytes);
    for (int i = 0; i < 16 && i < (int)lhs4_bytes.size(); i++) {
        printf("%02x", lhs4_bytes[i]);
    }
    cout << "..." << endl;

    cout << "RHS (multi_pairing) first bytes: ";
    OpenABEByteString rhs4_bytes;
    rhs4.serialize(rhs4_bytes);
    for (int i = 0; i < 16 && i < (int)rhs4_bytes.size(); i++) {
        printf("%02x", rhs4_bytes[i]);
    }
    cout << "..." << endl;

    if (lhs4 == rhs4) {
        cout << "PASS: Multi-pairing is consistent" << endl;
    } else {
        cout << "FAIL: Multi-pairing is inconsistent" << endl;
        ShutdownOpenABE();
        return 1;
    }

    cout << "\n=== All pairing tests passed! ===" << endl;
    ShutdownOpenABE();
    return 0;
}
