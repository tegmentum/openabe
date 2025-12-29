/**
 * Test multi-pairing: prod_{i} e(g1_i, g2_i) should equal e(g1_1, g2_1) * e(g1_2, g2_2) * ...
 */

#include <iostream>
#include <string>
#include <vector>
#include <openabe/openabe.h>

using namespace std;
using namespace oabe;

int main() {
    cout << "=== Multi-Pairing Test ===" << endl;

    InitializeOpenABE();

    // Create pairing group
    OpenABEPairing pairing("BLS12_P381");
    OpenABERNG rng;

    cout << "Pairing group created" << endl;

    // Create two pairs of random elements
    G1 g1_1 = pairing.randomG1(&rng);
    G2 g2_1 = pairing.randomG2(&rng);
    G1 g1_2 = pairing.randomG1(&rng);
    G2 g2_2 = pairing.randomG2(&rng);

    cout << "Created 2 pairs of random G1/G2 elements" << endl;

    // Compute using multi-pairing
    vector<G1> g1s = {g1_1, g1_2};
    vector<G2> g2s = {g2_1, g2_2};
    GT multiResult = pairing.initGT();
    pairing.multi_pairing(multiResult, g1s, g2s);

    cout << "Computed multi_pairing([g1_1, g1_2], [g2_1, g2_2])" << endl;

    // Compute using individual pairings and multiplication
    GT pair1 = pairing.pairing(g1_1, g2_1);
    GT pair2 = pairing.pairing(g1_2, g2_2);
    GT manualResult = pair1 * pair2;

    cout << "Computed e(g1_1, g2_1) * e(g1_2, g2_2)" << endl;

    // Serialize and compare
    OpenABEByteString multiBytes, manualBytes;
    multiResult.serialize(multiBytes);
    manualResult.serialize(manualBytes);

    bool isEqual = (multiBytes == manualBytes);

    cout << endl;
    cout << "=== RESULT ===" << endl;
    cout << "multi_pairing == manual product: " << (isEqual ? "TRUE (Good)" : "FALSE (BAD!)") << endl;

    if (!isEqual) {
        cout << endl;
        cout << "Multi-pairing result (first 64 bytes): ";
        for (size_t i = 0; i < min(multiBytes.size(), (size_t)64); i++) {
            printf("%02x", multiBytes[i]);
        }
        cout << endl;

        cout << "Manual product result (first 64 bytes): ";
        for (size_t i = 0; i < min(manualBytes.size(), (size_t)64); i++) {
            printf("%02x", manualBytes[i]);
        }
        cout << endl;
    }

    // Test with 3 pairs
    cout << endl << "=== Testing with 3 pairs ===" << endl;
    G1 g1_3 = pairing.randomG1(&rng);
    G2 g2_3 = pairing.randomG2(&rng);

    vector<G1> g1s_3 = {g1_1, g1_2, g1_3};
    vector<G2> g2s_3 = {g2_1, g2_2, g2_3};
    GT multiResult3 = pairing.initGT();
    pairing.multi_pairing(multiResult3, g1s_3, g2s_3);

    GT pair3 = pairing.pairing(g1_3, g2_3);
    GT manualResult3 = pair1 * pair2 * pair3;

    OpenABEByteString multi3Bytes, manual3Bytes;
    multiResult3.serialize(multi3Bytes);
    manualResult3.serialize(manual3Bytes);

    bool isEqual3 = (multi3Bytes == manual3Bytes);
    cout << "multi_pairing (3 pairs) == manual product: " << (isEqual3 ? "TRUE (Good)" : "FALSE (BAD!)") << endl;

    // Test with specific exponentiated values (closer to ABE use case)
    cout << endl << "=== Testing with exponentiated values (ABE-like) ===" << endl;

    ZP coeff1 = pairing.randomZP(&rng);
    ZP coeff2 = pairing.randomZP(&rng);

    // Simulate KX^coeff paired with D
    G1 kx1 = pairing.randomG1(&rng);
    G1 kx2 = pairing.randomG1(&rng);
    G2 d1 = pairing.randomG2(&rng);
    G2 d2 = pairing.randomG2(&rng);

    // Exponentiate G1 elements by coefficients
    G1 kx1_exp = kx1.exp(coeff1);
    G1 kx2_exp = kx2.exp(coeff2);

    cout << "Created KX^coeff pairs" << endl;

    // Multi-pairing with exponentiated values
    vector<G1> kxs_exp = {kx1_exp, kx2_exp};
    vector<G2> ds = {d1, d2};
    GT abeMulti = pairing.initGT();
    pairing.multi_pairing(abeMulti, kxs_exp, ds);

    // Manual computation
    GT abePair1 = pairing.pairing(kx1_exp, d1);
    GT abePair2 = pairing.pairing(kx2_exp, d2);
    GT abeManual = abePair1 * abePair2;

    OpenABEByteString abeMultiBytes, abeManualBytes;
    abeMulti.serialize(abeMultiBytes);
    abeManual.serialize(abeManualBytes);

    bool abeEqual = (abeMultiBytes == abeManualBytes);
    cout << "ABE-like multi_pairing == manual: " << (abeEqual ? "TRUE (Good)" : "FALSE (BAD!)") << endl;

    ShutdownOpenABE();

    bool allPassed = isEqual && isEqual3 && abeEqual;
    cout << endl << "=== ALL MULTI-PAIRING TESTS: " << (allPassed ? "PASSED" : "FAILED") << " ===" << endl;

    return allPassed ? 0 : 1;
}
