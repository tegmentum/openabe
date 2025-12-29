///
/// \file   test_mcl_build.cpp
///
/// \brief  Simple test to verify MCL backend is working with BLS12-381
///

#include <iostream>
#include <openabe/openabe.h>

using namespace std;
using namespace oabe;

int main() {
    cout << "Testing OpenABE with MCL backend..." << endl;

    try {
        // Initialize OpenABE
        InitializeOpenABE();

        // Test BLS12-381
        cout << "\n=== Testing BLS12-381 curve ===" << endl;
        {
            OpenABEPairing pairing(OpenABE_convertCurveIDToString(OpenABE_BLS12_P381_ID));
            OpenABERNG rng;

            cout << "✓ Pairing initialized for BLS12-381" << endl;

            // Generate random elements
            G1 g1 = pairing.randomG1(&rng);
            G2 g2 = pairing.randomG2(&rng);
            cout << "✓ Random G1 and G2 elements generated" << endl;

            // Test pairing
            GT gt = pairing.pairing(g1, g2);
            cout << "✓ Pairing operation successful" << endl;

            // Test serialization
            OpenABEByteString g1_bytes, g2_bytes, gt_bytes;
            g1.serialize(g1_bytes);
            g2.serialize(g2_bytes);
            gt.serialize(gt_bytes);

            cout << "✓ Serialization successful" << endl;
            cout << "  G1 size: " << g1_bytes.size() << " bytes" << endl;
            cout << "  G2 size: " << g2_bytes.size() << " bytes" << endl;
            cout << "  GT size: " << gt_bytes.size() << " bytes" << endl;
        }

        // Test BN254
        cout << "\n=== Testing BN254 curve ===" << endl;
        {
            OpenABEPairing pairing(OpenABE_convertCurveIDToString(OpenABE_BN_P254_ID));
            OpenABERNG rng;

            cout << "✓ Pairing initialized for BN254" << endl;

            // Generate random elements
            G1 g1 = pairing.randomG1(&rng);
            G2 g2 = pairing.randomG2(&rng);
            cout << "✓ Random G1 and G2 elements generated" << endl;

            // Test pairing
            GT gt = pairing.pairing(g1, g2);
            cout << "✓ Pairing operation successful" << endl;
        }

        // Cleanup
        ShutdownOpenABE();

        cout << "\n✓ All tests passed! MCL backend is working correctly." << endl;
        return 0;

    } catch (const exception& e) {
        cerr << "✗ Error: " << e.what() << endl;
        return 1;
    }
}
