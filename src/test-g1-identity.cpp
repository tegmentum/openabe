#include <iostream>
#include <openabe/openabe.h>

using namespace oabe;
using namespace std;

int main() {
    // Initialize library
    InitializeOpenABE();

    // Create pairing
    OpenABECryptoContext cpabe("CP-ABE");

    try {
        // Generate params to initialize pairing
        cpabe.generateParams("BN254");

        // Get the pairing object
        OpenABEPairing *pairing = (OpenABEPairing*)cpabe.getPairing();

        // Test 1: Check if initG1() returns identity
        cout << "\n=== TEST 1: initG1() Identity Check ===" << endl;
        G1 identity = pairing->initG1();
        cout << "initG1() result: " << identity << endl;
        cout << "Is infinity (identity): " << identity.isInfinity() << endl;

        // Test 2: Verify identity property: identity * g1 == g1
        cout << "\n=== TEST 2: Identity Property ===" << endl;
        G1 g1_random = pairing->randomG1(nullptr);
        cout << "Random g1: " << g1_random << endl;

        G1 result1 = identity * g1_random;
        cout << "identity * g1: " << result1 << endl;
        cout << "identity * g1 == g1: " << (result1 == g1_random ? "YES" : "NO") << endl;

        G1 result2 = g1_random * identity;
        cout << "g1 * identity: " << result2 << endl;
        cout << "g1 * identity == g1: " << (result2 == g1_random ? "YES" : "NO") << endl;

        // Test 3: Multiple multiplications with identity
        cout << "\n=== TEST 3: Multiple Multiplications ===" << endl;
        G1 prod = pairing->initG1();
        cout << "Initial prod: " << prod << endl;

        G1 g1_a = pairing->randomG1(nullptr);
        G1 g1_b = pairing->randomG1(nullptr);

        cout << "g1_a: " << g1_a << endl;
        cout << "g1_b: " << g1_b << endl;

        prod *= g1_a;
        cout << "prod after *= g1_a: " << prod << endl;
        cout << "prod == g1_a: " << (prod == g1_a ? "YES" : "NO") << endl;

        prod *= g1_b;
        cout << "prod after *= g1_b: " << prod << endl;

        G1 expected = g1_a * g1_b;
        cout << "expected (g1_a * g1_b): " << expected << endl;
        cout << "prod == expected: " << (prod == expected ? "YES" : "NO") << endl;

        // Test 4: Compare with explicit identity
        cout << "\n=== TEST 4: Explicit Identity ===" << endl;
        G1 g1_gen = pairing->randomG1(nullptr);
        ZP zero;
        pairing->initZP(zero, 0);
        G1 explicit_identity = g1_gen.exp(zero);
        cout << "g1^0 (explicit identity): " << explicit_identity << endl;
        cout << "g1^0 isInfinity: " << explicit_identity.isInfinity() << endl;
        cout << "initG1() == g1^0: " << (identity == explicit_identity ? "YES" : "NO") << endl;

    } catch (const exception &e) {
        cout << "Error: " << e.what() << endl;
        ShutdownOpenABE();
        return 1;
    }

    ShutdownOpenABE();
    cout << "\n=== ALL TESTS COMPLETE ===" << endl;
    return 0;
}
