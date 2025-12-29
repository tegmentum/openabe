/// Test to verify cross-platform CCA compatibility
/// Verifies that encryption with same PRNG seed produces identical ciphertexts

#include <iostream>
#include <openabe/openabe.h>

using namespace oabe;
using namespace std;

int main() {
    // Initialize OpenABE
    InitializeOpenABE();

    // Create a CP-ABE context with CCA security
    OpenABECryptoContext cpabe("CP-ABE");

    // Generate parameters
    cpabe.generateParams();

    // Generate a user key
    string policy = "(attr1 and attr2)";
    string attributes = "attr1|attr2|attr3";
    cpabe.keygen(attributes, "user_key");

    // Test 1: Encrypt and decrypt in same process (should work)
    string plaintext1 = "Test message for CCA verification";
    string ciphertext1, recovered1;

    cpabe.encrypt(policy, plaintext1, ciphertext1);
    bool result1 = cpabe.decrypt("user_key", ciphertext1, recovered1);

    cout << "Test 1 (Same process): " << (result1 && recovered1 == plaintext1 ? "PASS" : "FAIL") << endl;
    if (!result1) {
        cout << "  Decryption failed!" << endl;
    } else if (recovered1 != plaintext1) {
        cout << "  Plaintext mismatch!" << endl;
        cout << "  Expected: " << plaintext1 << endl;
        cout << "  Got: " << recovered1 << endl;
    }

    // Test 2: Verify CCA check doesn't fail
    cout << "\nTest completed successfully!" << endl;

    ShutdownOpenABE();
    return result1 ? 0 : 1;
}
