/**
 * Simple CP-ABE encryption/decryption test
 * Tests that RELIC with WASM-safe fixes works for CP-ABE operations
 */

#include <iostream>
#include <string>
#include <memory>
#include <openabe/openabe.h>

using namespace std;
using namespace oabe;

int main() {
    cout << "=== CP-ABE Encryption/Decryption Test ===" << endl;
    cout << "Testing RELIC 0.7.0 with WASM-safe fixes" << endl << endl;

    // Initialize OpenABE
    InitializeOpenABE();

    cout << "OpenABE Library Version: " << OpenABE_getLibraryVersion() << endl;

    try {
        // Create CP-ABE context
        cout << "\n1. Creating CP-ABE context..." << endl;
        unique_ptr<OpenABECryptoContext> cpabe = OpenABE_createContextABESchemeCPWaters();
        if (!cpabe) {
            cerr << "ERROR: Failed to create CP-ABE context" << endl;
            return 1;
        }
        cout << "   ✓ Context created" << endl;

        // Generate master keys
        cout << "\n2. Generating master public/secret keys..." << endl;
        cpabe->generateParams();
        cout << "   ✓ Master keys generated" << endl;

        // Define attributes and policy
        string attr_list = "student|engineer|faculty";
        string policy = "(student or faculty) and engineer";

        cout << "\n3. Generating user key with attributes: " << attr_list << endl;
        cpabe->keygen(attr_list, "alice_key");
        cout << "   ✓ User key generated" << endl;

        // Encrypt a message
        string plaintext = "Hello, CP-ABE with RELIC 0.7.0 WASM-safe fixes!";
        string ciphertext;

        cout << "\n4. Encrypting message with policy: " << policy << endl;
        cout << "   Plaintext: \"" << plaintext << "\"" << endl;

        if (cpabe->encrypt(policy, plaintext, ciphertext) != OpenABE_NOERROR) {
            cerr << "ERROR: Encryption failed!" << endl;
            cerr << "This likely indicates a G2 serialization problem." << endl;
            return 1;
        }
        cout << "   ✓ Encryption successful (ciphertext size: " << ciphertext.size() << " bytes)" << endl;

        // Decrypt the message
        string recovered_plaintext;

        cout << "\n5. Decrypting ciphertext with user key..." << endl;

        if (cpabe->decrypt("alice_key", ciphertext, recovered_plaintext) != OpenABE_NOERROR) {
            cerr << "ERROR: Decryption failed!" << endl;
            cerr << "This likely indicates a G2 deserialization problem." << endl;
            return 1;
        }
        cout << "   ✓ Decryption successful" << endl;

        // Verify plaintext matches
        cout << "\n6. Verifying recovered plaintext..." << endl;
        cout << "   Recovered: \"" << recovered_plaintext << "\"" << endl;

        if (plaintext == recovered_plaintext) {
            cout << "   ✓ PASS: Plaintext matches!" << endl;
        } else {
            cerr << "   ✗ FAIL: Plaintext does NOT match!" << endl;
            cerr << "   Expected: \"" << plaintext << "\"" << endl;
            cerr << "   Got:      \"" << recovered_plaintext << "\"" << endl;
            return 1;
        }

        // Test with non-matching attributes
        cout << "\n7. Testing decryption with non-matching key..." << endl;
        string bad_attr_list = "student|manager";  // missing "engineer"
        cpabe->keygen(bad_attr_list, "bob_key");

        string should_fail;
        OpenABE_ERROR result = cpabe->decrypt("bob_key", ciphertext, should_fail);

        if (result != OpenABE_NOERROR) {
            cout << "   ✓ PASS: Decryption correctly failed for non-matching attributes" << endl;
        } else {
            cerr << "   ✗ FAIL: Decryption should have failed but succeeded!" << endl;
            return 1;
        }

        cout << "\n=== All Tests PASSED ===" << endl;
        cout << "\n✅ RELIC 0.7.0 with WASM-safe fixes works correctly for CP-ABE!" << endl;
        cout << "   - G2 serialization: ✓" << endl;
        cout << "   - G2 deserialization: ✓" << endl;
        cout << "   - Legendre symbol computation: ✓" << endl;
        cout << "   - Fp2 square root: ✓" << endl;
        cout << "   - CP-ABE encryption: ✓" << endl;
        cout << "   - CP-ABE decryption: ✓" << endl;
        cout << "   - Access control: ✓" << endl;

    } catch (const exception& e) {
        cerr << "\nEXCEPTION: " << e.what() << endl;
        return 1;
    }

    // Cleanup
    ShutdownOpenABE();

    return 0;
}
