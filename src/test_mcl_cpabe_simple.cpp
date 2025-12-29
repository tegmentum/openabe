/// Simple CP-ABE test for MCL backend (no gtest dependency)
#include <iostream>
#include <string>
#include <openabe/openabe.h>

using namespace oabe;
using namespace std;

int main(int argc, char **argv) {
    InitializeOpenABE();

    cout << "[TEST] Testing CP-ABE with MCL backend" << endl;

    try {
        // Create CP-ABE context
        unique_ptr<OpenABECryptoContext> cpabe = OpenABE_createContextABESchemeCPWaters();
        if (!cpabe) {
            cerr << "[ERROR] Failed to create CP-ABE context" << endl;
            return 1;
        }
        cout << "[OK] Created CP-ABE context" << endl;

        // Generate master keys
        string mpk = "", msk = "";
        cpabe->generateParams(mpk, msk);
        if (mpk.empty() || msk.empty()) {
            cerr << "[ERROR] Failed to generate master keys" << endl;
            return 1;
        }
        cout << "[OK] Generated master public key (" << mpk.size() << " bytes)" << endl;
        cout << "[OK] Generated master secret key (" << msk.size() << " bytes)" << endl;

        // Generate user key with attributes
        string keyBlob = "";
        string attributes = "ONE|TWO|THREE";
        cpabe->keygen(mpk, msk, attributes, "alice", keyBlob);
        if (keyBlob.empty()) {
            cerr << "[ERROR] Failed to generate user key" << endl;
            return 1;
        }
        cout << "[OK] Generated user key for attributes: " << attributes << " (" << keyBlob.size() << " bytes)" << endl;

        // Encrypt with policy
        string plaintext = "This is a secret message for testing MCL backend!";
        string policy = "((ONE and TWO) or THREE)";
        string ciphertext = "";

        cpabe->encrypt(mpk, policy, plaintext, ciphertext);
        if (ciphertext.empty()) {
            cerr << "[ERROR] Failed to encrypt" << endl;
            return 1;
        }
        cout << "[OK] Encrypted with policy: " << policy << " (" << ciphertext.size() << " bytes)" << endl;

        // Decrypt
        string recoveredPlaintext = "";
        bool result = cpabe->decrypt(mpk, keyBlob, ciphertext, recoveredPlaintext);
        if (!result) {
            cerr << "[ERROR] Decryption failed" << endl;
            return 1;
        }
        cout << "[OK] Decrypted successfully" << endl;

        // Verify plaintext matches
        if (recoveredPlaintext != plaintext) {
            cerr << "[ERROR] Plaintext mismatch!" << endl;
            cerr << "  Expected: " << plaintext << endl;
            cerr << "  Got:      " << recoveredPlaintext << endl;
            return 1;
        }
        cout << "[OK] Plaintext matches!" << endl;
        cout << "  Original:  " << plaintext << endl;
        cout << "  Recovered: " << recoveredPlaintext << endl;

        // Test with key that shouldn't work
        cout << "\n[TEST] Testing with invalid attributes (should fail)" << endl;
        string badKeyBlob = "";
        string badAttributes = "FOUR|FIVE";
        cpabe->keygen(mpk, msk, badAttributes, "bob", badKeyBlob);
        cout << "[OK] Generated key with invalid attributes: " << badAttributes << endl;

        string badDecrypt = "";
        bool badResult = cpabe->decrypt(mpk, badKeyBlob, ciphertext, badDecrypt);
        if (badResult) {
            cerr << "[ERROR] Decryption should have failed but succeeded!" << endl;
            return 1;
        }
        cout << "[OK] Decryption correctly failed with invalid attributes" << endl;

        // Test multiple encrypt/decrypt cycles
        cout << "\n[TEST] Testing multiple encrypt/decrypt cycles" << endl;
        for (int i = 0; i < 3; i++) {
            string testPlaintext = "Test message " + to_string(i);
            string testCiphertext = "";
            string testRecovered = "";

            cpabe->encrypt(mpk, policy, testPlaintext, testCiphertext);
            cpabe->decrypt(mpk, keyBlob, testCiphertext, testRecovered);

            if (testRecovered != testPlaintext) {
                cerr << "[ERROR] Cycle " << i << " failed: plaintext mismatch" << endl;
                return 1;
            }
            cout << "[OK] Cycle " << i << " passed" << endl;
        }

        cout << "\n[SUCCESS] All tests passed! MCL backend is working correctly." << endl;

    } catch (const exception& e) {
        cerr << "[EXCEPTION] " << e.what() << endl;
        ShutdownOpenABE();
        return 1;
    }

    ShutdownOpenABE();
    return 0;
}
