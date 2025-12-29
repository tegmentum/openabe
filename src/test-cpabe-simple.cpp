#include <iostream>
#include <openabe/openabe.h>

using namespace std;
using namespace oabe;

int main() {
    InitializeOpenABE();

    cout << "=== Testing MCL CP-ABE Waters ===" << endl << endl;

    // Create CP-ABE context
    unique_ptr<OpenABEContextSchemeCPA> cpabe = OpenABE_createContextABESchemeCPA(OpenABE_SCHEME_CP_WATERS);

    try {
        // Generate master keys
        cout << "Generating keys..." << endl;
        cpabe->generateParams();

        // Create a simple policy
        string policy = "attr1";
        string attributes = "attr1";

        // Generate a user key
        cout << "Generating user key for: " << attributes << endl;
        cpabe->keygen(attributes, "user_key");

        // Encrypt a message
        string plaintext = "Hello, World!";
        cout << "Encrypting message: " << plaintext << endl;

        OpenABECiphertext ciphertext;
        cpabe->encrypt(policy, plaintext, &ciphertext);

        // Decrypt
        cout << "Decrypting..." << endl;
        string decrypted;
        bool success = cpabe->decrypt("user_key", decrypted, &ciphertext);

        if (success && decrypted == plaintext) {
            cout << "✓ SUCCESS! Decryption worked correctly." << endl;
            cout << "Decrypted: " << decrypted << endl;
            return 0;
        } else {
            cout << "✗ FAILURE! Decryption failed or produced wrong result." << endl;
            if (success) {
                cout << "Expected: " << plaintext << endl;
                cout << "Got:      " << decrypted << endl;
            }
            return 1;
        }

    } catch (const exception& e) {
        cerr << "Error: " << e.what() << endl;
        return 1;
    }

    ShutdownOpenABE();
    return 0;
}
