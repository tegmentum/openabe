#include <iostream>
#include <openabe/openabe.h>

using namespace std;
using namespace oabe;

int main() {
    // Initialize OpenABE
    InitializeOpenABE();

    // Create a context for CP-ABE with MCL
    unique_ptr<OpenABEContextSchemeCPA> cpabe = OpenABE_createContextABESchemeCPA(OpenABE_SCHEME_CP_WATERS);

    try {
        // Setup
        cpabe->generateParams();

        // Create a simple policy
        string policy = "attr1 and attr2";
        string plaintext = "Hello MCL";

        // Generate key for attributes
        string attributes = "attr1|attr2";
        cpabe->keygen(attributes, "alice");

        // Encrypt
        string ciphertext;
        cpabe->encrypt(policy, plaintext, ciphertext);
        cout << "Encryption successful" << endl;

        // Decrypt - this should trigger multi-pairing with debug logs
        string decrypted;
        cpabe->decrypt("alice", ciphertext, decrypted);

        if (decrypted == plaintext) {
            cout << "SUCCESS: Decryption matched!" << endl;
        } else {
            cout << "FAILURE: Decryption did not match!" << endl;
            cout << "Expected: " << plaintext << endl;
            cout << "Got: " << decrypted << endl;
        }

    } catch (OpenABE_ERROR err) {
        cerr << "ERROR: " << OpenABE_errorToString(err) << endl;
        ShutdownOpenABE();
        return 1;
    }

    ShutdownOpenABE();
    return 0;
}
