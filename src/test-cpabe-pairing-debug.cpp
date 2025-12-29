/// Test CP-ABE decryption with detailed pairing logging

#include <iostream>
#include <string>
#include <cassert>
#include <openabe/openabe.h>

using namespace std;
using namespace oabe;

int main() {
    // Initialize OpenABE
    InitializeOpenABE();

    cout << "Creating CP-ABE contexts..." << endl;

    // Create contexts
    unique_ptr<OpenABEContextSchemeCPA> cpabe = OpenABE_createContextABESchemeCPA(OpenABE_SCHEME_CP_WATERS);

    // Generate parameters
    cout << "Generating parameters..." << endl;
    if (cpabe->generateParams() != OpenABE_NOERROR) {
        cerr << "Failed to generate params" << endl;
        return 1;
    }

    // Generate a key for attributes
    string keyID = "key0";
    string attributes = "one|two|three";
    cout << "Generating key for attributes: " << attributes << endl;
    if (cpabe->keygen(attributes, keyID) != OpenABE_NOERROR) {
        cerr << "Failed to keygen" << endl;
        return 1;
    }

    // Encrypt with policy
    string policy = "((four or three) and (two or one))";
    string plaintext = "hello world";
    string ciphertext;

    cout << "Encrypting with policy: " << policy << endl;
    if (cpabe->encrypt(policy, plaintext, ciphertext) != OpenABE_NOERROR) {
        cerr << "Failed to encrypt" << endl;
        return 1;
    }

    cout << "Ciphertext length: " << ciphertext.size() << " bytes" << endl;

    // Decrypt
    OpenABEByteString recoveredBytes;
    OpenABECiphertext ct;
    ct.loadFromBytes(ciphertext);

    cout << "\n========== DECRYPTION WITH PAIRING DEBUG ==========\n" << endl;
    if (cpabe->decrypt("", keyID, &recoveredBytes, &ct) != OpenABE_NOERROR) {
        cerr << "Failed to decrypt" << endl;
        return 1;
    }

    cout << "\n========== DECRYPTION COMPLETE ==========\n" << endl;
    string recovered = recoveredBytes.toString();
    cout << "Recovered plaintext: " << recovered << endl;

    if (plaintext == recovered) {
        cout << "SUCCESS: Plaintext matches!" << endl;
    } else {
        cout << "FAILURE: Plaintext mismatch!" << endl;
        cout << "  Expected: " << plaintext << endl;
        cout << "  Got:      " << recovered << endl;
        return 1;
    }

    ShutdownOpenABE();
    return 0;
}
