#include <iostream>
#include <openabe/openabe.h>

using namespace std;
using namespace oabe;

int main() {
    cout << "Testing CCA encrypt/decrypt with MCL 3.04" << endl;

    // Initialize OpenABE
    InitializeOpenABE();

    // Create CP-ABE CCA context
    OpenABECryptoContext cpabe("CP-ABE");

    // Generate params
    if (cpabe.generateParams() != OpenABE_NOERROR) {
        cerr << "Failed to generate params" << endl;
        return 1;
    }

    // Generate a key for attributes
    if (cpabe.keygen("|one|two|three", "key1") != OpenABE_NOERROR) {
        cerr << "Failed to generate key" << endl;
        return 1;
    }

    // Encrypt
    string plaintext = "Hello MCL 3.04!";
    string ciphertext;

    cout << "Original plaintext: " << plaintext << endl;

    if (cpabe.encrypt("one and two", plaintext, ciphertext) != OpenABE_NOERROR) {
        cerr << "Encryption failed" << endl;
        return 1;
    }

    cout << "Encryption successful" << endl;

    // Decrypt
    string recovered;
    if (cpabe.decrypt("key1", ciphertext, recovered) != OpenABE_NOERROR) {
        cerr << "Decryption failed" << endl;
        return 1;
    }

    cout << "Recovered plaintext: " << recovered << endl;

    if (plaintext == recovered) {
        cout << "SUCCESS: Plaintext matches!" << endl;
    } else {
        cout << "FAILURE: Plaintexts don't match!" << endl;
        return 1;
    }

    ShutdownOpenABE();
    return 0;
}
