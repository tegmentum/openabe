/**
 * Simple test for RABE backend
 */
#include <iostream>
#include <openabe/openabe.h>

using namespace std;
using namespace oabe;

int main() {
    cout << "=== OpenABE with RABE Backend Test ===" << endl;

    try {
        // Initialize OpenABE
        cout << "1. Initializing OpenABE..." << endl;
        InitializeOpenABE();

        // Create CP-ABE context using BLS12-381 curve
        cout << "2. Creating CP-ABE context with BLS12-381..." << endl;
        OpenABECryptoContext cpabe("CP-ABE");

        // Generate parameters
        cout << "3. Generating master keys..." << endl;
        cpabe.generateParams();

        // Generate a key for attributes
        cout << "4. Generating key for attributes 'A|B|C'..." << endl;
        cpabe.keygen("|A|B|C|", "key1");

        // Encrypt a message
        cout << "5. Encrypting message with policy 'A and B'..." << endl;
        string plaintext = "Hello, RABE!";
        string ciphertext;
        cpabe.encrypt("(A and B)", plaintext, ciphertext);
        cout << "   Plaintext size: " << plaintext.size() << " bytes" << endl;
        cout << "   Ciphertext size: " << ciphertext.size() << " bytes" << endl;

        // Decrypt
        cout << "6. Decrypting..." << endl;
        string recovered;
        bool success = cpabe.decrypt("key1", ciphertext, recovered);

        if (success && recovered == plaintext) {
            cout << "   SUCCESS! Recovered: '" << recovered << "'" << endl;
        } else {
            cout << "   FAILED! Decryption unsuccessful." << endl;
            ShutdownOpenABE();
            return 1;
        }

        // Cleanup
        cout << "7. Cleanup..." << endl;
        ShutdownOpenABE();

        cout << "\n=== All tests passed! ===" << endl;
        return 0;

    } catch (exception& e) {
        cerr << "Exception: " << e.what() << endl;
        ShutdownOpenABE();
        return 1;
    }
}
