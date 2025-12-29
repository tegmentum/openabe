/**
 * Minimal ABE test to verify basic encrypt/decrypt without CCA
 * This tests if the core ABE KEM works correctly
 */

#include <iostream>
#include <string>
#include <openabe/openabe.h>

using namespace std;
using namespace oabe;

int main() {
    cout << "=== Basic ABE KEM Test (No CCA) ===" << endl;

    InitializeOpenABE();

    // Create CP-ABE context directly (no CCA wrapper)
    unique_ptr<OpenABERNG> rng(new OpenABERNG);
    OpenABEContextCPWaters cpabe(std::move(rng));

    // Generate parameters
    cout << "Generating parameters..." << endl;
    OpenABE_ERROR result = cpabe.generateParams("BLS12_P381", "mpk", "msk");
    if (result != OpenABE_NOERROR) {
        cerr << "generateParams failed: " << OpenABE_errorToString(result) << endl;
        return 1;
    }

    // Generate key for attributes "A|B"
    cout << "Generating decryption key..." << endl;
    unique_ptr<OpenABEAttributeList> attrList = createAttributeList("A|B");
    result = cpabe.generateDecryptionKey(attrList.get(), "key1", "mpk", "msk", "", "");
    if (result != OpenABE_NOERROR) {
        cerr << "generateDecryptionKey failed: " << OpenABE_errorToString(result) << endl;
        return 1;
    }

    // Encrypt with policy "A and B"
    cout << "Encrypting with policy 'A and B'..." << endl;
    unique_ptr<OpenABEPolicy> policy = createPolicyTree("A and B");
    shared_ptr<OpenABESymKey> encKey(new OpenABESymKey);
    OpenABECiphertext ciphertext;

    result = cpabe.encryptKEM(nullptr, "mpk", policy.get(), 32, encKey, &ciphertext);
    if (result != OpenABE_NOERROR) {
        cerr << "encryptKEM failed: " << OpenABE_errorToString(result) << endl;
        return 1;
    }

    OpenABEByteString encKeyBytes = encKey->getKeyBytes();
    cout << "Encryption key (" << encKeyBytes.size() << " bytes): ";
    for (size_t i = 0; i < encKeyBytes.size() && i < 16; i++) {
        printf("%02x", encKeyBytes[i]);
    }
    cout << "..." << endl;

    // Decrypt
    cout << "Decrypting..." << endl;
    shared_ptr<OpenABESymKey> decKey(new OpenABESymKey);
    result = cpabe.decryptKEM("mpk", "key1", &ciphertext, 32, decKey);
    if (result != OpenABE_NOERROR) {
        cerr << "decryptKEM failed: " << OpenABE_errorToString(result) << endl;
        return 1;
    }

    OpenABEByteString decKeyBytes = decKey->getKeyBytes();
    cout << "Decryption key (" << decKeyBytes.size() << " bytes): ";
    for (size_t i = 0; i < decKeyBytes.size() && i < 16; i++) {
        printf("%02x", decKeyBytes[i]);
    }
    cout << "..." << endl;

    // Compare keys
    bool keysMatch = (encKeyBytes == decKeyBytes);
    cout << endl;
    if (keysMatch) {
        cout << "SUCCESS: Encryption and decryption keys MATCH!" << endl;
    } else {
        cout << "FAILURE: Keys DO NOT MATCH!" << endl;
        cout << "Full encryption key: ";
        for (size_t i = 0; i < encKeyBytes.size(); i++) {
            printf("%02x", encKeyBytes[i]);
        }
        cout << endl;
        cout << "Full decryption key: ";
        for (size_t i = 0; i < decKeyBytes.size(); i++) {
            printf("%02x", decKeyBytes[i]);
        }
        cout << endl;
    }

    ShutdownOpenABE();
    return keysMatch ? 0 : 1;
}
