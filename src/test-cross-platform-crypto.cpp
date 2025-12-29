/// Deep investigation: Test if native and WASM builds produce identical
/// cryptographic operations when given the same PRNG seed

#include <iostream>
#include <iomanip>
#include <cstring>
#include <openabe/openabe.h>
#include <openabe/zsymcrypto.h>

using namespace oabe;
using namespace std;

void print_hex(const string& label, const uint8_t* data, size_t len) {
    cout << label << ": ";
    for (size_t i = 0; i < len && i < 64; i++) {
        cout << hex << setfill('0') << setw(2) << (int)data[i];
    }
    if (len > 64) cout << "...";
    cout << dec << " (" << len << " bytes)" << endl;
}

void print_hex_str(const string& label, const string& str) {
    print_hex(label, (const uint8_t*)str.data(), str.size());
}

int main() {
    cout << "=== Cross-Platform Cryptographic Operation Test ===" << endl;

    InitializeOpenABE();

    // Create CP-ABE context
    OpenABECryptoContext cpabe("CP-ABE");

    // Test 1: Deterministic key generation with fixed seed
    cout << "\n--- Test 1: Deterministic Setup ---" << endl;

    // Set a fixed PRNG seed for deterministic behavior
    unique_ptr<OpenABESymKeyAuthEnc> authenc(new OpenABESymKeyAuthEnc(DEFAULT_SYM_KEY_BYTES));
    string seed_key_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    string seed_key;
    for (size_t i = 0; i < seed_key_hex.length(); i += 2) {
        string byte = seed_key_hex.substr(i, 2);
        seed_key.push_back((char)strtol(byte.c_str(), nullptr, 16));
    }
    authenc->setKey(seed_key);

    // Generate parameters with deterministic PRNG
    cout << "Generating ABE parameters with fixed seed..." << endl;
    cpabe.generateParams();

    // Generate user key with same attributes
    string attributes = "attr1|attr2|attr3";
    cpabe.keygen(attributes, "test_user_key");

    // Test 2: Encrypt with deterministic PRNG
    cout << "\n--- Test 2: Deterministic Encryption ---" << endl;
    string policy = "(attr1 and attr2)";
    string plaintext = "Test message for determinism check";
    string ciphertext;

    // First encryption
    cout << "First encryption..." << endl;
    cpabe.encrypt(policy, plaintext, ciphertext);
    print_hex_str("Ciphertext 1", ciphertext);

    // Second encryption (should be different due to random elements)
    string ciphertext2;
    cout << "\nSecond encryption..." << endl;
    cpabe.encrypt(policy, plaintext, ciphertext2);
    print_hex_str("Ciphertext 2", ciphertext2);

    bool identical = (ciphertext == ciphertext2);
    cout << "\nCiphertexts identical: " << (identical ? "YES (UNEXPECTED!)" : "NO (expected - randomized)") << endl;

    // Test 3: Decrypt and check determinism
    cout << "\n--- Test 3: Decryption Test ---" << endl;
    string recovered1, recovered2;

    bool result1 = cpabe.decrypt("test_user_key", ciphertext, recovered1);
    bool result2 = cpabe.decrypt("test_user_key", ciphertext2, recovered2);

    cout << "Decryption 1: " << (result1 ? "SUCCESS" : "FAILED") << endl;
    cout << "Recovered 1: " << recovered1 << endl;
    cout << "Decryption 2: " << (result2 ? "SUCCESS" : "FAILED") << endl;
    cout << "Recovered 2: " << recovered2 << endl;

    bool match = (recovered1 == plaintext && recovered2 == plaintext);
    cout << "\nPlaintext recovery: " << (match ? "CORRECT" : "INCORRECT") << endl;

    // Test 4: Export and compare serialized elements
    cout << "\n--- Test 4: Check Serialized Key Elements ---" << endl;

    // Try to get MPK and compare
    string mpk_export;
    if (cpabe.exportPublicParams(mpk_export)) {
        print_hex_str("MPK serialized", mpk_export);
    }

    string msk_export;
    if (cpabe.exportSecretParams(msk_export)) {
        print_hex_str("MSK serialized", msk_export);
    }

    ShutdownOpenABE();

    cout << "\n=== Test Complete ===" << endl;
    cout << "Run this same test in WASM and compare outputs to find divergence." << endl;

    return 0;
}
