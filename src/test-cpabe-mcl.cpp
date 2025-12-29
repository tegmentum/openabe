#include <openabe/openabe.h>
#include <iostream>

using namespace oabe;

int main() {
    // Initialize OpenABE
    InitializeOpenABE();

    std::cout << "Testing CP-ABE with MCL backend" << std::endl;

    // Create a CP-ABE context
    OpenABECryptoContext cpabe("CP-ABE");

    // Generate master keys
    cpabe.generateParams();

    // Generate user key with attributes "one" and "two"
    cpabe.keygen("one|two", "user_key");

    // Create plaintext
    std::string plaintext = "Hello World!";
    std::string ciphertext;

    // Encrypt with policy "one and two"
    cpabe.encrypt("one and two", plaintext, ciphertext);

    std::cout << "Encryption successful" << std::endl;
    std::cout << "Ciphertext length: " << ciphertext.length() << std::endl;

    // Decrypt
    std::string recovered;
    cpabe.decrypt("user_key", ciphertext, recovered);

    std::cout << "Decryption successful" << std::endl;
    std::cout << "Original: " << plaintext << std::endl;
    std::cout << "Recovered: " << recovered << std::endl;

    if (plaintext == recovered) {
        std::cout << "SUCCESS: Decryption matches original!" << std::endl;
        return 0;
    } else {
        std::cout << "FAILURE: Decryption doesn't match!" << std::endl;
        return 1;
    }
}
