/// Test Encryption Determinism
/// Encrypts same message twice with same RNG seed to check if ciphertexts match

#include <stdio.h>
#include <string.h>
#include <iostream>
#include <openabe/openabe.h>

using namespace std;
using namespace oabe;

int main(int argc, char **argv) {
    cout << "========================================" << endl;
    cout << "  Encryption Determinism Test" << endl;
    cout << "========================================" << endl;
    cout << endl;

    InitializeOpenABE();

    // Create CP-ABE context
    unique_ptr<OpenABEContextSchemeCPA> cpabe(new OpenABEContextCPWaters);

    cout << "Generating parameters..." << endl;
    cpabe->generateParams("BN254", "mpk", "msk");

    // Create policy
    unique_ptr<OpenABEPolicy> policy(new OpenABEPolicy("one and two"));

    // Message to encrypt
    OpenABEByteString message;
    message.fromHex("0123456789ABCDEF");

    cout << "\n=== First Encryption ===" << endl;

    // Create RNG with fixed seed
    OpenABEByteString seed1;
    seed1.fillBuffer(0xAA, 32);
    unique_ptr<OpenABECTR_DRBG> rng1(new OpenABECTR_DRBG(seed1));

    OpenABEByteString nonce1;
    nonce1.fillBuffer(0xBB, 16);
    rng1->setSeed(nonce1);

    unique_ptr<OpenABECiphertext> ct1(new OpenABECiphertext);
    cpabe->encrypt(rng1.get(), "mpk", policy.get(), &message, ct1.get());

    cout << "First ciphertext created with " << ct1->getKeys().size() << " components" << endl;

    cout << "\n=== Second Encryption (Same Seed) ===" << endl;

    // Create IDENTICAL RNG
    OpenABEByteString seed2;
    seed2.fillBuffer(0xAA, 32);  // Same seed
    unique_ptr<OpenABECTR_DRBG> rng2(new OpenABECTR_DRBG(seed2));

    OpenABEByteString nonce2;
    nonce2.fillBuffer(0xBB, 16);  // Same nonce
    rng2->setSeed(nonce2);

    unique_ptr<OpenABECiphertext> ct2(new OpenABECiphertext);
    cpabe->encrypt(rng2.get(), "mpk", policy.get(), &message, ct2.get());

    cout << "Second ciphertext created with " << ct2->getKeys().size() << " components" << endl;

    cout << "\n=== Comparing Ciphertexts ===" << endl;

    vector<string> keys1 = ct1->getKeys();
    bool all_match = true;

    for (auto& key : keys1) {
        ZObject *obj1 = ct1->getComponent(key);
        ZObject *obj2 = ct2->getComponent(key);

        if (obj1 && obj2 && obj1->isEqual(obj2)) {
            cout << "  ✅ " << key << " matches" << endl;
        } else {
            cout << "  ❌ " << key << " DIFFERS" << endl;
            all_match = false;
        }
    }

    cout << "\n========================================" << endl;
    if (all_match) {
        cout << "✅ PASS: Encryption is DETERMINISTIC" << endl;
        cout << "Same seed → same ciphertext" << endl;
    } else {
        cout << "❌ FAIL: Encryption is NON-DETERMINISTIC" << endl;
        cout << "Same seed → different ciphertext" << endl;
        cout << "\nThis confirms Bug #2!" << endl;
    }
    cout << "========================================" << endl;

    ShutdownOpenABE();
    return all_match ? 0 : 1;
}
