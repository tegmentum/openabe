/// Test RNG Determinism
/// Tests whether the same RNG seed produces the same random values
/// This is critical for CCA security

#include <stdio.h>
#include <string.h>
#include <iostream>
#include <openabe/openabe.h>

using namespace std;
using namespace oabe;

void testRNGDeterminism() {
    cout << "=== Testing RNG Determinism ===" << endl;

    // Create two RNG instances with same seed
    OpenABEByteString seed1, seed2;
    seed1.fillBuffer(0xAA, 32);  // Fixed seed
    seed2.fillBuffer(0xAA, 32);  // Same fixed seed

    OpenABECTR_DRBG rng1(seed1);
    OpenABECTR_DRBG rng2(seed2);

    // Set same nonce
    OpenABEByteString nonce;
    nonce.fillBuffer(0xBB, 16);
    rng1.setSeed(nonce);
    rng2.setSeed(nonce);

    cout << "Created two RNGs with identical seeds and nonces" << endl;

    // Get random bytes from both
    OpenABEByteString bytes1, bytes2;
    rng1.getRandomBytes(&bytes1, 32);
    rng2.getRandomBytes(&bytes2, 32);

    cout << "RNG1 bytes: " << bytes1.toHex() << endl;
    cout << "RNG2 bytes: " << bytes2.toHex() << endl;

    if (bytes1 == bytes2) {
        cout << "✅ RNG is DETERMINISTIC - same seed produces same bytes" << endl;
    } else {
        cout << "❌ RNG is NON-DETERMINISTIC - same seed produces different bytes!" << endl;
    }
}

void testPairingRandomZP() {
    cout << "\n=== Testing Pairing randomZP Determinism ===" << endl;
    cout << "(Skipped - requires direct pairing access)" << endl;
}

void testSequentialRandomZP() {
    cout << "\n=== Testing Sequential randomZP Calls ===" << endl;
    cout << "(Skipped - requires direct pairing access)" << endl;
}

void testEncryptionDeterminism() {
    cout << "\n=== Testing Full Encryption Determinism ===" << endl;

    InitializeOpenABE();

    // Create CP-ABE context
    unique_ptr<OpenABEContextSchemeCPA> cpabe(new OpenABEContextCPWaters);

#ifdef BP_WITH_OPENSSL
    cout << "Using RELIC backend (BP_WITH_OPENSSL)" << endl;
#else
    cout << "Using MCL backend (BP_WITH_MCL)" << endl;
#endif

    // Generate params
    cpabe->generateParams("BN254", "mpk", "msk");

    // Create policy
    unique_ptr<OpenABEPolicy> policy(new OpenABEPolicy("one and two"));

    // Create two RNGs with same seed
    OpenABEByteString seed;
    seed.fillBuffer(0x11, 32);

    unique_ptr<OpenABECTR_DRBG> rng1(new OpenABECTR_DRBG(seed));
    unique_ptr<OpenABECTR_DRBG> rng2(new OpenABECTR_DRBG(seed));

    OpenABEByteString nonce;
    nonce.fillBuffer(0x22, 16);
    rng1->setSeed(nonce);
    rng2->setSeed(nonce);

    // Encrypt same message with both RNGs
    OpenABEByteString message;
    message.fromHex("0123456789ABCDEF");

    shared_ptr<OpenABESymKey> key1(new OpenABESymKey);
    shared_ptr<OpenABESymKey> key2(new OpenABESymKey);

    unique_ptr<OpenABECiphertext> ct1(new OpenABECiphertext);
    unique_ptr<OpenABECiphertext> ct2(new OpenABECiphertext);

    cpabe->encrypt(rng1.get(), "mpk", policy.get(), &message, ct1.get());
    cpabe->encrypt(rng2.get(), "mpk", policy.get(), &message, ct2.get());

    cout << "Encrypted same message with two RNGs (same seed)" << endl;

    // Compare ciphertexts
    vector<string> keys = ct1->getKeys();
    cout << "Comparing " << keys.size() << " ciphertext components:" << endl;

    bool all_match = true;
    for (auto& key : keys) {
        ZObject *obj1 = ct1->getComponent(key);
        ZObject *obj2 = ct2->getComponent(key);

        if (obj1 && obj2 && obj1->isEqual(obj2)) {
            cout << "  ✅ " << key << " matches" << endl;
        } else {
            cout << "  ❌ " << key << " DIFFERS" << endl;
            all_match = false;
        }
    }

    if (all_match) {
        cout << "\n✅ ENCRYPTION IS DETERMINISTIC - ciphertexts match" << endl;
    } else {
        cout << "\n❌ ENCRYPTION IS NON-DETERMINISTIC - ciphertexts differ!" << endl;
        cout << "\nThis is Bug #2: Non-deterministic encryption breaks CCA security" << endl;
    }

    ShutdownOpenABE();
}

int main(int argc, char **argv) {
    cout << "========================================" << endl;
    cout << "  RNG Determinism Test Suite" << endl;
    cout << "========================================" << endl;
    cout << endl;

    testRNGDeterminism();
    testPairingRandomZP();
    testSequentialRandomZP();
    testEncryptionDeterminism();

    cout << "\n========================================" << endl;
    cout << "  Test Complete" << endl;
    cout << "========================================" << endl;

    return 0;
}
