#include <iostream>
#include <iomanip>
#include <openabe/openabe.h>

using namespace std;
using namespace oabe;

int main() {
    cout << "Testing PRNG Determinism" << endl;
    cout << "========================" << endl;

    // Initialize OpenABE
    InitializeOpenABE();

    // Create identical entropy and nonce for both PRNGs
    OpenABEByteString entropy;
    entropy.fromHex("19F0493D5413F912126C50C1E987C8A64F373168E47F98CC011B1B588BDA46FF");

    OpenABEByteString nonce;
    nonce.fromHex("21415F4FCF168D14AA1A570A8E0BE1D6");

    cout << "\nEntropy: " << entropy.toHex() << endl;
    cout << "Nonce:   " << nonce.toHex() << endl;

    // Create first PRNG
    cout << "\n--- Creating PRNG #1 ---" << endl;
    unique_ptr<OpenABECTR_DRBG> prng1(new OpenABECTR_DRBG(entropy));
    prng1->setSeed(nonce);

    // Create second PRNG with same entropy and nonce
    cout << "\n--- Creating PRNG #2 ---" << endl;
    unique_ptr<OpenABECTR_DRBG> prng2(new OpenABECTR_DRBG(entropy));
    prng2->setSeed(nonce);

    // Generate random bytes from both PRNGs
    cout << "\n--- Generating Random Bytes ---" << endl;
    const size_t numBytes = 32;
    const int numIterations = 5;

    bool allMatch = true;

    for (int i = 0; i < numIterations; i++) {
        OpenABEByteString rand1, rand2;

        prng1->getRandomBytes(&rand1, numBytes);
        prng2->getRandomBytes(&rand2, numBytes);

        cout << "\nIteration " << (i+1) << ":" << endl;
        cout << "PRNG1: " << rand1.toHex() << endl;
        cout << "PRNG2: " << rand2.toHex() << endl;

        if (rand1 == rand2) {
            cout << "✓ MATCH" << endl;
        } else {
            cout << "✗ MISMATCH!" << endl;
            allMatch = false;
        }
    }

    cout << "\n========================" << endl;
    if (allMatch) {
        cout << "SUCCESS: All random values matched!" << endl;
        cout << "The PRNG is deterministic." << endl;
    } else {
        cout << "FAILURE: Random values did not match!" << endl;
        cout << "The PRNG is NOT deterministic - BUG FOUND!" << endl;
    }

    ShutdownOpenABE();

    return allMatch ? 0 : 1;
}
