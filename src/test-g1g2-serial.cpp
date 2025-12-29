#include <stdio.h>
#include <memory>
#include <openabe/openabe.h>

using namespace oabe;
using namespace std;

int main() {
    // Initialize OpenABE
    InitializeOpenABE();

    // Create pairing for BLS12-381 with MCL
    OpenABEPairing pairing("BLS12_P381");
    fprintf(stderr, "[TEST] Pairing initialized for BLS12-381\n");

    // Create a random OpenABERNG
    unique_ptr<OpenABERNG> rng(new OpenABERNG());

    // Generate random G1 element
    G1 g1_orig = pairing.randomG1(rng.get());
    fprintf(stderr, "[TEST] Created random G1 element\n");

    // Serialize it
    OpenABEByteString g1_bytes;
    g1_orig.serialize(g1_bytes);
    fprintf(stderr, "[TEST] Serialized G1: %zu bytes\n", g1_bytes.size());

    // Deserialize it
    G1 g1_restored = pairing.initG1();
    g1_restored.deserialize(g1_bytes);
    fprintf(stderr, "[TEST] Deserialized G1\n");

    // Compare
    if (g1_orig == g1_restored) {
        fprintf(stderr, "[TEST] SUCCESS: G1 serialization/deserialization works!\n");
    } else {
        fprintf(stderr, "[TEST] FAILURE: G1 mismatch after deserialization!\n");
        return 1;
    }

    // Do the same for G2
    G2 g2_orig = pairing.randomG2(rng.get());
    fprintf(stderr, "[TEST] Created random G2 element\n");

    OpenABEByteString g2_bytes;
    g2_orig.serialize(g2_bytes);
    fprintf(stderr, "[TEST] Serialized G2: %zu bytes\n", g2_bytes.size());

    G2 g2_restored = pairing.initG2();
    g2_restored.deserialize(g2_bytes);
    fprintf(stderr, "[TEST] Deserialized G2\n");

    if (g2_orig == g2_restored) {
        fprintf(stderr, "[TEST] SUCCESS: G2 serialization/deserialization works!\n");
    } else {
        fprintf(stderr, "[TEST] FAILURE: G2 mismatch after deserialization!\n");
        return 1;
    }

    fprintf(stderr, "[TEST] ALL TESTS PASSED!\n");

    ShutdownOpenABE();
    return 0;
}
