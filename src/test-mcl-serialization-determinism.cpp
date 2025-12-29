#include <stdio.h>
#include <memory>
#include <openabe/openabe.h>

using namespace oabe;
using namespace std;

int main() {
    InitializeOpenABE();

    // Create pairing
    OpenABEPairing pairing("BLS12_P381");
    fprintf(stderr, "[TEST] Testing MCL serialization determinism\n");

    // Create a deterministic RNG
    unique_ptr<OpenABERNG> rng1(new OpenABERNG());
    OpenABEByteString seed;
    seed.fromHex("0123456789ABCDEF0123456789ABCDEF");
    rng1->setSeed(seed);

    // Generate a G1 element with first RNG
    G1 g1_a = pairing.randomG1(rng1.get());

    // Serialize it twice
    OpenABEByteString g1_bytes1, g1_bytes2;
    g1_a.serialize(g1_bytes1);
    g1_a.serialize(g1_bytes2);

    fprintf(stderr, "[TEST] G1 serialization 1: %s\n", g1_bytes1.toHex().c_str());
    fprintf(stderr, "[TEST] G1 serialization 2: %s\n", g1_bytes2.toHex().c_str());

    if (g1_bytes1 == g1_bytes2) {
        fprintf(stderr, "[TEST] SUCCESS: G1 serialization is deterministic\n");
    } else {
        fprintf(stderr, "[TEST] FAILURE: G1 serialization is NOT deterministic!\n");
        ShutdownOpenABE();
        return 1;
    }

    // Now test with same seed but new RNG
    unique_ptr<OpenABERNG> rng2(new OpenABERNG());
    rng2->setSeed(seed);

    G1 g1_b = pairing.randomG1(rng2.get());
    OpenABEByteString g1_bytes3;
    g1_b.serialize(g1_bytes3);

    fprintf(stderr, "[TEST] G1 from RNG1: %s\n", g1_bytes1.toHex().c_str());
    fprintf(stderr, "[TEST] G1 from RNG2: %s\n", g1_bytes3.toHex().c_str());

    if (g1_bytes1 == g1_bytes3) {
        fprintf(stderr, "[TEST] SUCCESS: Same seed produces same G1\n");
    } else {
        fprintf(stderr, "[TEST] FAILURE: Same seed produces different G1!\n");
        ShutdownOpenABE();
        return 1;
    }

    // Test GT elements
    G1 g1_x = pairing.randomG1(rng1.get());
    G2 g2_x = pairing.randomG2(rng1.get());
    GT gt_a = pairing.pairing(g1_x, g2_x);

    OpenABEByteString gt_bytes1, gt_bytes2;
    gt_a.serialize(gt_bytes1);
    gt_a.serialize(gt_bytes2);

    fprintf(stderr, "[TEST] GT serialization 1: %zu bytes\n", gt_bytes1.size());
    fprintf(stderr, "[TEST] GT serialization 2: %zu bytes\n", gt_bytes2.size());

    if (gt_bytes1 == gt_bytes2) {
        fprintf(stderr, "[TEST] SUCCESS: GT serialization is deterministic\n");
    } else {
        fprintf(stderr, "[TEST] FAILURE: GT serialization is NOT deterministic!\n");
        ShutdownOpenABE();
        return 1;
    }

    fprintf(stderr, "[TEST] ALL TESTS PASSED!\n");
    ShutdownOpenABE();
    return 0;
}
