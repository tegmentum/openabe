// Simple test to isolate CTR-DRBG PRNG behavior
// This test uses fixed entropy/nonce to ensure deterministic initialization

#include <stdio.h>
#include <string.h>
#include <memory>
#include <openabe/openabe.h>

using namespace oabe;

int main() {
    fprintf(stderr, "=== CTR-DRBG Isolation Test ===\n");

    // Use fixed entropy for reproducibility
    uint8_t fixed_entropy[32];
    memset(fixed_entropy, 0x42, 32);  // Fill with 0x42

    fprintf(stderr, "Fixed entropy (32 bytes): ");
    for (int i = 0; i < 32; i++) {
        fprintf(stderr, "%02x", fixed_entropy[i]);
    }
    fprintf(stderr, "\n");

    // Create default PRNG (will use OS RNG but we're just testing AES logging)
    OpenABERNG rng;

    // Initialize OpenABE library (for curve parameters)
    InitializeOpenABE();

    // Use BLS12_381 curve - DEFAULT_BP_PARAM is for BLS12-381
    OpenABEPairing pairing(DEFAULT_BP_PARAM);

    fprintf(stderr, "\nGenerating 10 random ZP elements (using default RNG):\n");

    // Generate 10 random ZP scalars and print them
    for (int i = 0; i < 10; i++) {
        ZP zp_val = pairing.randomZP(&rng);

        // Serialize to bytes to see the value
        OpenABEByteString zp_bytes;
        zp_val.serialize(zp_bytes);

        fprintf(stderr, "ZP[%d] = ", i);
        for (size_t j = 0; j < zp_bytes.size() && j < 32; j++) {
            fprintf(stderr, "%02x", zp_bytes.at(j));
        }
        fprintf(stderr, "\n");
    }

    fprintf(stderr, "\n=== Test Complete ===\n");

    ShutdownOpenABE();
    return 0;
}
