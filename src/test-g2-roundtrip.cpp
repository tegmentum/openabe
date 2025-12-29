///
/// Minimal G2 Serialization Roundtrip Test
/// Tests if a G2 point survives serialization/deserialization
///

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openabe/openabe.h>

using namespace oabe;

#define TEST_PASS(msg) printf("✓ PASS: %s\n", msg)
#define TEST_FAIL(msg) printf("✗ FAIL: %s\n", msg); return 1

int main() {
    printf("╔════════════════════════════════════════════════════════╗\n");
    printf("║    G2 Serialization Roundtrip Test (RELIC 0.7.0)     ║\n");
    printf("╚════════════════════════════════════════════════════════╝\n\n");

    // Initialize OpenABE
    InitializeOpenABE();
    printf(">>> OpenABE initialized\n\n");

    // Create CP-ABE context to set up pairing parameters
    auto context = OpenABE_createContextABESchemeCPA(OpenABE_SCHEME_CP_WATERS);
    if (!context) {
        printf("✗ Failed to create context\n");
        return 1;
    }
    printf(">>> Created CP-ABE context (BN254 curve)\n\n");

    // Generate master parameters to initialize curve
    if (context->generateParams("BN_P256", "mpk", "msk") != OpenABE_NOERROR) {
        printf("✗ Failed to generate parameters\n");
        return 1;
    }
    printf(">>> Generated parameters (curve initialized)\n\n");

    // Test 1: Create a random G2 point
    printf("═══ Test 1: Generate Random G2 Point ═══\n");
    ZP zp;
    zp.setRandom();

    G2 g2_original;
    g2_original.setRandom();
    printf(">>> Generated random G2 point\n");

    // Get coordinates before serialization
    std::string hex_before = g2_original.getBytesAsHex();
    printf(">>> G2 point (hex, first 64 chars): %s...\n", hex_before.substr(0, 64).c_str());
    printf(">>> Hex length: %zu bytes\n\n", hex_before.length() / 2);

    // Test 2: Serialize the point
    printf("═══ Test 2: Serialize G2 Point ═══\n");
    OpenABEByteString serialized;
    g2_original.serializeToBytes(serialized);
    printf(">>> Serialized length: %zu bytes\n", serialized.size());
    printf(">>> First 32 bytes (hex): ");
    for (size_t i = 0; i < 32 && i < serialized.size(); i++) {
        printf("%02x", (unsigned char)serialized.at(i));
    }
    printf("\n\n");

    // Test 3: Deserialize into new point
    printf("═══ Test 3: Deserialize G2 Point ═══\n");
    G2 g2_recovered;
    try {
        g2_recovered.deserializeFromBytes(serialized);
        printf(">>> Deserialization succeeded\n");
    } catch (...) {
        TEST_FAIL("Deserialization threw exception");
        return 1;
    }

    std::string hex_after = g2_recovered.getBytesAsHex();
    printf(">>> G2 recovered (hex, first 64 chars): %s...\n", hex_after.substr(0, 64).c_str());
    printf(">>> Hex length: %zu bytes\n\n", hex_after.length() / 2);

    // Test 4: Compare the points
    printf("═══ Test 4: Compare Original vs Recovered ═══\n");

    // Binary comparison
    bool bytes_match = (hex_before == hex_after);
    if (bytes_match) {
        TEST_PASS("Byte representation matches");
    } else {
        TEST_FAIL("Byte representation MISMATCH");
        printf("    Original:  %s\n", hex_before.substr(0, 128).c_str());
        printf("    Recovered: %s\n", hex_after.substr(0, 128).c_str());
    }

    // Equality operator check
    bool equals = (g2_original == g2_recovered);
    if (equals) {
        TEST_PASS("Equality operator returns true");
    } else {
        TEST_FAIL("Equality operator returns FALSE");
    }

    // Test 5: Pairing test - compute e(G1, G2) with both points
    printf("\n═══ Test 5: Pairing Consistency Test ═══\n");

    G1 g1;
    g1.setRandom();
    printf(">>> Generated random G1 point\n");

    GT gt_original, gt_recovered;
    pairing(gt_original, g1, g2_original);
    pairing(gt_recovered, g1, g2_recovered);
    printf(">>> Computed e(G1, G2_original) and e(G1, G2_recovered)\n");

    std::string gt_orig_hex = gt_original.getBytesAsHex();
    std::string gt_recov_hex = gt_recovered.getBytesAsHex();

    printf(">>> GT_original  (first 64 chars): %s...\n", gt_orig_hex.substr(0, 64).c_str());
    printf(">>> GT_recovered (first 64 chars): %s...\n", gt_recov_hex.substr(0, 64).c_str());

    bool pairing_match = (gt_orig_hex == gt_recov_hex);
    if (pairing_match) {
        TEST_PASS("Pairing results MATCH - serialization preserves cryptographic properties");
    } else {
        TEST_FAIL("Pairing results MISMATCH - THIS IS THE BUG!");
        printf("    This means G2 serialization is broken\n");
        printf("    Original GT:  %s\n", gt_orig_hex.substr(0, 128).c_str());
        printf("    Recovered GT: %s\n", gt_recov_hex.substr(0, 128).c_str());
    }

    // Summary
    printf("\n╔════════════════════════════════════════════════════════╗\n");
    printf("║                    Test Summary                        ║\n");
    printf("╚════════════════════════════════════════════════════════╝\n");

    int status = 0;
    if (!bytes_match) {
        printf("✗ Byte representation changed\n");
        status = 1;
    }
    if (!equals) {
        printf("✗ Equality check failed\n");
        status = 1;
    }
    if (!pairing_match) {
        printf("✗ Pairing consistency failed - CRYPTOGRAPHIC BUG\n");
        status = 1;
    }

    if (status == 0) {
        printf("✓ All tests passed - G2 serialization works correctly\n");
    }

    ShutdownOpenABE();
    return status;
}
