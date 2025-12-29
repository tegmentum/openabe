/*
 * Test to verify cryptographic element generation is deterministic with same PRNG
 *
 * This test verifies that generating ZP, G1, and G2 elements using the pairing
 * randomZP(), randomG1(), randomG2() functions with PRNGs having the same seed
 * produces identical elements. This is critical for CCA verification.
 */

#include <stdio.h>
#include <string.h>
#include <openabe/openabe.h>

using namespace oabe;

int main() {
  printf("\n=== Cryptographic Element PRNG Determinism Test ===\n\n");

  // Initialize OpenABE
  InitializeOpenABE();

  // Create pairing context
  std::unique_ptr<OpenABEPairing> pairing(new OpenABEPairing("BN254"));

  // Create fixed test key and nonce
  OpenABEByteString key, nonce;
  uint8_t key_data[32];
  uint8_t nonce_data[16];

  // Fill with test pattern
  for (int i = 0; i < 32; i++) {
    key_data[i] = (uint8_t)(i * 7);
  }
  for (int i = 0; i < 16; i++) {
    nonce_data[i] = (uint8_t)(i * 11);
  }

  key.appendArray(key_data, 32);
  nonce.appendArray(nonce_data, 16);

  printf("Test Key (hex):   %s\n", key.toHex().c_str());
  printf("Test Nonce (hex): %s\n\n", nonce.toHex().c_str());

  // Test 1: ZP elements
  printf("Test 1: ZP elements from two PRNGs with same seed\n");
  printf("--------------------------------------------------\n");

  OpenABECTR_DRBG prng1(key);
  prng1.setSeed(nonce);

  OpenABECTR_DRBG prng2(key);
  prng2.setSeed(nonce);

  bool all_match = true;
  for (int i = 0; i < 5; i++) {
    ZP elem1 = pairing->randomZP(&prng1);
    ZP elem2 = pairing->randomZP(&prng2);

    printf("ZP[%d] - PRNG1: %s\n", i, elem1.getBytesAsString().substr(0, 64).c_str());
    printf("ZP[%d] - PRNG2: %s", i, elem2.getBytesAsString().substr(0, 64).c_str());

    if (elem1 == elem2) {
      printf(" ✓\n");
    } else {
      printf(" ✗ MISMATCH!\n");
      all_match = false;
    }
  }

  if (!all_match) {
    printf("\n✗ FAIL: ZP elements don't match!\n");
    printf("\n🔍 ROOT CAUSE FOUND:\n");
    printf("randomZP() produces different elements despite identical PRNG seeds.\n");
    printf("This explains why CCA verification fails!\n\n");
    ShutdownOpenABE();
    return 1;
  }

  printf("\n✓ PASS: All ZP elements matched\n\n");

  // Test 2: G1 elements
  printf("Test 2: G1 elements from two PRNGs with same seed\n");
  printf("--------------------------------------------------\n");

  OpenABECTR_DRBG prng3(key);
  prng3.setSeed(nonce);

  OpenABECTR_DRBG prng4(key);
  prng4.setSeed(nonce);

  all_match = true;
  for (int i = 0; i < 3; i++) {
    G1 elem1 = pairing->randomG1(&prng3);
    G1 elem2 = pairing->randomG1(&prng4);

    printf("G1[%d]: ", i);

    if (elem1 == elem2) {
      printf(" ✓\n");
    } else {
      printf(" ✗ MISMATCH!\n");
      all_match = false;
    }
  }

  if (!all_match) {
    printf("\n✗ FAIL: G1 elements don't match!\n");
    printf("\n🔍 ROOT CAUSE FOUND:\n");
    printf("randomG1() produces different elements despite identical PRNG seeds.\n");
    printf("This explains why CCA verification fails!\n\n");
    ShutdownOpenABE();
    return 1;
  }

  printf("\n✓ PASS: All G1 elements matched\n\n");

  // Test 3: G2 elements
  printf("Test 3: G2 elements from two PRNGs with same seed\n");
  printf("--------------------------------------------------\n");

  OpenABECTR_DRBG prng5(key);
  prng5.setSeed(nonce);

  OpenABECTR_DRBG prng6(key);
  prng6.setSeed(nonce);

  all_match = true;
  for (int i = 0; i < 3; i++) {
    G2 elem1 = pairing->randomG2(&prng5);
    G2 elem2 = pairing->randomG2(&prng6);

    printf("G2[%d]: ", i);

    if (elem1 == elem2) {
      printf("✓\n");
    } else {
      printf("✗ MISMATCH!\n");
      all_match = false;
    }
  }

  if (!all_match) {
    printf("\n✗ FAIL: G2 elements don't match!\n");
    printf("\n🔍 ROOT CAUSE FOUND:\n");
    printf("randomG2() produces different elements despite identical PRNG seeds.\n");
    printf("This explains why CCA verification fails!\n\n");
    ShutdownOpenABE();
    return 1;
  }

  printf("\n✓ PASS: All G2 elements matched\n\n");

  // Test 4: Mixed element generation (like in CP-ABE encryption)
  printf("Test 4: Mixed element generation pattern (simulating CP-ABE)\n");
  printf("--------------------------------------------------------------\n");

  OpenABECTR_DRBG prng7(key);
  prng7.setSeed(nonce);

  OpenABECTR_DRBG prng8(key);
  prng8.setSeed(nonce);

  // Simulate CP-ABE encryption pattern: s, multiple yi values, G1 elements
  printf("Generating: s (ZP), y1 (ZP), y2 (ZP), C' (G1)\n\n");

  ZP s1 = pairing->randomZP(&prng7);
  ZP y1_1 = pairing->randomZP(&prng7);
  ZP y2_1 = pairing->randomZP(&prng7);
  G1 Cprime1 = pairing->randomG1(&prng7);

  ZP s2 = pairing->randomZP(&prng8);
  ZP y1_2 = pairing->randomZP(&prng8);
  ZP y2_2 = pairing->randomZP(&prng8);
  G1 Cprime2 = pairing->randomG1(&prng8);

  printf("s from PRNG7:  %s\n", s1.getBytesAsString().substr(0, 32).c_str());
  printf("s from PRNG8:  %s", s2.getBytesAsString().substr(0, 32).c_str());
  bool s_match = (s1 == s2);
  printf(" %s\n", s_match ? "✓" : "✗");

  printf("y1 from PRNG7: %s\n", y1_1.getBytesAsString().substr(0, 32).c_str());
  printf("y1 from PRNG8: %s", y1_2.getBytesAsString().substr(0, 32).c_str());
  bool y1_match = (y1_1 == y1_2);
  printf(" %s\n", y1_match ? "✓" : "✗");

  printf("y2 from PRNG7: %s\n", y2_1.getBytesAsString().substr(0, 32).c_str());
  printf("y2 from PRNG8: %s", y2_2.getBytesAsString().substr(0, 32).c_str());
  bool y2_match = (y2_1 == y2_2);
  printf(" %s\n", y2_match ? "✓" : "✗");

  printf("C' from PRNG7: ");
  bool Cprime_match = (Cprime1 == Cprime2);
  printf("%s\n", Cprime_match ? "✓" : "✗");

  if (s_match && y1_match && y2_match && Cprime_match) {
    printf("\n✓ PASS: Mixed element generation is deterministic\n\n");
  } else {
    printf("\n✗ FAIL: Mixed element generation has non-determinism!\n");
    printf("\n🔍 ROOT CAUSE FOUND:\n");
    printf("The element generation pattern used in CP-ABE is non-deterministic.\n");
    printf("This is why CCA verification fails!\n\n");
    ShutdownOpenABE();
    return 1;
  }

  printf("=== ALL TESTS PASSED ===\n");
  printf("\nConclusion: All cryptographic element generation is deterministic.\n");
  printf("If CCA still fails, the issue must be in a different part of the code.\n\n");

  ShutdownOpenABE();
  return 0;
}
