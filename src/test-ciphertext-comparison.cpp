/*
 * Test to verify ciphertext comparison works correctly after the fix
 *
 * This test creates two identical ciphertexts and verifies they compare as equal.
 * Before the fix, this would fail due to the bug in operator==.
 */

#include <stdio.h>
#include <string.h>
#include <openabe/openabe.h>

using namespace oabe;

int main() {
  printf("\n=== Ciphertext Comparison Fix Verification ===\n\n");

  // Initialize OpenABE
  InitializeOpenABE();

  // Create pairing context
  std::unique_ptr<OpenABEPairing> pairing(new OpenABEPairing("BN254"));

  // Create RNG with fixed seed for deterministic testing
  OpenABEByteString key, nonce;
  uint8_t key_data[32];
  uint8_t nonce_data[16];

  for (int i = 0; i < 32; i++) {
    key_data[i] = (uint8_t)(i * 7);
  }
  for (int i = 0; i < 16; i++) {
    nonce_data[i] = (uint8_t)(i * 11);
  }

  key.appendArray(key_data, 32);
  nonce.appendArray(nonce_data, 16);

  std::unique_ptr<OpenABERNG> rng1(new OpenABECTR_DRBG(key));
  rng1->setSeed(nonce);

  std::unique_ptr<OpenABERNG> rng2(new OpenABECTR_DRBG(key));
  rng2->setSeed(nonce);

  // Test 1: Create two containers with identical components
  printf("Test 1: Identical containers should compare equal\n");
  printf("--------------------------------------------------\n");

  OpenABECiphertext ct1(pairing->getGroup());
  OpenABECiphertext ct2(pairing->getGroup());

  // Add same components to both
  G1 g1_1 = pairing->randomG1(rng1.get());
  G1 g1_2 = pairing->randomG1(rng2.get());

  ct1.setComponent("test_g1", &g1_1);
  ct2.setComponent("test_g1", &g1_2);

  printf("Created two ciphertexts with identical G1 components\n");

  if (ct1 == ct2) {
    printf("✓ PASS: Ciphertexts compare as equal\n\n");
  } else {
    printf("✗ FAIL: Ciphertexts don't compare as equal (bug still present!)\n\n");
    ShutdownOpenABE();
    return 1;
  }

  // Test 2: Different ciphertexts should not compare equal
  printf("Test 2: Different containers should not compare equal\n");
  printf("-------------------------------------------------------\n");

  OpenABECiphertext ct3(pairing->getGroup());
  OpenABECiphertext ct4(pairing->getGroup());

  G1 g1_3 = pairing->randomG1(rng1.get());
  G1 g1_4 = pairing->randomG1(rng1.get()); // Different element

  ct3.setComponent("test_g1", &g1_3);
  ct4.setComponent("test_g1", &g1_4);

  if (ct3 == ct4) {
    printf("✗ FAIL: Different ciphertexts compare as equal (bug in comparison!)\n\n");
    ShutdownOpenABE();
    return 1;
  } else {
    printf("✓ PASS: Different ciphertexts correctly compare as not equal\n\n");
  }

  // Test 3: Containers with different number of components
  printf("Test 3: Containers with different keys should not compare equal\n");
  printf("-----------------------------------------------------------------\n");

  OpenABECiphertext ct5(pairing->getGroup());
  OpenABECiphertext ct6(pairing->getGroup());

  G1 g1_5 = pairing->randomG1(rng1.get());
  G2 g2_5 = pairing->randomG2(rng1.get());

  ct5.setComponent("test_g1", &g1_5);
  ct6.setComponent("test_g1", &g1_5);
  ct6.setComponent("test_g2", &g2_5); // Extra component

  if (ct5 == ct6) {
    printf("✗ FAIL: Containers with different keys compare as equal (bug!)\n\n");
    ShutdownOpenABE();
    return 1;
  } else {
    printf("✓ PASS: Containers with different keys correctly compare as not equal\n\n");
  }

  // Test 4: Multiple identical components
  printf("Test 4: Multiple identical components\n");
  printf("---------------------------------------\n");

  rng1.reset(new OpenABECTR_DRBG(key));
  rng1->setSeed(nonce);
  rng2.reset(new OpenABECTR_DRBG(key));
  rng2->setSeed(nonce);

  OpenABECiphertext ct7(pairing->getGroup());
  OpenABECiphertext ct8(pairing->getGroup());

  G1 g1_7a = pairing->randomG1(rng1.get());
  G1 g1_7b = pairing->randomG1(rng1.get());
  G2 g2_7 = pairing->randomG2(rng1.get());

  G1 g1_8a = pairing->randomG1(rng2.get());
  G1 g1_8b = pairing->randomG1(rng2.get());
  G2 g2_8 = pairing->randomG2(rng2.get());

  ct7.setComponent("C_attr1", &g1_7a);
  ct7.setComponent("C_attr2", &g1_7b);
  ct7.setComponent("D_attr1", &g2_7);

  ct8.setComponent("C_attr1", &g1_8a);
  ct8.setComponent("C_attr2", &g1_8b);
  ct8.setComponent("D_attr1", &g2_8);

  printf("Created two ciphertexts with 3 components each\n");

  if (ct7 == ct8) {
    printf("✓ PASS: Multi-component ciphertexts compare as equal\n\n");
  } else {
    printf("✗ FAIL: Multi-component ciphertexts don't compare as equal\n\n");
    ShutdownOpenABE();
    return 1;
  }

  printf("=== ALL TESTS PASSED ===\n");
  printf("\nConclusion: Ciphertext comparison operator is working correctly!\n");
  printf("The bug fix in zcontainer.cpp:272 has resolved the issue.\n");
  printf("CCA verification should now work properly.\n\n");

  ShutdownOpenABE();
  return 0;
}
