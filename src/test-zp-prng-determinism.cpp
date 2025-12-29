/*
 * Test to verify ZP element generation is deterministic with same PRNG
 *
 * This test verifies that creating ZP elements using ZP::setRandom() with
 * the same PRNG produces identical elements. This is critical for CCA
 * verification to work.
 */

#include <stdio.h>
#include <string.h>
#include <openabe/openabe.h>

using namespace oabe;

int main() {
  printf("\n=== ZP Element PRNG Determinism Test ===\n\n");

  // Initialize OpenABE
  InitializeOpenABE();

  // Create pairing context
  std::unique_ptr<OpenABEPairing> pairing(new OpenABEPairing(OpenABE_SCHEME_CP_WATERS));

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

  // Test 1: Create ZP elements with two PRNGs using same seed
  printf("Test 1: ZP elements from two PRNGs with same seed\n");
  printf("--------------------------------------------------\n");

  OpenABECTR_DRBG prng1(key);
  prng1.setSeed(nonce);

  OpenABECTR_DRBG prng2(key);
  prng2.setSeed(nonce);

  // Create 5 ZP elements from each PRNG
  bool all_match = true;
  for (int i = 0; i < 5; i++) {
    ZP elem1, elem2;
    elem1.setRandom(pairing.get(), &prng1);
    elem2.setRandom(pairing.get(), &prng2);

    OpenABEByteString bytes1, bytes2;
    elem1.getLengthAndByteString(bytes1);
    elem2.getLengthAndByteString(bytes2);

    printf("ZP[%d] - PRNG1: %s\n", i, bytes1.toHex().substr(0, 64).c_str());
    printf("ZP[%d] - PRNG2: %s", i, bytes2.toHex().substr(0, 64).c_str());

    if (bytes1 == bytes2) {
      printf(" ✓\n");
    } else {
      printf(" ✗ MISMATCH!\n");
      all_match = false;
    }
  }

  if (!all_match) {
    printf("\n✗ FAIL: ZP elements don't match!\n");
    printf("\nThis explains the CCA verification failure:\n");
    printf("Even with deterministic PRNG, ZP::setRandom() produces different elements.\n\n");
    ShutdownOpenABE();
    return 1;
  }

  printf("\n✓ PASS: All ZP elements matched\n\n");

  // Test 2: Create G1 elements
  printf("Test 2: G1 elements from two PRNGs with same seed\n");
  printf("--------------------------------------------------\n");

  OpenABECTR_DRBG prng3(key);
  prng3.setSeed(nonce);

  OpenABECTR_DRBG prng4(key);
  prng4.setSeed(nonce);

  all_match = true;
  for (int i = 0; i < 3; i++) {
    G1 elem1, elem2;
    elem1.setRandom(pairing.get(), &prng3);
    elem2.setRandom(pairing.get(), &prng4);

    OpenABEByteString bytes1, bytes2;
    elem1.getLengthAndByteString(bytes1);
    elem2.getLengthAndByteString(bytes2);

    printf("G1[%d] - PRNG3: %s\n", i, bytes1.toHex().substr(0, 64).c_str());
    printf("G1[%d] - PRNG4: %s", i, bytes2.toHex().substr(0, 64).c_str());

    if (bytes1 == bytes2) {
      printf(" ✓\n");
    } else {
      printf(" ✗ MISMATCH!\n");
      all_match = false;
    }
  }

  if (!all_match) {
    printf("\n✗ FAIL: G1 elements don't match!\n\n");
    ShutdownOpenABE();
    return 1;
  }

  printf("\n✓ PASS: All G1 elements matched\n\n");

  // Test 3: Create G2 elements
  printf("Test 3: G2 elements from two PRNGs with same seed\n");
  printf("--------------------------------------------------\n");

  OpenABECTR_DRBG prng5(key);
  prng5.setSeed(nonce);

  OpenABECTR_DRBG prng6(key);
  prng6.setSeed(nonce);

  all_match = true;
  for (int i = 0; i < 3; i++) {
    G2 elem1, elem2;
    elem1.setRandom(pairing.get(), &prng5);
    elem2.setRandom(pairing.get(), &prng6);

    OpenABEByteString bytes1, bytes2;
    elem1.getLengthAndByteString(bytes1);
    elem2.getLengthAndByteString(bytes2);

    printf("G2[%d] - PRNG5: %s\n", i, bytes1.toHex().substr(0, 64).c_str());
    printf("G2[%d] - PRNG6: %s", i, bytes2.toHex().substr(0, 64).c_str());

    if (bytes1 == bytes2) {
      printf(" ✓\n");
    } else {
      printf(" ✗ MISMATCH!\n");
      all_match = false;
    }
  }

  if (!all_match) {
    printf("\n✗ FAIL: G2 elements don't match!\n\n");
    ShutdownOpenABE();
    return 1;
  }

  printf("\n✓ PASS: All G2 elements matched\n\n");

  printf("=== ALL TESTS PASSED ===\n");
  printf("\nConclusion: ZP, G1, and G2 element generation is deterministic.\n");
  printf("The CCA verification issue must be elsewhere in the encryption flow.\n\n");

  ShutdownOpenABE();
  return 0;
}
