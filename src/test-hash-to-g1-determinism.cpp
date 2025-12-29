/*
 * Test to verify hash-to-G1 operations are deterministic
 *
 * In CP-ABE encryption, attribute strings are hashed to G1 elements using
 * hashToG1(). For CCA verification to work, the same string must always
 * produce the same G1 element.
 *
 * This test verifies that hashToG1() is deterministic.
 */

#include <stdio.h>
#include <string.h>
#include <openabe/openabe.h>

using namespace oabe;

int main() {
  printf("\n=== Hash-to-G1 Determinism Test ===\n\n");

  // Initialize OpenABE
  InitializeOpenABE();

  // Create pairing context
  std::unique_ptr<OpenABEPairing> pairing(new OpenABEPairing("BN254"));

  // Create a hash function key prefix (like CP-ABE does)
  OpenABEByteString k;
  uint8_t k_bytes[16] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                         0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10};
  k.appendArray(k_bytes, 16);

  // Test 1: Basic hash-to-G1 determinism
  printf("Test 1: Basic hash-to-G1 with same string\n");
  printf("-------------------------------------------\n");

  std::string test_str1 = "attribute1";
  G1 hash1_a = pairing->hashToG1(k, test_str1);
  G1 hash1_b = pairing->hashToG1(k, test_str1);

  printf("hashToG1(\"%s\") first:  ", test_str1.c_str());
  if (hash1_a == hash1_b) {
    printf("✓ MATCH\n");
  } else {
    printf("✗ MISMATCH!\n");
    printf("\n🔍 ROOT CAUSE FOUND:\n");
    printf("hashToG1() produces different G1 elements for same string!\n");
    printf("This explains why CCA re-encryption produces different ciphertexts.\n\n");
    ShutdownOpenABE();
    return 1;
  }

  printf("\n✓ PASS: Basic hash-to-G1 is deterministic\n\n");

  // Test 2: Multiple different strings
  printf("Test 2: Multiple different attribute strings\n");
  printf("----------------------------------------------\n");

  std::string attributes[] = {
    "department:engineering",
    "role:developer",
    "level:senior",
    "location:usa",
    "clearance:top_secret"
  };

  bool all_match = true;
  for (int i = 0; i < 5; i++) {
    G1 hash_a = pairing->hashToG1(k, attributes[i]);
    G1 hash_b = pairing->hashToG1(k, attributes[i]);

    printf("hashToG1(\"%s\"): ", attributes[i].c_str());
    if (hash_a == hash_b) {
      printf("✓ MATCH\n");
    } else {
      printf("✗ MISMATCH!\n");
      all_match = false;
    }
  }

  if (!all_match) {
    printf("\n✗ FAIL: Some hash-to-G1 operations didn't match!\n\n");
    ShutdownOpenABE();
    return 1;
  }

  printf("\n✓ PASS: All attribute hash-to-G1 operations are deterministic\n\n");

  // Test 3: Hash-to-G1 with different prefix keys
  printf("Test 3: Hash-to-G1 with different hash prefixes\n");
  printf("-------------------------------------------------\n");

  OpenABEByteString k2;
  uint8_t k2_bytes[16] = {0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA, 0xF9, 0xF8,
                          0xF7, 0xF6, 0xF5, 0xF4, 0xF3, 0xF2, 0xF1, 0xF0};
  k2.appendArray(k2_bytes, 16);

  std::string test_attr = "test:attribute";
  G1 hash_k1_a = pairing->hashToG1(k, test_attr);
  G1 hash_k1_b = pairing->hashToG1(k, test_attr);

  printf("hashToG1(k,  \"%s\"): ", test_attr.c_str());
  if (hash_k1_a == hash_k1_b) {
    printf("✓ MATCH\n");
  } else {
    printf("✗ MISMATCH!\n");
    ShutdownOpenABE();
    return 1;
  }

  G1 hash_k2_a = pairing->hashToG1(k2, test_attr);
  G1 hash_k2_b = pairing->hashToG1(k2, test_attr);

  printf("hashToG1(k2, \"%s\"): ", test_attr.c_str());
  if (hash_k2_a == hash_k2_b) {
    printf("✓ MATCH\n");
  } else {
    printf("✗ MISMATCH!\n");
    ShutdownOpenABE();
    return 1;
  }

  printf("\n✓ PASS: Hash-to-G1 with different prefixes is deterministic\n\n");

  // Test 4: Simulating CP-ABE encryption pattern
  printf("Test 4: CP-ABE encryption pattern simulation\n");
  printf("----------------------------------------------\n");

  // Simulate what happens during CP-ABE encryption for an attribute
  // For each attribute in policy: h_i = hashToG1(attr_i)
  std::string policy_attrs[] = {
    "department:engineering",
    "role:manager"
  };

  printf("First encryption:\n");
  G1 h1_enc1 = pairing->hashToG1(k, policy_attrs[0]);
  G1 h2_enc1 = pairing->hashToG1(k, policy_attrs[1]);

  printf("  h_i for \"%s\"\n", policy_attrs[0].c_str());
  printf("  h_i for \"%s\"\n", policy_attrs[1].c_str());

  printf("\nSecond encryption (re-encryption):\n");
  G1 h1_enc2 = pairing->hashToG1(k, policy_attrs[0]);
  G1 h2_enc2 = pairing->hashToG1(k, policy_attrs[1]);

  printf("  h_i for \"%s\"\n", policy_attrs[0].c_str());
  printf("  h_i for \"%s\"\n", policy_attrs[1].c_str());

  printf("\nComparison:\n");
  bool h1_match = (h1_enc1 == h1_enc2);
  bool h2_match = (h2_enc1 == h2_enc2);

  printf("  h1 matches: %s\n", h1_match ? "✓ YES" : "✗ NO");
  printf("  h2 matches: %s\n", h2_match ? "✓ YES" : "✗ NO");

  if (!h1_match || !h2_match) {
    printf("\n✗ FAIL: Hash-to-G1 in CP-ABE pattern is non-deterministic!\n");
    printf("This explains the CCA verification failure.\n\n");
    ShutdownOpenABE();
    return 1;
  }

  printf("\n✓ PASS: CP-ABE encryption pattern hash-to-G1 is deterministic\n\n");

  // Test 5: Repeated hash-to-G1 calls
  printf("Test 5: Repeated hash-to-G1 calls\n");
  printf("-----------------------------------\n");

  std::string repeated_attr = "clearance:confidential";
  G1 first = pairing->hashToG1(k, repeated_attr);
  G1 second = pairing->hashToG1(k, repeated_attr);
  G1 third = pairing->hashToG1(k, repeated_attr);

  printf("First  hash-to-G1(\"%s\")\n", repeated_attr.c_str());
  printf("Second hash-to-G1(\"%s\")\n", repeated_attr.c_str());
  printf("Third  hash-to-G1(\"%s\")\n", repeated_attr.c_str());

  printf("Comparing first vs second: ");
  if (first == second) {
    printf("✓ MATCH\n");
  } else {
    printf("✗ MISMATCH!\n");
    ShutdownOpenABE();
    return 1;
  }

  printf("Comparing second vs third: ");
  if (second == third) {
    printf("✓ MATCH\n");
  } else {
    printf("✗ MISMATCH!\n");
    ShutdownOpenABE();
    return 1;
  }

  printf("\n✓ PASS: Repeated hash-to-G1 is consistent\n\n");

  printf("=== ALL TESTS PASSED ===\n");
  printf("\nConclusion: Hash-to-G1 operations are completely deterministic.\n");
  printf("If CCA still fails, the issue must be in:\n");
  printf("  - LSSS (policy evaluation and secret sharing)\n");
  printf("  - Ciphertext serialization/comparison\n");
  printf("  - Attribute list ordering or processing\n\n");

  ShutdownOpenABE();
  return 0;
}
