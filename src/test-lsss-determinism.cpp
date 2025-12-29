/*
 * Test to verify LSSS (Linear Secret Sharing Scheme) is deterministic
 *
 * The LSSS is used in CP-ABE to distribute secret shares according to a policy.
 * For CCA verification to work, the same policy and secret must produce
 * identical secret shares every time.
 *
 * This test verifies that LSSS operations are deterministic.
 */

#include <stdio.h>
#include <string.h>
#include <openabe/openabe.h>

using namespace oabe;

void printLSSSRows(const OpenABELSSSRowMap& rows, const char* label) {
  printf("\n%s:\n", label);
  for (auto it = rows.begin(); it != rows.end(); ++it) {
    printf("  Attribute: %s\n", it->first.c_str());
    printf("    Label: %s\n", it->second.label().c_str());
    printf("    Share: %s\n", it->second.element().getBytesAsString().substr(0, 32).c_str());
  }
}

int main() {
  printf("\n=== LSSS Determinism Test ===\n\n");

  // Initialize OpenABE
  InitializeOpenABE();

  // Create pairing context
  std::unique_ptr<OpenABEPairing> pairing(new OpenABEPairing("BN254"));

  // Create fixed RNG with known seed
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

  // Test 1: Basic LSSS determinism with simple policy
  printf("Test 1: Basic LSSS with simple AND policy\n");
  printf("-------------------------------------------\n");

  std::string policy_str1 = "department:engineering and role:developer";
  std::unique_ptr<OpenABEPolicy> policy1 = createPolicyTree(policy_str1);

  // Create two RNGs with same seed
  std::unique_ptr<OpenABECTR_DRBG> rng1(new OpenABECTR_DRBG(key));
  rng1->setSeed(nonce);

  std::unique_ptr<OpenABECTR_DRBG> rng2(new OpenABECTR_DRBG(key));
  rng2->setSeed(nonce);

  // Generate same secret for both
  ZP s1 = pairing->randomZP(rng1.get());

  // Reset RNG2 to same state
  rng2.reset(new OpenABECTR_DRBG(key));
  rng2->setSeed(nonce);
  ZP s2 = pairing->randomZP(rng2.get());

  printf("Secret s1: %s\n", s1.getBytesAsString().substr(0, 32).c_str());
  printf("Secret s2: %s\n", s2.getBytesAsString().substr(0, 32).c_str());

  if (!(s1 == s2)) {
    printf("✗ FAIL: Secrets don't match! RNG is broken.\n\n");
    ShutdownOpenABE();
    return 1;
  }
  printf("✓ Secrets match\n");

  // Create two LSSS instances and share the secret
  OpenABELSSS lsss1(pairing.get(), rng1.get());
  lsss1.shareSecret(policy1.get(), s1);

  OpenABELSSS lsss2(pairing.get(), rng2.get());
  lsss2.shareSecret(policy1.get(), s2);

  // Get the rows from both
  OpenABELSSSRowMap rows1 = lsss1.getRows();
  OpenABELSSSRowMap rows2 = lsss2.getRows();

  printf("\nNumber of shares in LSSS1: %zu\n", rows1.size());
  printf("Number of shares in LSSS2: %zu\n", rows2.size());

  if (rows1.size() != rows2.size()) {
    printf("✗ FAIL: Different number of shares!\n\n");
    ShutdownOpenABE();
    return 1;
  }

  // Compare each share
  bool all_match = true;
  for (auto it1 = rows1.begin(); it1 != rows1.end(); ++it1) {
    auto it2 = rows2.find(it1->first);

    if (it2 == rows2.end()) {
      printf("✗ Attribute '%s' not found in LSSS2!\n", it1->first.c_str());
      all_match = false;
      continue;
    }

    printf("\nComparing attribute: %s\n", it1->first.c_str());

    // Compare labels
    if (it1->second.label() != it2->second.label()) {
      printf("  Labels differ: '%s' vs '%s'\n",
             it1->second.label().c_str(), it2->second.label().c_str());
      all_match = false;
    } else {
      printf("  Labels match: %s ✓\n", it1->second.label().c_str());
    }

    // Compare shares (ZP elements)
    if (it1->second.element() == it2->second.element()) {
      printf("  Shares match ✓\n");
    } else {
      printf("  Shares differ ✗\n");
      printf("    LSSS1 share: %s\n", it1->second.element().getBytesAsString().substr(0, 32).c_str());
      printf("    LSSS2 share: %s\n", it2->second.element().getBytesAsString().substr(0, 32).c_str());
      all_match = false;
    }
  }

  if (!all_match) {
    printf("\n✗ FAIL: LSSS produced different shares!\n");
    printf("\n🔍 ROOT CAUSE FOUND:\n");
    printf("LSSS is non-deterministic! Same policy and secret produce different shares.\n");
    printf("This explains why CCA re-encryption produces different ciphertexts.\n\n");

    printLSSSRows(rows1, "LSSS1 rows");
    printLSSSRows(rows2, "LSSS2 rows");

    ShutdownOpenABE();
    return 1;
  }

  printf("\n✓ PASS: LSSS produces identical shares\n\n");

  // Test 2: More complex policy (OR of ANDs)
  printf("Test 2: Complex policy with OR and AND\n");
  printf("----------------------------------------\n");

  std::string policy_str2 = "(department:engineering and role:developer) or (department:sales and level:senior)";
  std::unique_ptr<OpenABEPolicy> policy2 = createPolicyTree(policy_str2);

  // Reset RNGs to same state
  rng1.reset(new OpenABECTR_DRBG(key));
  rng1->setSeed(nonce);
  rng2.reset(new OpenABECTR_DRBG(key));
  rng2->setSeed(nonce);

  ZP s3 = pairing->randomZP(rng1.get());
  ZP s4 = pairing->randomZP(rng2.get());

  if (!(s3 == s4)) {
    printf("✗ FAIL: Secrets don't match!\n\n");
    ShutdownOpenABE();
    return 1;
  }

  OpenABELSSS lsss3(pairing.get(), rng1.get());
  lsss3.shareSecret(policy2.get(), s3);

  OpenABELSSS lsss4(pairing.get(), rng2.get());
  lsss4.shareSecret(policy2.get(), s4);

  OpenABELSSSRowMap rows3 = lsss3.getRows();
  OpenABELSSSRowMap rows4 = lsss4.getRows();

  printf("Number of shares in LSSS3: %zu\n", rows3.size());
  printf("Number of shares in LSSS4: %zu\n", rows4.size());

  if (rows3.size() != rows4.size()) {
    printf("✗ FAIL: Different number of shares!\n\n");
    ShutdownOpenABE();
    return 1;
  }

  all_match = true;
  for (auto it3 = rows3.begin(); it3 != rows3.end(); ++it3) {
    auto it4 = rows4.find(it3->first);

    if (it4 == rows4.end()) {
      printf("✗ Attribute '%s' not found in LSSS4!\n", it3->first.c_str());
      all_match = false;
      continue;
    }

    if (it3->second.label() != it4->second.label()) {
      printf("✗ Labels differ for '%s'\n", it3->first.c_str());
      all_match = false;
    }

    if (!(it3->second.element() == it4->second.element())) {
      printf("✗ Shares differ for '%s'\n", it3->first.c_str());
      all_match = false;
    }
  }

  if (!all_match) {
    printf("\n✗ FAIL: Complex policy LSSS is non-deterministic!\n\n");
    printLSSSRows(rows3, "LSSS3 rows");
    printLSSSRows(rows4, "LSSS4 rows");
    ShutdownOpenABE();
    return 1;
  }

  printf("✓ PASS: Complex policy LSSS produces identical shares\n\n");

  // Test 3: Repeated LSSS calls with same secret
  printf("Test 3: Repeated LSSS calls\n");
  printf("-----------------------------\n");

  std::string policy_str3 = "attr1 and attr2 and attr3";
  std::unique_ptr<OpenABEPolicy> policy3 = createPolicyTree(policy_str3);

  rng1.reset(new OpenABECTR_DRBG(key));
  rng1->setSeed(nonce);
  ZP s5 = pairing->randomZP(rng1.get());

  OpenABELSSS lsss5(pairing.get(), rng1.get());
  lsss5.shareSecret(policy3.get(), s5);

  rng2.reset(new OpenABECTR_DRBG(key));
  rng2->setSeed(nonce);
  ZP s6 = pairing->randomZP(rng2.get());

  OpenABELSSS lsss6(pairing.get(), rng2.get());
  lsss6.shareSecret(policy3.get(), s6);

  std::unique_ptr<OpenABECTR_DRBG> rng3(new OpenABECTR_DRBG(key));
  rng3->setSeed(nonce);
  ZP s7 = pairing->randomZP(rng3.get());

  OpenABELSSS lsss7(pairing.get(), rng3.get());
  lsss7.shareSecret(policy3.get(), s7);

  OpenABELSSSRowMap rows5 = lsss5.getRows();
  OpenABELSSSRowMap rows6 = lsss6.getRows();
  OpenABELSSSRowMap rows7 = lsss7.getRows();

  printf("Comparing LSSS5 vs LSSS6: ");
  bool match_5_6 = true;
  for (auto it5 = rows5.begin(); it5 != rows5.end(); ++it5) {
    auto it6 = rows6.find(it5->first);
    if (it6 == rows6.end() || !(it5->second.element() == it6->second.element())) {
      match_5_6 = false;
      break;
    }
  }
  printf("%s\n", match_5_6 ? "✓ MATCH" : "✗ MISMATCH");

  printf("Comparing LSSS6 vs LSSS7: ");
  bool match_6_7 = true;
  for (auto it6 = rows6.begin(); it6 != rows6.end(); ++it6) {
    auto it7 = rows7.find(it6->first);
    if (it7 == rows7.end() || !(it6->second.element() == it7->second.element())) {
      match_6_7 = false;
      break;
    }
  }
  printf("%s\n", match_6_7 ? "✓ MATCH" : "✗ MISMATCH");

  if (!match_5_6 || !match_6_7) {
    printf("\n✗ FAIL: Repeated LSSS calls produce different results!\n\n");
    ShutdownOpenABE();
    return 1;
  }

  printf("\n✓ PASS: Repeated LSSS calls are consistent\n\n");

  printf("=== ALL TESTS PASSED ===\n");
  printf("\nConclusion: LSSS is completely deterministic.\n");
  printf("If CCA still fails, the issue must be in:\n");
  printf("  - Ciphertext serialization/comparison\n");
  printf("  - Attribute ordering in ciphertext map\n");
  printf("  - Some other aspect of the CCA encryption flow\n\n");

  ShutdownOpenABE();
  return 0;
}
