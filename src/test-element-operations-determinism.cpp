/*
 * Test to verify cryptographic element operations are deterministic
 *
 * This test verifies that element operations (exponentiation, multiplication,
 * division) produce identical results when given the same operands. This is
 * critical for CCA verification where re-encryption must produce identical
 * ciphertexts.
 *
 * Tests:
 * 1. ZP exponentiation: g^s with same g and s
 * 2. G1 exponentiation: g1^zp with same g1 and zp
 * 3. G2 exponentiation: g2^zp with same g2 and zp
 * 4. GT exponentiation: gt^zp with same gt and zp
 * 5. G1 multiplication: g1 * g2
 * 6. G2 multiplication: g1 * g2
 * 7. GT multiplication: gt1 * gt2
 * 8. G1 division: g1 / g2
 * 9. Combined operations (simulating CP-ABE encryption flow)
 */

#include <stdio.h>
#include <string.h>
#include <openabe/openabe.h>

using namespace oabe;

int main() {
  printf("\n=== Element Operations Determinism Test ===\n\n");

  // Initialize OpenABE
  InitializeOpenABE();

  // Create pairing context
  std::unique_ptr<OpenABEPairing> pairing(new OpenABEPairing("BN254"));

  // Create an RNG for generating test elements
  std::unique_ptr<OpenABERNG> rng(new OpenABERNG);

  // Test 1: G1 exponentiation determinism
  printf("Test 1: G1 exponentiation (g1^zp)\n");
  printf("------------------------------------\n");

  G1 g1_base = pairing->randomG1(rng.get());
  ZP exp1 = pairing->randomZP(rng.get());

  // Perform exponentiation twice with same operands
  G1 result1_a = g1_base.exp(exp1);
  G1 result1_b = g1_base.exp(exp1);

  printf("g1_base^exp1 (first):  ");
  if (result1_a == result1_b) {
    printf("✓ MATCH\n");
  } else {
    printf("✗ MISMATCH!\n");
    printf("\n🔍 ROOT CAUSE FOUND:\n");
    printf("G1 exponentiation is non-deterministic!\n");
    printf("This explains why CCA re-encryption produces different ciphertexts.\n\n");
    ShutdownOpenABE();
    return 1;
  }

  // Test with different base and exponent
  G1 g1_base2 = pairing->randomG1(rng.get());
  ZP exp2 = pairing->randomZP(rng.get());

  G1 result2_a = g1_base2.exp(exp2);
  G1 result2_b = g1_base2.exp(exp2);

  printf("g1_base2^exp2 (second): ");
  if (result2_a == result2_b) {
    printf("✓ MATCH\n");
  } else {
    printf("✗ MISMATCH!\n\n");
    ShutdownOpenABE();
    return 1;
  }

  printf("\n✓ PASS: G1 exponentiation is deterministic\n\n");

  // Test 2: G2 exponentiation determinism
  printf("Test 2: G2 exponentiation (g2^zp)\n");
  printf("------------------------------------\n");

  G2 g2_base = pairing->randomG2(rng.get());
  ZP exp3 = pairing->randomZP(rng.get());

  G2 result3_a = g2_base.exp(exp3);
  G2 result3_b = g2_base.exp(exp3);

  printf("g2_base^exp3 (first):  ");
  if (result3_a == result3_b) {
    printf("✓ MATCH\n");
  } else {
    printf("✗ MISMATCH!\n");
    printf("\n🔍 ROOT CAUSE FOUND:\n");
    printf("G2 exponentiation is non-deterministic!\n\n");
    ShutdownOpenABE();
    return 1;
  }

  G2 g2_base2 = pairing->randomG2(rng.get());
  ZP exp4 = pairing->randomZP(rng.get());

  G2 result4_a = g2_base2.exp(exp4);
  G2 result4_b = g2_base2.exp(exp4);

  printf("g2_base2^exp4 (second): ");
  if (result4_a == result4_b) {
    printf("✓ MATCH\n");
  } else {
    printf("✗ MISMATCH!\n\n");
    ShutdownOpenABE();
    return 1;
  }

  printf("\n✓ PASS: G2 exponentiation is deterministic\n\n");

  // Test 3: GT exponentiation determinism
  printf("Test 3: GT exponentiation (gt^zp)\n");
  printf("-----------------------------------\n");

  G1 g1_for_pairing = pairing->randomG1(rng.get());
  G2 g2_for_pairing = pairing->randomG2(rng.get());
  GT gt_base = pairing->pairing(g1_for_pairing, g2_for_pairing);
  ZP exp5 = pairing->randomZP(rng.get());

  GT result5_a = gt_base.exp(exp5);
  GT result5_b = gt_base.exp(exp5);

  printf("gt_base^exp5 (first):  ");
  if (result5_a == result5_b) {
    printf("✓ MATCH\n");
  } else {
    printf("✗ MISMATCH!\n");
    printf("\n🔍 ROOT CAUSE FOUND:\n");
    printf("GT exponentiation is non-deterministic!\n");
    printf("This is critical - CP-ABE heavily uses GT exponentiation.\n\n");
    ShutdownOpenABE();
    return 1;
  }

  G1 g1_for_pairing2 = pairing->randomG1(rng.get());
  G2 g2_for_pairing2 = pairing->randomG2(rng.get());
  GT gt_base2 = pairing->pairing(g1_for_pairing2, g2_for_pairing2);
  ZP exp6 = pairing->randomZP(rng.get());

  GT result6_a = gt_base2.exp(exp6);
  GT result6_b = gt_base2.exp(exp6);

  printf("gt_base2^exp6 (second): ");
  if (result6_a == result6_b) {
    printf("✓ MATCH\n");
  } else {
    printf("✗ MISMATCH!\n\n");
    ShutdownOpenABE();
    return 1;
  }

  printf("\n✓ PASS: GT exponentiation is deterministic\n\n");

  // Test 4: G1 multiplication determinism
  printf("Test 4: G1 multiplication (g1 * g2)\n");
  printf("-------------------------------------\n");

  G1 g1_a = pairing->randomG1(rng.get());
  G1 g1_b = pairing->randomG1(rng.get());

  G1 mul1_a = g1_a * g1_b;
  G1 mul1_b = g1_a * g1_b;

  printf("g1_a * g1_b (first):  ");
  if (mul1_a == mul1_b) {
    printf("✓ MATCH\n");
  } else {
    printf("✗ MISMATCH!\n");
    printf("\n🔍 ROOT CAUSE FOUND:\n");
    printf("G1 multiplication is non-deterministic!\n\n");
    ShutdownOpenABE();
    return 1;
  }

  G1 g1_c = pairing->randomG1(rng.get());
  G1 g1_d = pairing->randomG1(rng.get());

  G1 mul2_a = g1_c * g1_d;
  G1 mul2_b = g1_c * g1_d;

  printf("g1_c * g1_d (second): ");
  if (mul2_a == mul2_b) {
    printf("✓ MATCH\n");
  } else {
    printf("✗ MISMATCH!\n\n");
    ShutdownOpenABE();
    return 1;
  }

  printf("\n✓ PASS: G1 multiplication is deterministic\n\n");

  // Test 5: G2 multiplication determinism
  printf("Test 5: G2 multiplication (g2 * g2)\n");
  printf("-------------------------------------\n");

  G2 g2_a = pairing->randomG2(rng.get());
  G2 g2_b = pairing->randomG2(rng.get());

  G2 mul3_a = g2_a * g2_b;
  G2 mul3_b = g2_a * g2_b;

  printf("g2_a * g2_b (first):  ");
  if (mul3_a == mul3_b) {
    printf("✓ MATCH\n");
  } else {
    printf("✗ MISMATCH!\n");
    printf("\n🔍 ROOT CAUSE FOUND:\n");
    printf("G2 multiplication is non-deterministic!\n\n");
    ShutdownOpenABE();
    return 1;
  }

  printf("\n✓ PASS: G2 multiplication is deterministic\n\n");

  // Test 6: GT multiplication determinism
  printf("Test 6: GT multiplication (gt * gt)\n");
  printf("-------------------------------------\n");

  G1 g1_gt_a = pairing->randomG1(rng.get());
  G2 g2_gt_a = pairing->randomG2(rng.get());
  GT gt_a = pairing->pairing(g1_gt_a, g2_gt_a);

  G1 g1_gt_b = pairing->randomG1(rng.get());
  G2 g2_gt_b = pairing->randomG2(rng.get());
  GT gt_b = pairing->pairing(g1_gt_b, g2_gt_b);

  GT mul4_a = gt_a * gt_b;
  GT mul4_b = gt_a * gt_b;

  printf("gt_a * gt_b (first):  ");
  if (mul4_a == mul4_b) {
    printf("✓ MATCH\n");
  } else {
    printf("✗ MISMATCH!\n");
    printf("\n🔍 ROOT CAUSE FOUND:\n");
    printf("GT multiplication is non-deterministic!\n\n");
    ShutdownOpenABE();
    return 1;
  }

  printf("\n✓ PASS: GT multiplication is deterministic\n\n");

  // Test 7: G1 division determinism
  printf("Test 7: G1 division (g1 / g2)\n");
  printf("-------------------------------\n");

  G1 g1_e = pairing->randomG1(rng.get());
  G1 g1_f = pairing->randomG1(rng.get());

  G1 div1_a = g1_e / g1_f;
  G1 div1_b = g1_e / g1_f;

  printf("g1_e / g1_f (first):  ");
  if (div1_a == div1_b) {
    printf("✓ MATCH\n");
  } else {
    printf("✗ MISMATCH!\n");
    printf("\n🔍 ROOT CAUSE FOUND:\n");
    printf("G1 division is non-deterministic!\n\n");
    ShutdownOpenABE();
    return 1;
  }

  printf("\n✓ PASS: G1 division is deterministic\n\n");

  // Test 8: GT division determinism
  printf("Test 8: GT division (gt / gt)\n");
  printf("-------------------------------\n");

  G1 g1_gt_c = pairing->randomG1(rng.get());
  G2 g2_gt_c = pairing->randomG2(rng.get());
  GT gt_c = pairing->pairing(g1_gt_c, g2_gt_c);

  G1 g1_gt_d = pairing->randomG1(rng.get());
  G2 g2_gt_d = pairing->randomG2(rng.get());
  GT gt_d = pairing->pairing(g1_gt_d, g2_gt_d);

  GT div2_a = gt_c / gt_d;
  GT div2_b = gt_c / gt_d;

  printf("gt_c / gt_d (first):  ");
  if (div2_a == div2_b) {
    printf("✓ MATCH\n");
  } else {
    printf("✗ MISMATCH!\n");
    printf("\n🔍 ROOT CAUSE FOUND:\n");
    printf("GT division is non-deterministic!\n\n");
    ShutdownOpenABE();
    return 1;
  }

  printf("\n✓ PASS: GT division is deterministic\n\n");

  // Test 9: Combined operations (simulating CP-ABE pattern)
  printf("Test 9: Combined operations (CP-ABE encryption pattern)\n");
  printf("--------------------------------------------------------\n");

  // Simulate: C' = g^s, C_i = (g^a_i * h^r_i)^s
  G1 g = pairing->randomG1(rng.get());
  G1 h = pairing->randomG1(rng.get());
  ZP s = pairing->randomZP(rng.get());
  ZP a_i = pairing->randomZP(rng.get());
  ZP r_i = pairing->randomZP(rng.get());

  // First computation
  G1 Cprime_1 = g.exp(s);
  G1 g_ai = g.exp(a_i);
  G1 h_ri = h.exp(r_i);
  G1 combined1 = g_ai * h_ri;
  G1 Ci_1 = combined1.exp(s);

  // Second computation (same inputs)
  G1 Cprime_2 = g.exp(s);
  G1 g_ai_2 = g.exp(a_i);
  G1 h_ri_2 = h.exp(r_i);
  G1 combined2 = g_ai_2 * h_ri_2;
  G1 Ci_2 = combined2.exp(s);

  printf("C' = g^s:              ");
  if (Cprime_1 == Cprime_2) {
    printf("✓ MATCH\n");
  } else {
    printf("✗ MISMATCH!\n\n");
    ShutdownOpenABE();
    return 1;
  }

  printf("C_i = (g^a_i * h^r_i)^s: ");
  if (Ci_1 == Ci_2) {
    printf("✓ MATCH\n");
  } else {
    printf("✗ MISMATCH!\n");
    printf("\n🔍 ROOT CAUSE FOUND:\n");
    printf("Combined CP-ABE operations are non-deterministic!\n\n");
    ShutdownOpenABE();
    return 1;
  }

  printf("\n✓ PASS: Combined operations are deterministic\n\n");

  // Test 10: Pairing operation determinism
  printf("Test 10: Pairing operation (e(g1, g2))\n");
  printf("----------------------------------------\n");

  G1 pair_g1 = pairing->randomG1(rng.get());
  G2 pair_g2 = pairing->randomG2(rng.get());

  GT pair_result1 = pairing->pairing(pair_g1, pair_g2);
  GT pair_result2 = pairing->pairing(pair_g1, pair_g2);

  printf("e(g1, g2) (first):  ");
  if (pair_result1 == pair_result2) {
    printf("✓ MATCH\n");
  } else {
    printf("✗ MISMATCH!\n");
    printf("\n🔍 ROOT CAUSE FOUND:\n");
    printf("Pairing operation is non-deterministic!\n");
    printf("This is critical - pairing is fundamental to CP-ABE.\n\n");
    ShutdownOpenABE();
    return 1;
  }

  printf("\n✓ PASS: Pairing operation is deterministic\n\n");

  printf("=== ALL TESTS PASSED ===\n");
  printf("\nConclusion: All element operations are deterministic.\n");
  printf("If CCA still fails, the issue must be in:\n");
  printf("  - LSSS (policy evaluation)\n");
  printf("  - Hash-to-element operations\n");
  printf("  - Ciphertext serialization/comparison\n");
  printf("  - Something else in the encryption algorithm logic\n\n");

  ShutdownOpenABE();
  return 0;
}
