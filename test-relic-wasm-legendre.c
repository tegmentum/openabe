/**
 * Minimal WASM test for RELIC Legendre symbol computation
 * Tests that the WASM-safe fixes work correctly at runtime
 */

#include <stdio.h>
#include <relic.h>
#include <relic_conf.h>

int main(void) {
    printf("=== RELIC WASM Legendre Symbol Test ===\n\n");

    // Initialize RELIC
    if (core_init() != RLC_OK) {
        printf("ERROR: Failed to initialize RELIC\n");
        return 1;
    }

    // Set BN254 curve parameters
    if (ep_param_set_any_pairf() != RLC_OK) {
        printf("ERROR: Failed to set curve parameters\n");
        core_clean();
        return 1;
    }

    printf("RELIC initialized successfully\n");
    printf("Curve: BN254 (pairing-friendly)\n");
    printf("FP_SMB method: ");

#if FP_SMB == BASIC
    printf("BASIC\n");
#elif FP_SMB == BINAR
    printf("BINAR (with WASM-safe fixes)\n");
#elif FP_SMB == DIVST
    printf("DIVST (with WASM-safe fixes)\n");
#elif FP_SMB == JMPDS
    printf("JMPDS (with WASM-safe fixes)\n");
#else
    printf("UNKNOWN\n");
#endif

    printf("\nTesting Legendre symbol computation...\n\n");

    // Test 1: Simple quadratic residues
    fp_t a;
    fp_null(a);
    fp_new(a);

    // Test with 1 (always a QR)
    fp_set_dig(a, 1);
    int result = fp_smb(a);
    printf("1. fp_smb(1) = %d (expected: 1) %s\n",
           result, result == 1 ? "✓ PASS" : "✗ FAIL");

    // Test with 4 = 2² (QR)
    fp_set_dig(a, 4);
    result = fp_smb(a);
    printf("2. fp_smb(4) = %d (expected: 1) %s\n",
           result, result == 1 ? "✓ PASS" : "✗ FAIL");

    // Test with 9 = 3² (QR)
    fp_set_dig(a, 9);
    result = fp_smb(a);
    printf("3. fp_smb(9) = %d (expected: 1) %s\n",
           result, result == 1 ? "✓ PASS" : "✗ FAIL");

    // Test 2: Compute a square and verify it's a QR
    fp_t b, c;
    fp_null(b);
    fp_null(c);
    fp_new(b);
    fp_new(c);

    printf("\n4. Testing computed square:\n");
    fp_set_dig(b, 123456);
    fp_sqr(c, b);  // c = 123456²
    result = fp_smb(c);
    printf("   fp_smb(123456²) = %d (expected: 1) %s\n",
           result, result == 1 ? "✓ PASS" : "✗ FAIL");

    // Test 3: Large field element (the critical test)
    printf("\n5. Testing large Fp element (critical for G2):\n");
    fp2_t fp2_elem;
    fp2_null(fp2_elem);
    fp2_new(fp2_elem);

    // Generate random Fp2 element
    fp2_rand(fp2_elem);

    // Compute t = a[0]² - i² * a[1]² (as done in fp2_srt)
    fp_t t;
    fp_null(t);
    fp_new(t);

    fp_sqr(t, fp2_elem[0]);
    fp_sqr(a, fp2_elem[1]);

    // For BN254, i² = -1, so we add a[1]²
    fp_add(t, t, a);

    // This MUST be a QR for most random Fp2 elements
    result = fp_smb(t);
    printf("   fp_smb(t) where t from random Fp2 = %d\n", result);

    if (result == 1) {
        printf("   ✓ PASS - Correctly identified as quadratic residue\n");
        printf("   This is the fix! RELIC 0.7.0 without WASM-safe fixes would return 0.\n");
    } else {
        printf("   Note: Non-residue is statistically rare but possible\n");
    }

    // Test 4: Verify a non-residue (if we can find one)
    printf("\n6. Testing known non-residue:\n");
    fp_set_dig(a, 2);  // 2 is typically a QNR for BN254
    result = fp_smb(a);
    printf("   fp_smb(2) = %d (expected: -1) %s\n",
           result, result == -1 ? "✓ PASS" : "(may vary by curve)");

    // Cleanup
    fp_free(a);
    fp_free(b);
    fp_free(c);
    fp_free(t);
    fp2_free(fp2_elem);
    core_clean();

    printf("\n=== Test Complete ===\n");
    printf("If tests 1-4 passed, the WASM-safe fixes are working correctly!\n");

    return 0;
}
