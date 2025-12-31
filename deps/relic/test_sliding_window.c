/*
 * Minimal test case to reproduce RELIC 0.7.0 buffer overflow bug
 * in ep_mul_slide() function with BN254 curve.
 */
#include <stdio.h>
#include <relic/relic.h>

int main(void) {
    core_init();

    if (pc_param_set_any() != RLC_OK) {
        core_clean();
        fprintf(stderr, "Error: Failed to set pairing parameters\n");
        return 1;
    }

    ep_t p, r;
    bn_t k, n;

    ep_null(p);
    ep_null(r);
    bn_null(k);
    bn_null(n);

    ep_new(p);
    ep_new(r);
    bn_new(k);
    bn_new(n);

    // Get the group order
    ep_curve_get_ord(n);

    printf("Testing ep_mul_slide with BN254 curve...\n");
    printf("Group order bits: %d\n", bn_bits(n));
    printf("RLC_FP_BITS: %d\n", RLC_FP_BITS);
    printf("RLC_BN_BITS: %d\n", RLC_BN_BITS);

    // Generate random point and scalar
    ep_rand(p);
    bn_rand_mod(k, n);

    printf("Scalar bits: %d\n", bn_bits(k));
    printf("Calling ep_mul_slide...\n");

    // This should trigger buffer overflow if using original buggy code
    ep_mul_slide(r, p, k);

    printf("SUCCESS: ep_mul_slide completed without error\n");

    ep_free(p);
    ep_free(r);
    bn_free(k);
    bn_free(n);

    core_clean();
    return 0;
}
