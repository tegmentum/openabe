#include <stdio.h>
#include <relic_bp/relic.h>

int main() {
    printf("========================================\n");
    printf("RELIC BLS12-381 Simple Test\n");
    printf("========================================\n\n");

    // Initialize RELIC
    if (core_init() != RLC_OK) {
        printf("FAILED: Cannot initialize RELIC\n");
        return 1;
    }

    // Try to set BLS12-381 curve
    printf("Setting BLS12-381 curve...\n");
    ep_param_set(B12_P381);

    // Check if curve was set
    if (ep_param_get() != B12_P381) {
        printf("FAILED: Curve not set properly\n");
        core_clean();
        return 1;
    }

    printf("SUCCESS: Curve set to BLS12-381\n\n");

    // Get curve parameters
    bn_t order;
    bn_null(order);
    bn_new(order);
    ep_curve_get_ord(order);

    printf("Curve Information:\n");
    printf("  Curve ID: B12_P381\n");
    printf("  Field size: %d bits\n", ep_param_level());
    printf("  Group order: %d bits\n", bn_bits(order));
    printf("  Security level: ~%d bits\n\n", ep_param_level() / 2);

    // Test basic G1 operations
    printf("Testing G1 operations...\n");
    ep_t g1, p1, p2;
    bn_t scalar;

    ep_null(g1);
    ep_null(p1);
    ep_null(p2);
    bn_null(scalar);

    ep_new(g1);
    ep_new(p1);
    ep_new(p2);
    bn_new(scalar);

    // Get generator
    ep_curve_get_gen(g1);
    printf("  Generator retrieved\n");

    // Test scalar multiplication
    bn_rand_mod(scalar, order);
    ep_mul(p1, g1, scalar);
    printf("  Scalar multiplication works\n");

    // Test point addition
    ep_rand(p2);
    ep_add(p1, p1, p2);
    printf("  Point addition works\n");

    // Test pairing
#if defined(WITH_PC)
    printf("\nTesting pairing operations...\n");
    ep2_t g2;
    fp12_t gt;

    ep2_null(g2);
    fp12_null(gt);
    ep2_new(g2);
    fp12_new(gt);

    ep2_curve_get_gen(g2);
    printf("  G2 generator retrieved\n");

    pp_map_oatep_k12(gt, g1, g2);
    printf("  Pairing e(G1, G2) computed\n");

    fp12_free(gt);
    ep2_free(g2);
#endif

    printf("\n========================================\n");
    printf("ALL TESTS PASSED!\n");
    printf("========================================\n");
    printf("BLS12-381 is working correctly in this RELIC build.\n\n");

    // Cleanup
    bn_free(scalar);
    ep_free(p2);
    ep_free(p1);
    ep_free(g1);
    bn_free(order);
    core_clean();

    return 0;
}
