#include <stdio.h>
#include <time.h>
#include "relic.h"

void benchmark_curve(int curve_id, const char *curve_name) {
    printf("\n=== Testing %s ===\n", curve_name);

    // Initialize
    if (core_init() != RLC_OK) {
        printf("ERROR: core_init failed\n");
        return;
    }

    ep_param_set(curve_id);

    // Get curve order
    bn_t order;
    bn_null(order);
    bn_new(order);
    ep_curve_get_ord(order);

    if (bn_is_zero(order)) {
        printf("ERROR: Curve order is ZERO!\n");
        bn_free(order);
        core_clean();
        return;
    }

    printf("✅ Curve initialized successfully\n");
    printf("Order: ");
    bn_print(order);
    printf("\n");

    // Benchmark G1 scalar multiplication
    ep_t g, p;
    bn_t k;

    ep_null(g);
    ep_null(p);
    bn_null(k);

    ep_new(g);
    ep_new(p);
    bn_new(k);

    ep_curve_get_gen(g);
    bn_rand_mod(k, order);

    clock_t start = clock();
    int iterations = 1000;

    for (int i = 0; i < iterations; i++) {
        ep_mul(p, g, k);
    }

    clock_t end = clock();
    double time_spent = ((double)(end - start)) / CLOCKS_PER_SEC;
    double avg_time_ms = (time_spent / iterations) * 1000.0;

    printf("G1 Scalar Multiplication:\n");
    printf("  %d iterations: %.3f seconds\n", iterations, time_spent);
    printf("  Average: %.3f ms per operation\n", avg_time_ms);

    // Benchmark pairing (if supported)
    #if defined(WITH_PC)
    printf("\nPairing operations supported: YES\n");

    ep2_t q;
    gt_t e;

    ep2_null(q);
    gt_null(e);
    ep2_new(q);
    gt_new(e);

    ep2_curve_get_gen(q);

    start = clock();
    iterations = 100;

    for (int i = 0; i < iterations; i++) {
        pc_map(e, p, q);
    }

    end = clock();
    time_spent = ((double)(end - start)) / CLOCKS_PER_SEC;
    avg_time_ms = (time_spent / iterations) * 1000.0;

    printf("Pairing e(G1, G2):\n");
    printf("  %d iterations: %.3f seconds\n", iterations, time_spent);
    printf("  Average: %.3f ms per operation\n", avg_time_ms);

    ep2_free(q);
    gt_free(e);
    #else
    printf("\nPairing operations supported: NO\n");
    #endif

    // Cleanup
    ep_free(g);
    ep_free(p);
    bn_free(k);
    bn_free(order);
    core_clean();
}

int main() {
    printf("RELIC BLS12-381 vs BN254 Benchmark\n");
    printf("===================================\n");

    // Test BN254
    benchmark_curve(BN_P254, "BN-P254 (254-bit, ~100-bit security)");

    // Test BLS12-381
    benchmark_curve(B12_P381, "BLS12-381 (381-bit, 128-bit security)");

    printf("\n=== Benchmark Complete ===\n");
    return 0;
}
