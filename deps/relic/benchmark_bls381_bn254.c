#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <sys/time.h>

// Use BP-labeled RELIC headers (BLS12-381 pairing library)
#include <relic_bp/relic.h>

// Timing helper
static inline double get_time() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec + tv.tv_usec / 1000000.0;
}

void benchmark_curve(const char *curve_name, int curve_id, int iterations) {
    printf("\n========================================\n");
    printf("Benchmarking: %s\n", curve_name);
    printf("========================================\n\n");

    // Set curve
    ep_param_set(curve_id);

    // Verify curve was set
    if (ep_param_get() != curve_id) {
        printf("❌ Failed to set curve %s\n", curve_name);
        return;
    }

    // Get curve parameters
    bn_t order;
    bn_null(order);
    bn_new(order);
    ep_curve_get_ord(order);

    printf("Curve: %s\n", curve_name);
    printf("Field size: %d bits\n", ep_param_level());
    printf("Group order: %zu bits\n", (size_t)bn_bits(order));
    printf("Security level: ~%d bits\n", ep_param_level() / 2);
    printf("Iterations: %d\n\n", iterations);

    // Benchmark 1: G1 Scalar Multiplication
    printf("[1] G1 Scalar Multiplication\n");
    ep_t g1, result;
    bn_t scalar;
    ep_null(g1);
    ep_null(result);
    bn_null(scalar);
    ep_new(g1);
    ep_new(result);
    bn_new(scalar);

    ep_curve_get_gen(g1);
    bn_rand_mod(scalar, order);

    double start = get_time();
    for (int i = 0; i < iterations; i++) {
        ep_mul(result, g1, scalar);
    }
    double elapsed = get_time() - start;
    double avg = (elapsed / iterations) * 1000.0;

    printf("   Total: %.3f ms\n", elapsed * 1000.0);
    printf("   Average: %.3f ms per operation\n", avg);
    printf("   Throughput: %.0f ops/sec\n\n", iterations / elapsed);

    // Benchmark 2: G1 Point Addition
    printf("[2] G1 Point Addition\n");
    ep_t p1, p2;
    ep_null(p1);
    ep_null(p2);
    ep_new(p1);
    ep_new(p2);

    ep_rand(p1);
    ep_rand(p2);

    start = get_time();
    for (int i = 0; i < iterations * 10; i++) {  // 10x more iterations
        ep_add(result, p1, p2);
    }
    elapsed = get_time() - start;
    avg = (elapsed / (iterations * 10)) * 1000.0;

    printf("   Total: %.3f ms (%d ops)\n", elapsed * 1000.0, iterations * 10);
    printf("   Average: %.6f ms per operation\n", avg);
    printf("   Throughput: %.0f ops/sec\n\n", (iterations * 10) / elapsed);

    // Benchmark 3: G1 Multi-Exponentiation (if available)
    printf("[3] G1 Multi-Exponentiation (2 bases)\n");
    ep_t bases[2];
    bn_t exps[2];
    for (int i = 0; i < 2; i++) {
        ep_null(bases[i]);
        bn_null(exps[i]);
        ep_new(bases[i]);
        bn_new(exps[i]);
        ep_rand(bases[i]);
        bn_rand_mod(exps[i], order);
    }

    start = get_time();
    for (int i = 0; i < iterations / 2; i++) {  // Slower operation
        ep_mul_sim(result, bases[0], exps[0], bases[1], exps[1]);
    }
    elapsed = get_time() - start;
    avg = (elapsed / (iterations / 2)) * 1000.0;

    printf("   Total: %.3f ms\n", elapsed * 1000.0);
    printf("   Average: %.3f ms per operation\n", avg);
    printf("   Throughput: %.0f ops/sec\n\n", (iterations / 2) / elapsed);

    // Check if pairing is available
    int has_pairing = 0;
#if defined(WITH_PC)
    // Try to initialize pairing
    fp12_t gt;
    fp12_null(gt);
    fp12_new(gt);
    has_pairing = 1;
    fp12_free(gt);
#endif

    if (has_pairing) {
        printf("[4] Pairing e(G1, G2) → GT\n");

        ep2_t g2;
        fp12_t result_gt;
        ep2_null(g2);
        fp12_null(result_gt);
        ep2_new(g2);
        fp12_new(result_gt);

        ep2_curve_get_gen(g2);

        start = get_time();
        for (int i = 0; i < iterations / 5; i++) {  // Pairings are slow
            pp_map_oatep_k12(result_gt, g1, g2);
        }
        elapsed = get_time() - start;
        avg = (elapsed / (iterations / 5)) * 1000.0;

        printf("   Total: %.3f ms\n", elapsed * 1000.0);
        printf("   Average: %.3f ms per operation\n", avg);
        printf("   Throughput: %.0f ops/sec\n\n", (iterations / 5) / elapsed);

        // Benchmark 5: GT Exponentiation
        printf("[5] GT Exponentiation\n");
        fp12_t gt_base, gt_result;
        fp12_null(gt_base);
        fp12_null(gt_result);
        fp12_new(gt_base);
        fp12_new(gt_result);

        // Get a random GT element via pairing
        pp_map_oatep_k12(gt_base, g1, g2);

        start = get_time();
        for (int i = 0; i < iterations; i++) {
            fp12_exp(gt_result, gt_base, scalar);
        }
        elapsed = get_time() - start;
        avg = (elapsed / iterations) * 1000.0;

        printf("   Total: %.3f ms\n", elapsed * 1000.0);
        printf("   Average: %.3f ms per operation\n", avg);
        printf("   Throughput: %.0f ops/sec\n\n", iterations / elapsed);

        fp12_free(gt_base);
        fp12_free(gt_result);
        fp12_free(result_gt);
        ep2_free(g2);
    } else {
        printf("[4] Pairing operations: Not available\n\n");
    }

    // Cleanup
    for (int i = 0; i < 2; i++) {
        ep_free(bases[i]);
        bn_free(exps[i]);
    }
    ep_free(p1);
    ep_free(p2);
    ep_free(result);
    ep_free(g1);
    bn_free(scalar);
    bn_free(order);
}

int main() {
    printf("========================================\n");
    printf("RELIC 0.7.0 Curve Benchmark\n");
    printf("========================================\n");
    printf("Testing BN254 vs BLS12-381 Performance\n\n");

    // Initialize RELIC
    if (core_init() != RLC_OK) {
        printf("❌ Failed to initialize RELIC\n");
        return 1;
    }

    const int ITERATIONS = 100;

    // Benchmark BN254 (BN-P254)
    printf("\n*** TESTING BN254 (Barreto-Naehrig 254-bit) ***\n");
    benchmark_curve("BN254 (BN-P254)", BN_P254, ITERATIONS);

    // Benchmark BLS12-381
    printf("\n*** TESTING BLS12-381 (Barreto-Lynn-Scott 381-bit) ***\n");
    benchmark_curve("BLS12-381 (B12-P381)", B12_P381, ITERATIONS);

    // Comparison Summary
    printf("\n========================================\n");
    printf("Performance Comparison Summary\n");
    printf("========================================\n\n");

    printf("Curve Characteristics:\n");
    printf("┌──────────────┬────────────┬────────────┬────────────┐\n");
    printf("│ Curve        │ Field Size │ Security   │ Status     │\n");
    printf("├──────────────┼────────────┼────────────┼────────────┤\n");
    printf("│ BN254        │ 254-bit    │ ~100-bit   │ Deprecated │\n");
    printf("│ BLS12-381    │ 381-bit    │ 128-bit    │ Standard   │\n");
    printf("└──────────────┴────────────┴────────────┴────────────┘\n\n");

    printf("Expected Performance:\n");
    printf("- BLS12-381 is ~30-50%% slower than BN254 for most operations\n");
    printf("- BLS12-381 provides +28%% more security bits (100→128 bits)\n");
    printf("- Trade-off: Worth it for future-proof 128-bit security\n\n");

    printf("Recommendations:\n");
    printf("✓ Use BLS12-381 for new applications (128-bit security)\n");
    printf("✓ BN254 is deprecated due to advances in discrete log attacks\n");
    printf("✓ Performance overhead of BLS12-381 is acceptable\n\n");

    core_clean();

    printf("========================================\n");
    printf("Benchmark Complete!\n");
    printf("========================================\n\n");

    return 0;
}
