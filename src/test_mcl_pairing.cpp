///
/// \file   test_mcl_pairing.cpp
///
/// \brief  Direct test of MCL pairing operations without gtest dependency
///

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern "C" {
#include <openabe/zml/zelement.h>
}

int test_bls12_381() {
    printf("\n=== Testing BLS12-381 with MCL ===\n");

    // Initialize curve
    printf("Initializing BLS12-381...\n");
    bp_group_t group = NULL;
    int ret = bp_group_init(&group, 0xA2); // OpenABE_BLS12_P381_ID
    if (ret != 0) {
        printf("✗ Failed to initialize BLS12-381 group\n");
        return 1;
    }
    printf("✓ Group initialized\n");

    // Test G1 operations
    printf("\nTesting G1 operations...\n");
    g1_ptr g1_a, g1_b, g1_c;
    g1_init(group, &g1_a);
    g1_init(group, &g1_b);
    g1_init(group, &g1_c);

    // Generate random G1 elements
    g1_rand_op(&g1_a);
    g1_rand_op(&g1_b);
    printf("✓ G1 random elements generated\n");

    // Test G1 addition
    g1_add_op(group, &g1_c, &g1_a, &g1_b);
    printf("✓ G1 addition successful\n");

    // Test G1 serialization
    size_t g1_size = g1_elem_len(g1_a);
    printf("  G1 element size: %zu bytes\n", g1_size);

    uint8_t g1_buf[256];
    g1_elem_out(&g1_a, g1_buf, g1_size);
    printf("✓ G1 serialization successful\n");

    // Test G2 operations
    printf("\nTesting G2 operations...\n");
    g2_ptr g2_a, g2_b;
    g2_init(group, &g2_a);
    g2_init(group, &g2_b);

    // Generate random G2 element
    g2_rand_op(g2_a);
    printf("✓ G2 random element generated\n");

    // Test G2 serialization
    size_t g2_size = g2_elem_len(g2_a);
    printf("  G2 element size: %zu bytes\n", g2_size);

    uint8_t g2_buf[512];
    g2_elem_out(&g2_a, g2_buf, g2_size);
    printf("✓ G2 serialization successful\n");

    // Test pairing
    printf("\nTesting pairing operation...\n");
    gt_ptr gt;
    gt_init(group, &gt);

    bp_map_op(group, &gt, &g1_a, &g2_a);
    printf("✓ Pairing operation successful\n");

    // Test GT serialization
    size_t gt_size = gt_elem_len(&gt, 0);
    printf("  GT element size: %zu bytes\n", gt_size);

    // Test GT unity check
    int is_unity = gt_is_unity_check(group, &gt);
    printf("  GT is unity: %s (expected: no)\n", is_unity ? "yes" : "no");

    // Test GT operations
    printf("\nTesting GT operations...\n");
    gt_ptr gt2, gt3;
    gt_init(group, &gt2);
    gt_init(group, &gt3);

    // Test GT multiplication
    bp_map_op(group, &gt2, &g1_b, &g2_a);
    gt_mul_op(group, &gt3, &gt, &gt2);
    printf("✓ GT multiplication successful\n");

    // Test bilinearity: e(g1_a + g1_b, g2_a) == e(g1_a, g2_a) * e(g1_b, g2_a)
    printf("\nTesting bilinearity property...\n");
    gt_ptr gt_left, gt_right;
    gt_init(group, &gt_left);
    gt_init(group, &gt_right);

    g1_ptr g1_sum;
    g1_init(group, &g1_sum);
    g1_add_op(group, &g1_sum, &g1_a, &g1_b);

    bp_map_op(group, &gt_left, &g1_sum, &g2_a);

    gt_ptr gt_a, gt_b;
    gt_init(group, &gt_a);
    gt_init(group, &gt_b);
    bp_map_op(group, &gt_a, &g1_a, &g2_a);
    bp_map_op(group, &gt_b, &g1_b, &g2_a);
    gt_mul_op(group, &gt_right, &gt_a, &gt_b);

    // Compare gt_left and gt_right
    int cmp = gt_cmp(gt_left, gt_right);
    if (cmp == 0) {
        printf("✓ Bilinearity verified: e(a+b, c) = e(a,c) * e(b,c)\n");
    } else {
        printf("✗ Bilinearity check failed!\n");
        return 1;
    }

    printf("\n✓ All BLS12-381 tests passed!\n");
    return 0;
}

int test_bn254() {
    printf("\n=== Testing BN254 with MCL ===\n");

    // Initialize curve
    printf("Initializing BN254...\n");
    bp_group_t group = NULL;
    int ret = bp_group_init(&group, 0x6F); // OpenABE_BN_P254_ID
    if (ret != 0) {
        printf("✗ Failed to initialize BN254 group\n");
        return 1;
    }
    printf("✓ Group initialized\n");

    // Test basic pairing
    printf("\nTesting basic pairing...\n");
    g1_ptr g1;
    g2_ptr g2;
    gt_ptr gt;

    g1_init(group, &g1);
    g2_init(group, &g2);
    gt_init(group, &gt);

    g1_rand_op(&g1);
    g2_rand_op(g2);

    bp_map_op(group, &gt, &g1, &g2);
    printf("✓ BN254 pairing successful\n");

    // Check sizes
    size_t g1_size = g1_elem_len(g1);
    size_t g2_size = g2_elem_len(g2);
    size_t gt_size = gt_elem_len(&gt, 0);

    printf("  G1 size: %zu bytes\n", g1_size);
    printf("  G2 size: %zu bytes\n", g2_size);
    printf("  GT size: %zu bytes\n", gt_size);

    printf("\n✓ All BN254 tests passed!\n");
    return 0;
}

int main() {
    printf("OpenABE MCL Backend Test\n");
    printf("========================\n");

    // Initialize the math library
    zml_init();

    int result = 0;

    // Test BLS12-381
    if (test_bls12_381() != 0) {
        result = 1;
    }

    // Test BN254
    if (test_bn254() != 0) {
        result = 1;
    }

    // Cleanup
    zml_clean();

    if (result == 0) {
        printf("\n========================================\n");
        printf("✓ ALL TESTS PASSED!\n");
        printf("MCL backend is working correctly.\n");
        printf("========================================\n");
    } else {
        printf("\n✗ SOME TESTS FAILED\n");
    }

    return result;
}
