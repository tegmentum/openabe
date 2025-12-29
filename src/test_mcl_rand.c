#include <stdio.h>
#include <string.h>
#include <mcl/bn.h>

int main() {
    // Initialize MCL
    int ret = mclBn_init(mclBn_CurveFp254BNb, MCLBN_COMPILED_TIME_VAR);
    if (ret != 0) {
        printf("MCL init failed: %d\n", ret);
        return 1;
    }
    printf("MCL initialized successfully\n");

    // Test hashAndMapTo for G1
    mclBnG1 g1;
    ret = mclBnG1_hashAndMapTo(&g1, "test", 4);
    printf("mclBnG1_hashAndMapTo returned: %d\n", ret);

    // Check if zero
    int isZero = mclBnG1_isZero(&g1);
    printf("G1 isZero: %d\n", isZero);

    // Get string representation
    char buf[1024];
    size_t size = mclBnG1_getStr(buf, sizeof(buf), &g1, 10);
    printf("G1 string (size %zu): %s\n", size, buf);

    // Test with random scalar multiplication
    mclBnFr r;
    mclBnFr_setByCSPRNG(&r);

    mclBnG1 g1_rand;
    mclBnG1_hashAndMapTo(&g1_rand, "base", 4);
    mclBnG1_mul(&g1_rand, &g1_rand, &r);

    isZero = mclBnG1_isZero(&g1_rand);
    printf("G1 after mul isZero: %d\n", isZero);

    size = mclBnG1_getStr(buf, sizeof(buf), &g1_rand, 10);
    printf("G1 after mul string (size %zu): %s\n", size, buf);

    return 0;
}
