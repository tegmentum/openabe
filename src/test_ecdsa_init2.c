#include <stdio.h>
#include <mcl/bn.h>
#include <mcl/ecdsa.h>

int main() {
    printf("Testing MCL initialization sequence...\n");

    // Try initializing MCL BN first
    printf("1. Initializing MCL BN254...\n");
    int ret = mclBn_init(MCL_BN254, MCLBN_COMPILED_TIME_VAR);
    printf("   mclBn_init() returned: %d\n", ret);

    if (ret != 0) {
        printf("FAIL: MCL BN initialization failed\n");
        return 1;
    }

    printf("SUCCESS: MCL BN254 initialized\n\n");

    // Now try ECDSA
    printf("2. Initializing MCL ECDSA...\n");
    ret = ecdsaInit();
    printf("   ecdsaInit() returned: %d\n", ret);

    if (ret == 0) {
        printf("SUCCESS: MCL ECDSA initialized\n");
        return 0;
    } else {
        printf("FAIL: MCL ECDSA initialization failed\n");
        return 1;
    }
}
