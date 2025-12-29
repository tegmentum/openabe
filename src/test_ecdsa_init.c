#include <stdio.h>
#include <mcl/ecdsa.h>

int main() {
    printf("Testing MCL ECDSA initialization...\n");

    int ret = ecdsaInit();
    printf("ecdsaInit() returned: %d\n", ret);

    if (ret == 0) {
        printf("SUCCESS: MCL ECDSA initialized\n");
        return 0;
    } else {
        printf("FAIL: MCL ECDSA initialization failed\n");
        return 1;
    }
}
