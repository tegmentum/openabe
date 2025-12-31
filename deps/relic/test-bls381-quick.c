#include <stdio.h>
#include "relic.h"

int main() {
    printf("Initializing RELIC core...\\n");
    if (core_init() != RLC_OK) {
        printf("core_init failed\\n");
        return 1;
    }

    printf("Setting EP parameters to BLS12-381...\\n");
    ep_param_set(B12_P381);

    printf("Checking curve order...\\n");
    bn_t order;
    bn_null(order);
    bn_new(order);

    ep_curve_get_ord(order);

    if (bn_is_zero(order)) {
        printf("ERROR: Curve order is ZERO!\\n");
        bn_free(order);
        core_clean();
        return 1;
    }

    printf("SUCCESS: BLS12-381 curve order is non-zero\\n");
    printf("Order: ");
    bn_print(order);
    printf("\\n");

    bn_free(order);
    core_clean();
    return 0;
}
