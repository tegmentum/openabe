// Simple test that just tries to call setup
#include <iostream>
extern "C" {
#include <relic/relic.h>
}

int main() {
    printf("Initializing RELIC core...\n");
    if (core_init() != RLC_OK) {
        printf("core_init failed\n");
        return 1;
    }
    
    printf("Setting up BLS12-381 curve...\n");
    ep_param_set(B12_P381);
    
    printf("Getting curve order...\n");
    bn_t order;
    bn_new(order);
    ep_curve_get_ord(order);
    
    printf("Order is zero: %d\n", bn_is_zero(order));
    printf("Order digits: %d\n", order->used);
    
    if (!bn_is_zero(order)) {
        printf("Order: ");
        bn_print(order);
        printf("\n");
    } else {
        printf("ERROR: Order is ZERO!\n");
    }
    
    bn_free(order);
    core_clean();
    return 0;
}
