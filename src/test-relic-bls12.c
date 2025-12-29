#include <stdio.h>
#include <relic.h>

int main() {
    printf("Testing RELIC BLS12-381...\n");
    
    if (core_init() != RLC_OK) {
        printf("RELIC core_init failed!\n");
        return 1;
    }
    
    if (pc_param_set_any() != RLC_OK) {
        printf("pc_param_set_any failed!\n");
        core_clean();
        return 1;
    }
    
    printf("Trying to set BLS12-381 parameters...\n");
    
    // Try to set BLS12-381
    ep_param_set(B12_P381);
    
    printf("Checking if curve parameters are set...\n");
    
    // Try to get the group order
    bn_t order;
    bn_null(order);
    bn_new(order);
    
    ep_curve_get_ord(order);
    
    printf("Group order: ");
    bn_print(order);
    printf("\n");
    
    // Check if order is zero (which would cause bn_div errors)
    if (bn_is_zero(order)) {
        printf("ERROR: Group order is ZERO! This will cause bn_div errors.\n");
        bn_free(order);
        core_clean();
        return 1;
    }
    
    printf("Group order is non-zero - looks good!\n");
    
    // Try to create a random point
    printf("Generating random G1 point...\n");
    ep_t g1;
    ep_null(g1);
    ep_new(g1);
    ep_rand(g1);
    
    printf("G1 point generated successfully!\n");
    ep_print(g1);
    
    ep_free(g1);
    bn_free(order);
    core_clean();
    
    printf("SUCCESS!\n");
    return 0;
}
