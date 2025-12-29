///
/// \file   zelement_ec_stubs_mcl.cpp
///
/// \brief  Stub implementations for EC operations when using MCL backend.
///         These are not used in practice but needed for linking.
///
/// \author OpenABE Contributors
///

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Forward declare the types we need WITHOUT including MCL headers
// to avoid C++/C linkage conflicts
extern "C" {

// Forward declarations for EC types
typedef void* ec_group_t;
typedef void* ec_point_t;
typedef void* bignum_t;

#ifdef EC_WITH_MCL

// Stub implementations - EC operations are not supported with MCL backend

int ec_group_init(ec_group_t *group, uint8_t id) {
    (void)id;
    *group = (void*)0x1;
    return 0;
}

void ec_get_order(ec_group_t group, bignum_t order) {
    (void)group;
    // MCL backend is designed for pairing-based cryptography (BLS12-381, BN254)
    // and does not support traditional EC operations like ECDSA on secp256k1.
    // The bignum_t type (mclBnFr) is tied to the scalar field of pairing curves,
    // not arbitrary EC curves. EC operations should use OpenSSL backend instead.
    //
    // Initialize order to zero to indicate failure/unsupported operation
    memset(&order, 0, sizeof(order));
    fprintf(stderr, "ERROR: ec_get_order not supported with MCL backend - use OpenSSL for EC operations\n");
}

void ec_point_init(ec_group_t group, ec_point_t *e) {
    (void)group;
    *e = NULL;
}

void ec_point_copy(ec_group_t group, ec_point_t to, const ec_point_t from) {
    (void)group;
    (void)to;
    (void)from;
}

void ec_point_set_inf(ec_group_t group, ec_point_t p) {
    (void)group;
    (void)p;
}

int ec_point_cmp(ec_group_t group, const ec_point_t a, const ec_point_t b) {
    (void)group;
    (void)a;
    (void)b;
    return 0;
}

int ec_point_is_inf(ec_group_t group, ec_point_t p) {
    (void)group;
    (void)p;
    return 1;
}

void ec_get_generator(ec_group_t group, ec_point_t p) {
    (void)group;
    (void)p;
}

void ec_get_coordinates(ec_group_t group, bignum_t x, bignum_t y, const ec_point_t p) {
    (void)group;
    (void)x;
    (void)y;
    (void)p;
}

int ec_convert_to_point(ec_group_t group, ec_point_t p, uint8_t *xstr, int len) {
    (void)group;
    (void)p;
    (void)xstr;
    (void)len;
    return 0;
}

int ec_point_is_on_curve(ec_group_t group, ec_point_t p) {
    (void)group;
    (void)p;
    return 1;
}

void ec_point_add(ec_group_t g, ec_point_t r, const ec_point_t x, const ec_point_t y) {
    (void)g;
    (void)r;
    (void)x;
    (void)y;
}

void ec_point_mul(ec_group_t g, ec_point_t r, const ec_point_t x, const bignum_t y) {
    (void)g;
    (void)r;
    (void)x;
    (void)y;
}

size_t ec_point_elem_len(const ec_point_t g) {
    (void)g;
    return 0;
}

void ec_point_elem_in(ec_point_t g, uint8_t *in, size_t len) {
    (void)g;
    (void)in;
    (void)len;
}

void ec_point_elem_out(const ec_point_t g, uint8_t *out, size_t len) {
    (void)g;
    (void)out;
    (void)len;
}

#endif  // EC_WITH_MCL

}  // extern "C"
