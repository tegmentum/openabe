///
/// \file   zelement_ec_stubs.cpp
///
/// \brief  Stub implementations for EC operations when using incompatible
///         combinations (e.g., BP_WITH_MCL + EC_WITH_OPENSSL).
///         These stubs are provided to satisfy linker requirements but will
///         error at runtime if called.
///
/// \author OpenABE Contributors
///

#include <stdio.h>
#include <stdlib.h>

extern "C" {
#include <openabe/zml/zelement.h>
}

// Compile stubs when:
// 1. Using MCL for pairings but OpenSSL for EC/ECDSA (BP_WITH_MCL && EC_WITH_OPENSSL)
// 2. Using MCL for EC/ECDSA (EC_WITH_MCL) - MCL ECDSA is high-level only, doesn't provide low-level EC ops
#if (defined(BP_WITH_MCL) && defined(EC_WITH_OPENSSL)) || defined(EC_WITH_MCL)

extern "C" {

int ec_group_init(ec_group_t *group, uint8_t id) {
    fprintf(stderr, "ERROR: ec_group_init called with incompatible MCL configuration\n");
    fprintf(stderr, "       Low-level EC operations are not supported with this configuration.\n");
    fprintf(stderr, "       PKSIG (ECDSA) operations should still work via the abstraction layer.\n");
    return -1;
}

void ec_get_order(ec_group_t group, bignum_t order) {
    fprintf(stderr, "ERROR: ec_get_order called with incompatible configuration\n");
}

void ec_point_init(ec_group_t group, ec_point_t *e) {
    fprintf(stderr, "ERROR: ec_point_init called with incompatible configuration\n");
    *e = nullptr;
}

void ec_point_copy(ec_point_t to, const ec_point_t from) {
    fprintf(stderr, "ERROR: ec_point_copy called with incompatible configuration\n");
}

void ec_point_set_inf(ec_group_t group, ec_point_t p) {
    fprintf(stderr, "ERROR: ec_point_set_inf called with incompatible configuration\n");
}

int ec_point_cmp(ec_group_t group, const ec_point_t a, const ec_point_t b) {
    fprintf(stderr, "ERROR: ec_point_cmp called with incompatible configuration\n");
    return -1;
}

int ec_point_is_inf(ec_group_t group, ec_point_t p) {
    fprintf(stderr, "ERROR: ec_point_is_inf called with incompatible configuration\n");
    return 0;
}

void ec_get_generator(ec_group_t group, ec_point_t p) {
    fprintf(stderr, "ERROR: ec_get_generator called with incompatible configuration\n");
}

void ec_get_coordinates(ec_group_t group, bignum_t x, bignum_t y, const ec_point_t p) {
    fprintf(stderr, "ERROR: ec_get_coordinates called with incompatible configuration\n");
}

int ec_convert_to_point(ec_group_t group, ec_point_t p, uint8_t *xstr, int len) {
    fprintf(stderr, "ERROR: ec_convert_to_point called with incompatible configuration\n");
    return -1;
}

int ec_point_is_on_curve(ec_group_t group, ec_point_t p) {
    fprintf(stderr, "ERROR: ec_point_is_on_curve called with incompatible configuration\n");
    return 0;
}

void ec_point_add(ec_group_t g, ec_point_t r, const ec_point_t x, const ec_point_t y) {
    fprintf(stderr, "ERROR: ec_point_add called with incompatible configuration\n");
}

void ec_point_mul(ec_group_t g, ec_point_t r, const ec_point_t x, const bignum_t y) {
    fprintf(stderr, "ERROR: ec_point_mul called with incompatible configuration\n");
}

size_t ec_point_elem_len(const ec_point_t g) {
    fprintf(stderr, "ERROR: ec_point_elem_len called with incompatible configuration\n");
    return 0;
}

void ec_point_elem_in(ec_point_t g, uint8_t *in, size_t len) {
    fprintf(stderr, "ERROR: ec_point_elem_in called with incompatible configuration\n");
}

void ec_point_elem_out(const ec_point_t g, uint8_t *out, size_t len) {
    fprintf(stderr, "ERROR: ec_point_elem_out called with incompatible configuration\n");
}

} // extern "C"

#endif /* (BP_WITH_MCL && EC_WITH_OPENSSL) || EC_WITH_MCL */
