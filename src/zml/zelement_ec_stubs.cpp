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
#include <openabe/zml/zelement.h>

// Compile stubs when:
// 1. Using MCL-only without OpenSSL EC (BP_WITH_MCL without EC_WITH_OPENSSL)
// 2. Using MCL for EC/ECDSA (EC_WITH_MCL) - MCL ECDSA is high-level only, doesn't provide low-level EC ops
// These stubs satisfy linker requirements but will error at runtime if called.
// ABE operations don't use these functions, so ABE works fine.
#if (defined(BP_WITH_MCL) && !defined(EC_WITH_OPENSSL)) || defined(EC_WITH_MCL)

extern "C" {

int ec_group_init(ec_group_t *group, uint8_t id) {
    fprintf(stderr, "ERROR: ec_group_init called in ABE-only build (MCL-only configuration)\n");
    fprintf(stderr, "       OpenABE is configured for ABE operations only.\n");
    fprintf(stderr, "       PKE/PKSIG operations are not supported in this build.\n");
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
    (void)to;
    (void)from;
    fprintf(stderr, "ERROR: ec_point_copy called in ABE-only build\n");
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

#endif /* (BP_WITH_MCL && !EC_WITH_OPENSSL) || EC_WITH_MCL */

// ECDSA stub implementations for ABE-only build
#if defined(BP_WITH_MCL) && !defined(EC_WITH_OPENSSL)

#include <openabe/zml/zecdsa.h>

extern "C" {

int ecdsa_context_init(ecdsa_context_t *ctx, uint8_t curve_id) {
    (void)ctx;
    (void)curve_id;
    fprintf(stderr, "ERROR: ECDSA operations not supported in ABE-only build\n");
    fprintf(stderr, "       PKE/PKSIG functionality requires OpenSSL EC support\n");
    return -1;
}

void ecdsa_context_free(ecdsa_context_t ctx) {
    (void)ctx;
}

int ecdsa_keygen(ecdsa_context_t ctx, ecdsa_keypair_t *keypair) {
    (void)ctx;
    (void)keypair;
    fprintf(stderr, "ERROR: ECDSA keygen not supported in ABE-only build\n");
    return -1;
}

void ecdsa_keypair_free(ecdsa_keypair_t keypair) {
    (void)keypair;
}

size_t ecdsa_export_public_key(ecdsa_keypair_t keypair, uint8_t *buf, size_t buf_len) {
    (void)keypair;
    (void)buf;
    (void)buf_len;
    fprintf(stderr, "ERROR: ECDSA export_public_key not supported in ABE-only build\n");
    return 0;
}

size_t ecdsa_export_private_key(ecdsa_keypair_t keypair, uint8_t *buf, size_t buf_len) {
    (void)keypair;
    (void)buf;
    (void)buf_len;
    fprintf(stderr, "ERROR: ECDSA export_private_key not supported in ABE-only build\n");
    return 0;
}

int ecdsa_import_public_key(ecdsa_context_t ctx, ecdsa_keypair_t *keypair,
                             const uint8_t *buf, size_t buf_len) {
    (void)ctx;
    (void)keypair;
    (void)buf;
    (void)buf_len;
    fprintf(stderr, "ERROR: ECDSA import_public_key not supported in ABE-only build\n");
    return -1;
}

int ecdsa_import_private_key(ecdsa_context_t ctx, ecdsa_keypair_t *keypair,
                              const uint8_t *buf, size_t buf_len) {
    (void)ctx;
    (void)keypair;
    (void)buf;
    (void)buf_len;
    fprintf(stderr, "ERROR: ECDSA import_private_key not supported in ABE-only build\n");
    return -1;
}

size_t ecdsa_sign(ecdsa_keypair_t keypair, const uint8_t *msg, size_t msg_len,
                  uint8_t *sig, size_t sig_len) {
    (void)keypair;
    (void)msg;
    (void)msg_len;
    (void)sig;
    (void)sig_len;
    fprintf(stderr, "ERROR: ECDSA sign not supported in ABE-only build\n");
    return 0;
}

int ecdsa_verify(ecdsa_keypair_t keypair, const uint8_t *msg, size_t msg_len,
                 const uint8_t *sig, size_t sig_len) {
    (void)keypair;
    (void)msg;
    (void)msg_len;
    (void)sig;
    (void)sig_len;
    fprintf(stderr, "ERROR: ECDSA verify not supported in ABE-only build\n");
    return 0;
}

size_t ecdsa_get_max_signature_size(ecdsa_context_t ctx) {
    (void)ctx;
    return 0;
}

int ecdsa_has_private_key(ecdsa_keypair_t keypair) {
    (void)keypair;
    return 0;
}

} // extern "C"

#endif /* BP_WITH_MCL && !EC_WITH_OPENSSL */
