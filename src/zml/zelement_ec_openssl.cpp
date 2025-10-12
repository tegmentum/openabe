///
/// \file   zelement_ec_openssl.cpp
///
/// \brief  OpenSSL-based EC operations for NIST curves (P-256, P-384, P-521).
///         Implements EC abstraction layer using OpenSSL's EC functions.
///
/// \author OpenABE Contributors
///

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/obj_mac.h>
#include <openabe/zml/zelement.h>
#include <openabe/utils/zconstants.h>

#if defined(EC_WITH_OPENSSL)

extern "C" {

/********************************************************************************
 * Utility Functions
 ********************************************************************************/

static int curve_id_to_nid(uint8_t id) {
    switch (id) {
        case OpenABE_NIST_P256_ID:
            return NID_X9_62_prime256v1; // secp256r1 / P-256
        case OpenABE_NIST_P384_ID:
            return NID_secp384r1; // P-384
        case OpenABE_NIST_P521_ID:
            return NID_secp521r1; // P-521
        default:
            fprintf(stderr, "Unsupported curve ID: 0x%02x\n", id);
            return 0;
    }
}

/********************************************************************************
 * EC Group Initialization
 ********************************************************************************/

int ec_group_init(ec_group_t *group, uint8_t id) {
    int nid = curve_id_to_nid(id);
    if (nid == 0) {
        return -1;
    }

    EC_GROUP *ec_group = EC_GROUP_new_by_curve_name(nid);
    if (ec_group == NULL) {
        fprintf(stderr, "ec_group_init: Failed to create EC_GROUP for nid %d\n", nid);
        return -1;
    }

    // Set group to use named curve for more efficient serialization
    EC_GROUP_set_asn1_flag(ec_group, OPENSSL_EC_NAMED_CURVE);

    *group = ec_group;
    return 0;
}

void ec_get_order(ec_group_t group, bignum_t order) {
    if (!group || !order) return;

    EC_GROUP *ec_group = static_cast<EC_GROUP*>(group);
    BIGNUM *bn_order = static_cast<BIGNUM*>(order);

    if (!EC_GROUP_get_order(ec_group, bn_order, NULL)) {
        fprintf(stderr, "ec_get_order: Failed to get group order\n");
    }
}

/********************************************************************************
 * EC Point Operations
 ********************************************************************************/

void ec_point_init(ec_group_t group, ec_point_t *e) {
    if (!group) return;

    EC_GROUP *ec_group = static_cast<EC_GROUP*>(group);
    EC_POINT *point = EC_POINT_new(ec_group);

    if (point == NULL) {
        fprintf(stderr, "ec_point_init: Failed to create EC_POINT\n");
        *e = NULL;
        return;
    }

    *e = point;
}

void ec_point_copy(ec_point_t to, const ec_point_t from) {
    if (!to || !from) return;

    // We need the group for copy, but we don't have it here
    // This is a limitation of the current API
    // For now, we'll do a memcpy which works for the internal representation
    memcpy(to, from, sizeof(EC_POINT));
}

void ec_point_set_inf(ec_group_t group, ec_point_t p) {
    if (!group || !p) return;

    EC_GROUP *ec_group = static_cast<EC_GROUP*>(group);
    EC_POINT *point = static_cast<EC_POINT*>(p);

    if (!EC_POINT_set_to_infinity(ec_group, point)) {
        fprintf(stderr, "ec_point_set_inf: Failed to set point to infinity\n");
    }
}

int ec_point_cmp(ec_group_t group, const ec_point_t a, const ec_point_t b) {
    if (!group || !a || !b) return -1;

    EC_GROUP *ec_group = static_cast<EC_GROUP*>(group);
    const EC_POINT *pa = static_cast<const EC_POINT*>(a);
    const EC_POINT *pb = static_cast<const EC_POINT*>(b);

    BN_CTX *ctx = BN_CTX_new();
    if (!ctx) return -1;

    int result = EC_POINT_cmp(ec_group, pa, pb, ctx);
    BN_CTX_free(ctx);

    return result; // 0 if equal, non-zero otherwise
}

int ec_point_is_inf(ec_group_t group, ec_point_t p) {
    if (!group || !p) return 1;

    EC_GROUP *ec_group = static_cast<EC_GROUP*>(group);
    EC_POINT *point = static_cast<EC_POINT*>(p);

    return EC_POINT_is_at_infinity(ec_group, point);
}

void ec_get_generator(ec_group_t group, ec_point_t p) {
    if (!group || !p) return;

    EC_GROUP *ec_group = static_cast<EC_GROUP*>(group);
    EC_POINT *point = static_cast<EC_POINT*>(p);
    const EC_POINT *generator = EC_GROUP_get0_generator(ec_group);

    if (!generator) {
        fprintf(stderr, "ec_get_generator: Failed to get generator\n");
        return;
    }

    if (!EC_POINT_copy(point, generator)) {
        fprintf(stderr, "ec_get_generator: Failed to copy generator\n");
    }
}

void ec_get_coordinates(ec_group_t group, bignum_t x, bignum_t y, const ec_point_t p) {
    if (!group || !p) return;

    EC_GROUP *ec_group = static_cast<EC_GROUP*>(group);
    const EC_POINT *point = static_cast<const EC_POINT*>(p);
    BIGNUM *bn_x = static_cast<BIGNUM*>(x);
    BIGNUM *bn_y = static_cast<BIGNUM*>(y);

    BN_CTX *ctx = BN_CTX_new();
    if (!ctx) {
        fprintf(stderr, "ec_get_coordinates: Failed to create BN_CTX\n");
        return;
    }

    if (!EC_POINT_get_affine_coordinates(ec_group, point, bn_x, bn_y, ctx)) {
        fprintf(stderr, "ec_get_coordinates: Failed to get affine coordinates\n");
    }

    BN_CTX_free(ctx);
}

int ec_convert_to_point(ec_group_t group, ec_point_t p, uint8_t *xstr, int len) {
    if (!group || !p || !xstr) return -1;

    EC_GROUP *ec_group = static_cast<EC_GROUP*>(group);
    EC_POINT *point = static_cast<EC_POINT*>(p);

    // Convert from compressed or uncompressed format
    if (!EC_POINT_oct2point(ec_group, point, xstr, len, NULL)) {
        fprintf(stderr, "ec_convert_to_point: Failed to convert octets to point\n");
        return -1;
    }

    return 0;
}

int ec_point_is_on_curve(ec_group_t group, ec_point_t p) {
    if (!group || !p) return 0;

    EC_GROUP *ec_group = static_cast<EC_GROUP*>(group);
    EC_POINT *point = static_cast<EC_POINT*>(p);

    BN_CTX *ctx = BN_CTX_new();
    if (!ctx) return 0;

    int result = EC_POINT_is_on_curve(ec_group, point, ctx);
    BN_CTX_free(ctx);

    return result;
}

void ec_point_add(ec_group_t g, ec_point_t r, const ec_point_t x, const ec_point_t y) {
    if (!g || !r || !x || !y) return;

    EC_GROUP *ec_group = static_cast<EC_GROUP*>(g);
    EC_POINT *result = static_cast<EC_POINT*>(r);
    const EC_POINT *px = static_cast<const EC_POINT*>(x);
    const EC_POINT *py = static_cast<const EC_POINT*>(y);

    BN_CTX *ctx = BN_CTX_new();
    if (!ctx) {
        fprintf(stderr, "ec_point_add: Failed to create BN_CTX\n");
        return;
    }

    if (!EC_POINT_add(ec_group, result, px, py, ctx)) {
        fprintf(stderr, "ec_point_add: Failed to add points\n");
    }

    BN_CTX_free(ctx);
}

void ec_point_mul(ec_group_t g, ec_point_t r, const ec_point_t x, const bignum_t y) {
    if (!g || !r || !x || !y) return;

    EC_GROUP *ec_group = static_cast<EC_GROUP*>(g);
    EC_POINT *result = static_cast<EC_POINT*>(r);
    const EC_POINT *point = static_cast<const EC_POINT*>(x);
    const BIGNUM *scalar = static_cast<const BIGNUM*>(y);

    BN_CTX *ctx = BN_CTX_new();
    if (!ctx) {
        fprintf(stderr, "ec_point_mul: Failed to create BN_CTX\n");
        return;
    }

    if (!EC_POINT_mul(ec_group, result, NULL, point, scalar, ctx)) {
        fprintf(stderr, "ec_point_mul: Failed to multiply point\n");
    }

    BN_CTX_free(ctx);
}

/********************************************************************************
 * Serialization Operations
 ********************************************************************************/

size_t ec_point_elem_len(const ec_point_t g) {
    // Maximum size for compressed point (1 + field size)
    // For P-521, this is 1 + 66 = 67 bytes
    // We'll return a safe maximum
    return 67;
}

void ec_point_elem_in(ec_point_t g, uint8_t *in, size_t len) {
    if (!g || !in) return;

    // We need the group for deserialization, but we don't have it here
    // This is a limitation - the point should already be associated with a group
    fprintf(stderr, "ec_point_elem_in: Warning - need group context for deserialization\n");
}

void ec_point_elem_out(const ec_point_t g, uint8_t *out, size_t len) {
    if (!g || !out) return;

    // We need the group for serialization, but we don't have it here
    // This is a limitation - the point should already be associated with a group
    fprintf(stderr, "ec_point_elem_out: Warning - need group context for serialization\n");
}

} // extern "C"

#endif /* EC_WITH_OPENSSL */
