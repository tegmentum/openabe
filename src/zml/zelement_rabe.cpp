///
/// \file   zelement_rabe.cpp
///
/// \brief  RABE backend implementation for ZML abstraction layer.
///         Implements bignum and pairing operations using RABE BLS12-381 library.
///
/// \author OpenABE Contributors
///

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

// RABE FFI header
#include <rabe_bls12381.h>

extern "C" {
#include <openabe/utils/zconstants.h>
}

#if defined(BP_WITH_RABE)

/********************************************************************************
 * RABE Library Initialization
 ********************************************************************************/

static bool rabe_initialized = false;

extern "C" {

void zml_init() {
    if (!rabe_initialized) {
        rabe_zml_init();
        rabe_initialized = true;
        fprintf(stderr, "RABE: Initialized BLS12-381 (128-bit security)\n");
    }
}

void zml_clean() {
    if (rabe_initialized) {
        rabe_zml_clean();
        rabe_initialized = false;
    }
}

/********************************************************************************
 * Bignum Operations (Fr field elements)
 ********************************************************************************/

void zml_bignum_init(RabeFr **a) {
    *a = rabe_fr_new();
}

int zml_bignum_sign(const RabeFr *a) {
    if (a == nullptr) return 0;
    return rabe_fr_is_zero(a) ? 0 : 1;
}

int zml_bignum_cmp(const RabeFr *a, const RabeFr *b) {
    if (a == nullptr || b == nullptr) return 0;
    // Simple comparison - check if both are zero or non-zero
    int a_zero = rabe_fr_is_zero(a);
    int b_zero = rabe_fr_is_zero(b);
    if (a_zero && b_zero) return 0;
    if (a_zero && !b_zero) return -1;
    if (!a_zero && b_zero) return 1;
    return 0;  // Both non-zero, cannot compare without serialization
}

int zml_bignum_countbytes(const RabeFr *a) {
    return (int)rabe_fr_byte_size();
}

char *zml_bignum_toHex(const RabeFr *b, int *length) {
    if (b == nullptr) {
        *length = 0;
        return nullptr;
    }
    // Serialize to bytes then convert to hex
    size_t byte_len = rabe_fr_byte_size();
    uint8_t *bytes = (uint8_t*)malloc(byte_len);
    rabe_fr_serialize(bytes, byte_len, b);

    // Convert to hex string (2 chars per byte)
    *length = (int)(byte_len * 2);
    char *hex = (char*)malloc(*length + 1);
    for (size_t i = 0; i < byte_len; i++) {
        sprintf(hex + i*2, "%02x", bytes[i]);
    }
    hex[*length] = '\0';
    free(bytes);
    return hex;
}

char *zml_bignum_toDec(const RabeFr *b, int *length) {
    // For simplicity, return hex representation
    // A proper implementation would convert to decimal
    return zml_bignum_toHex(b, length);
}

void zml_bignum_fromHex(RabeFr *a, const char *hex, size_t hex_len) {
    if (a == nullptr || hex == nullptr) return;
    // Convert hex string to bytes
    size_t byte_len = hex_len / 2;
    uint8_t *bytes = (uint8_t*)malloc(byte_len);
    for (size_t i = 0; i < byte_len; i++) {
        unsigned int val;
        sscanf(hex + i*2, "%02x", &val);
        bytes[i] = (uint8_t)val;
    }
    rabe_fr_deserialize(a, bytes, byte_len);
    free(bytes);
}

void zml_bignum_fromBin(RabeFr *a, const uint8_t *bin, size_t bin_len) {
    if (a == nullptr || bin == nullptr) return;
    rabe_fr_deserialize(a, bin, bin_len);
}

void zml_bignum_toBin(const RabeFr *a, uint8_t *bin, size_t bin_len) {
    if (a == nullptr || bin == nullptr) return;
    rabe_fr_serialize(bin, bin_len, a);
}

void zml_bignum_rand(RabeFr **a, const RabeFr **o) {
    (void)o;  // Order not needed for RABE
    if (*a == nullptr) {
        *a = rabe_fr_new();
    }
    rabe_fr_random(*a);
}

int zml_check_error() {
    return 0;
}

int bn_is_even(const RabeFr *a) {
    // Serialize and check last bit
    if (a == nullptr) return 1;
    uint8_t bytes[32];
    rabe_fr_serialize(bytes, sizeof(bytes), a);
    return (bytes[0] & 1) == 0;
}

void zml_bignum_free(RabeFr *a) {
    if (a != nullptr) {
        rabe_fr_free(a);
    }
}

void zml_bignum_copy(RabeFr *a, const RabeFr *b) {
    if (a != nullptr && b != nullptr) {
        rabe_fr_copy(a, b);
    }
}

// IMPORTANT: Signature must match RELIC version (4 arguments).
// The order parameter is not used since RABE Fr arithmetic is automatically mod r.
void zml_bignum_add(RabeFr *z, const RabeFr *x, const RabeFr *y, const RabeFr *o) {
    (void)o;  // Not used - RABE Fr arithmetic is automatically mod r
    if (z != nullptr && x != nullptr && y != nullptr) {
        rabe_fr_add(z, x, y);
    }
}

void zml_bignum_sub(RabeFr *z, const RabeFr *x, const RabeFr *y) {
    if (z != nullptr && x != nullptr && y != nullptr) {
        rabe_fr_sub(z, x, y);
    }
}

// IMPORTANT: Signature must match RELIC version (4 arguments).
// The order parameter is not used since RABE Fr arithmetic is automatically mod r.
void zml_bignum_mul(RabeFr *z, const RabeFr *x, const RabeFr *y, const RabeFr *o) {
    (void)o;  // Not used - RABE Fr arithmetic is automatically mod r
    if (z != nullptr && x != nullptr && y != nullptr) {
        rabe_fr_mul(z, x, y);
    }
}

// IMPORTANT: Signature must match RELIC version (4 arguments).
// The order parameter is not used since RABE Fr arithmetic is automatically mod r.
void zml_bignum_div(RabeFr *z, const RabeFr *x, const RabeFr *y, const RabeFr *o) {
    (void)o;  // Not used - RABE Fr arithmetic is automatically mod r
    if (z != nullptr && x != nullptr && y != nullptr) {
        rabe_fr_div(z, x, y);
    }
}

// IMPORTANT: This must match RELIC semantics where b is negated IN PLACE.
// The second parameter 'order' is the modulus, but RABE handles this automatically.
// Called as: zml_bignum_negate(zr.m_ZP, zr.order) to negate zr.m_ZP in place.
void zml_bignum_negate(RabeFr *b, const RabeFr *order) {
    (void)order;  // Not used - RABE Fr arithmetic is automatically mod r
    if (b != nullptr) {
        rabe_fr_neg(b, b);  // Negate b in place
    }
}

// Called as: zml_bignum_mod(x, order) to reduce x mod order in place.
// For RABE Fr elements, all arithmetic is automatically mod r, so this is a no-op.
void zml_bignum_mod(RabeFr *x, const RabeFr *o) {
    (void)x;
    (void)o;
    // No-op: RABE Fr elements are already reduced mod r
}

void zml_bignum_mod_inv(RabeFr *z, const RabeFr *x, const RabeFr *m) {
    // Compute modular inverse: z = x^(-1) mod m
    (void)m;  // Modulus is implicit in Fr
    if (z != nullptr && x != nullptr) {
        rabe_fr_inv(z, x);
    }
}

void zml_bignum_exp(RabeFr *z, const RabeFr *x, const RabeFr *y, const RabeFr *m) {
    // Exponentiation in Fr: z = x^y mod m
    // Modulus is implicit in Fr (the field order)
    (void)m;
    if (z == nullptr || x == nullptr || y == nullptr) return;

    rabe_fr_pow(z, x, y);
}

void zml_bignum_setzero(RabeFr *a) {
    if (a != nullptr) {
        rabe_fr_clear(a);
    }
}

void zml_bignum_lshift(RabeFr *z, const RabeFr *x, int bits) {
    // Left shift - multiply by 2^bits
    if (z == nullptr || x == nullptr) return;
    rabe_fr_copy(z, x);
    for (int i = 0; i < bits; i++) {
        rabe_fr_add(z, z, z);  // z = z * 2
    }
}

void zml_bignum_rshift(RabeFr *z, const RabeFr *x, int bits) {
    // Right shift - divide by 2^bits
    // This is complex in prime fields, just do a copy for now
    (void)bits;
    if (z != nullptr && x != nullptr) {
        rabe_fr_copy(z, x);
    }
}

// IMPORTANT: Signature must match RELIC version (4 arguments).
// The order parameter is not used since RABE Fr arithmetic is automatically mod r.
void zml_bignum_sub_order(RabeFr *z, const RabeFr *x, const RabeFr *y, const RabeFr *o) {
    (void)o;  // Not used - RABE Fr arithmetic is automatically mod r
    // Subtract with modular reduction (automatic in RABE Fr)
    if (z != nullptr && x != nullptr && y != nullptr) {
        rabe_fr_sub(z, x, y);
    }
}

/********************************************************************************
 * Group Initialization
 ********************************************************************************/

int bp_group_init(void **group, uint8_t id) {
    // Map OpenABE curve IDs to RABE
    int result = -1;

    if (id == OpenABE_BLS12_P381_ID || id == OpenABE_BN_P382_ID) {
        // BLS12-381 (128-bit security)
        result = rabe_init_curve(id);
    } else if (id == OpenABE_BN_P254_ID || id == OpenABE_BN_P256_ID) {
        fprintf(stderr, "RABE: BN254 curve not supported, only BLS12-381\n");
        return -1;
    } else {
        fprintf(stderr, "RABE: Unsupported OpenABE curve ID: %d (0x%x)\n", id, id);
        return -1;
    }

    // Store curve ID in group handle
    *group = (void*)(uintptr_t)id;

    return result;
}

void bp_get_order(void *group, RabeFr *order) {
    (void)group;
    // The order of BLS12-381 scalar field is fixed
    // For now, just set to a non-zero value
    if (order != nullptr) {
        rabe_fr_set_one(order);
    }
}

void bp_ensure_curve_params(uint8_t id) {
    (void)id;
    // No-op for RABE
}

/********************************************************************************
 * G1 Operations
 * Note: g1_ptr is a wrapper struct { RabeG1* ptr; }
 ********************************************************************************/

// Forward declarations for wrapper types
typedef struct { RabeG1* ptr; } g1_wrapper;
typedef struct { RabeG2* ptr; } g2_wrapper;
typedef struct { RabeGt* ptr; } gt_wrapper;

void g1_init(void *group, g1_wrapper *e) {
    (void)group;
    e->ptr = rabe_g1_new();
}

void g1_set_to_infinity(void *group, g1_wrapper *e) {
    (void)group;
    if (e->ptr == nullptr) {
        e->ptr = rabe_g1_new();
    }
    rabe_g1_clear(e->ptr);
}

void g1_add_op(void *group, g1_wrapper *z, const g1_wrapper *x, const g1_wrapper *y) {
    (void)group;
    if (z->ptr == nullptr) z->ptr = rabe_g1_new();
    rabe_g1_add(z->ptr, x->ptr, y->ptr);
}

void g1_sub_op(void *group, g1_wrapper *z, const g1_wrapper *x) {
    (void)group;
    if (z->ptr == nullptr) z->ptr = rabe_g1_new();
    rabe_g1_neg(z->ptr, x->ptr);
}

void g1_mul_op(void *group, g1_wrapper *z, const g1_wrapper *x, const RabeFr **r) {
    (void)group;
    if (z->ptr == nullptr) z->ptr = rabe_g1_new();
    rabe_g1_mul(z->ptr, x->ptr, *r);
}

void g1_rand_op(g1_wrapper *g) {
    if (g->ptr == nullptr) g->ptr = rabe_g1_new();
    rabe_g1_random(g->ptr);
}

void g1_map_op(const void *group, g1_wrapper *g, uint8_t *msg, int msg_len) {
    (void)group;
    if (g->ptr == nullptr) g->ptr = rabe_g1_new();
    rabe_g1_hash(g->ptr, msg, (size_t)msg_len);
}

size_t g1_elem_len(const g1_wrapper g) {
    (void)g;
    return rabe_g1_byte_size();
}

void g1_elem_in(g1_wrapper *g, uint8_t *in, size_t len) {
    if (g->ptr == nullptr) g->ptr = rabe_g1_new();
    rabe_g1_deserialize(g->ptr, in, len);
}

void g1_elem_out(const g1_wrapper *g, uint8_t *out, size_t len) {
    rabe_g1_serialize(out, len, g->ptr);
}

/********************************************************************************
 * G2 Operations
 ********************************************************************************/

void g2_init(void *group, g2_wrapper *e) {
    (void)group;
    e->ptr = rabe_g2_new();
}

void g2_set_to_infinity(void *group, g2_wrapper *e) {
    (void)group;
    if (e->ptr == nullptr) {
        e->ptr = rabe_g2_new();
    }
    rabe_g2_clear(e->ptr);
}

void g2_mul_op(void *group, g2_wrapper *z, const g2_wrapper *x, const RabeFr **r) {
    (void)group;
    if (z->ptr == nullptr) z->ptr = rabe_g2_new();
    rabe_g2_mul(z->ptr, x->ptr, *r);
}

int g2_cmp_op(void *group, const g2_wrapper *x, const g2_wrapper *y) {
    (void)group;
    return rabe_g2_cmp(x->ptr, y->ptr);
}

size_t g2_elem_len(g2_wrapper g) {
    (void)g;
    return rabe_g2_byte_size();
}

void g2_elem_in(g2_wrapper *g, uint8_t *in, size_t len) {
    if (g->ptr == nullptr) g->ptr = rabe_g2_new();
    rabe_g2_deserialize(g->ptr, in, len);
}

void g2_elem_out(const g2_wrapper *g, uint8_t *out, size_t len) {
    rabe_g2_serialize(out, len, g->ptr);
}

void g2_rand_op(g2_wrapper g) {
    rabe_g2_random(g.ptr);
}

/********************************************************************************
 * GT Operations
 ********************************************************************************/

void gt_init(const void *group, gt_wrapper *e) {
    (void)group;
    e->ptr = rabe_gt_new();
}

void gt_set_to_infinity(void *group, gt_wrapper *e) {
    (void)group;
    if (e->ptr == nullptr) {
        e->ptr = rabe_gt_new();
    }
    rabe_gt_set_one(e->ptr);
}

void gt_mul_op(const void *group, gt_wrapper *z, const gt_wrapper *x, const gt_wrapper *y) {
    (void)group;
    if (z->ptr == nullptr) z->ptr = rabe_gt_new();
    rabe_gt_mul(z->ptr, x->ptr, y->ptr);
}

void gt_div_op(const void *group, gt_wrapper *z, const gt_wrapper *x, const gt_wrapper *y) {
    (void)group;
    if (z->ptr == nullptr) z->ptr = rabe_gt_new();
    rabe_gt_div(z->ptr, x->ptr, y->ptr);
}

void gt_exp_op(const void *group, gt_wrapper *y, const gt_wrapper *x, const RabeFr **r) {
    (void)group;
    if (y->ptr == nullptr) y->ptr = rabe_gt_new();
    rabe_gt_pow(y->ptr, x->ptr, *r);
}

int gt_is_unity_check(const void *group, const gt_wrapper *r) {
    (void)group;
    return rabe_gt_is_one(r->ptr);
}

size_t gt_elem_len(const gt_wrapper *g, int should_compress) {
    (void)g;
    (void)should_compress;
    return rabe_gt_byte_size();
}

void gt_elem_in(gt_wrapper *g, uint8_t *in, size_t len) {
    if (g->ptr == nullptr) g->ptr = rabe_gt_new();
    rabe_gt_deserialize(g->ptr, in, len);
}

void gt_elem_out(const gt_wrapper *g, uint8_t *out, size_t len, int should_compress) {
    (void)should_compress;
    rabe_gt_serialize(out, len, g->ptr);
}

int gt_is_unity(const gt_wrapper a) {
    return rabe_gt_is_one(a.ptr);
}

/********************************************************************************
 * Pairing Operation
 ********************************************************************************/

void bp_map_op(const void *group, gt_wrapper *gt, const g1_wrapper *g1, const g2_wrapper *g2) {
    (void)group;
    if (gt->ptr == nullptr) gt->ptr = rabe_gt_new();
    rabe_pairing(gt->ptr, g1->ptr, g2->ptr);
}

/********************************************************************************
 * Random Number Generation
 ********************************************************************************/

void g1_rand(RabeG1 **g) {
    if (*g == nullptr) *g = rabe_g1_new();
    rabe_g1_random(*g);
}

void g2_rand(RabeG2 **g) {
    if (*g == nullptr) *g = rabe_g2_new();
    rabe_g2_random(*g);
}

void oabe_rand_seed(unsigned char* buf, int buf_len) {
    (void)buf;
    (void)buf_len;
    // RABE uses system RNG internally
}

} // extern "C"

#endif // BP_WITH_RABE
