///
/// \file   zelement_mcl.cpp
///
/// \brief  MCL backend implementation for ZML abstraction layer.
///         Implements bignum and pairing operations using MCL library.
///         Note: Uses global MCL state - one curve active at a time.
///
/// \author OpenABE Contributors
///

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

// MCL headers
#include <mcl/bn.h>
#ifndef __wasm__
#include <mcl/bn.hpp>  // C++ API for initialization
#include <exception>
#endif

// Note: This file implements low-level C functions and uses MCL C types directly
// Type definitions for this file (matching MCL backend in zelement.h)
typedef void* bp_group_t;
typedef mclBnG1 g1_ptr;
typedef mclBnG2 g2_ptr;
typedef mclBnGT gt_ptr;

extern "C" {
#include <openabe/utils/zconstants.h>
}

#if defined(BP_WITH_MCL)

/********************************************************************************
 * MCL Library Initialization (uses global state)
 ********************************************************************************/

static bool mcl_initialized = false;
static int mcl_current_curve = -1;

extern "C" {

// Initialize MCL with a specific curve
int mcl_init_curve(int curve_id) {
    if (mcl_initialized && mcl_current_curve == curve_id) {
        return 0;  // Already initialized with this curve
    }

    if (mcl_initialized && mcl_current_curve != curve_id) {
        // Switching curves - warn user
        fprintf(stderr, "MCL: Switching from curve %d to curve %d\n",
                mcl_current_curve, curve_id);
    }

    // Map to MCL C API curve constants
    int mcl_curve;
    const char* curve_name = nullptr;

    switch (curve_id) {
        case MCL_BN254:
            mcl_curve = MCL_BN254;  // mclBn_CurveFp254BNb = 0
            curve_name = "BN254";
            break;
        case MCL_BLS12_381:
            mcl_curve = mclBls12_CurveFp381;  // = 5
            curve_name = "BLS12-381";
            break;
        default:
            fprintf(stderr, "MCL: Unsupported curve ID: %d\n", curve_id);
            return -1;
    }

    // Use C API initialization for both native and WASM for maximum compatibility
    // MCLBN_COMPILED_TIME_VAR = (FR_UNIT_SIZE * 10) + FP_UNIT_SIZE
    // For BLS12-381: FP=384 bits (6 units), FR=256 bits (4 units) -> 4*10+6 = 46
    int compiled_time_var = 46;  // BLS12-381: FR=256bit(4units), FP=384bit(6units)
    if (mcl_curve == MCL_BN254) {
        compiled_time_var = 44;  // BN254: FR=254bit(4units), FP=254bit(4units)
    }

    int ret = mclBn_init(mcl_curve, compiled_time_var);
    if (ret != 0) {
        fprintf(stderr, "MCL: Initialization failed with error code %d\n", ret);
        return -1;
    }

    // Explicitly set serialization mode for cross-platform compatibility
    // Disable ETH serialization for consistent behavior
    mclBn_setETHserialization(0);

    mcl_initialized = true;
    mcl_current_curve = curve_id;
#ifdef __wasm__
    fprintf(stderr, "MCL: Initialized %s (curve ID %d) via C API [WASM] (ETH serialization: disabled)\n", curve_name, curve_id);
#else
    fprintf(stderr, "MCL: Initialized %s (curve ID %d) via C API [NATIVE] (ETH serialization: disabled)\n", curve_name, curve_id);
#endif
    return 0;
}

void zml_init() {
    // Default initialization with BLS12-381
    if (!mcl_initialized) {
        mcl_init_curve(MCL_BLS12_381);
    }
}

void zml_clean() {
    mcl_initialized = false;
    mcl_current_curve = -1;
}

/********************************************************************************
 * MCL Helper Functions
 ********************************************************************************/

void mclBnG1_copy(mclBnG1* y, const mclBnG1* x) {
    *y = *x;
}

void mclBnG2_copy(mclBnG2* y, const mclBnG2* x) {
    *y = *x;
}

void mclBnGT_copy(mclBnGT* y, const mclBnGT* x) {
    *y = *x;
}

/********************************************************************************
 * Bignum Operations (Fr field elements)
 ********************************************************************************/

void zml_bignum_init(mclBnFr *a) {
    mclBnFr_clear(a);
}

int zml_bignum_sign(const mclBnFr a) {
    return mclBnFr_isZero(&a) ? 0 : 1;
}

int zml_bignum_cmp(const mclBnFr a, const mclBnFr b) {
    char buf_a[1024], buf_b[1024];
    size_t len_a = mclBnFr_getStr(buf_a, sizeof(buf_a), &a, 16);
    size_t len_b = mclBnFr_getStr(buf_b, sizeof(buf_b), &b, 16);

    if (len_a == 0 || len_b == 0) return 0;

    if (len_a != len_b) {
        return len_a > len_b ? 1 : -1;
    }

    for (size_t i = 0; i < len_a; i++) {
        if (buf_a[i] != buf_b[i]) {
            return buf_a[i] > buf_b[i] ? 1 : -1;
        }
    }

    return 0;
}

int zml_bignum_countbytes(const mclBnFr a) {
    // FIX Bug #15: MCL mclBnFr is mclBnFr, use MCL serialization to get byte count
    // MCL returns the serialized byte count directly
    uint8_t buf[64];  // Fr elements are at most 32 bytes for BLS12-381
    size_t len = mclBnFr_serialize(buf, sizeof(buf), &a);
    return (int)len;
}

char *zml_bignum_toHex(const mclBnFr b, int *length) {
    char buf[1024];
    size_t len = mclBnFr_getStr(buf, sizeof(buf), &b, 16);
    if (len == 0) {
        *length = 0;
        return NULL;
    }
    char *result = (char*)malloc(len + 1);
    memcpy(result, buf, len + 1);
    *length = (int)len;
    return result;
}

char *zml_bignum_toDec(const mclBnFr b, int *length) {
    char buf[1024];
    size_t len = mclBnFr_getStr(buf, sizeof(buf), &b, 10);
    if (len == 0) {
        *length = 0;
        return NULL;
    }
    char *result = (char*)malloc(len + 1);
    memcpy(result, buf, len + 1);
    *length = (int)len;
    return result;
}

/********************************************************************************
 * Group Initialization
 ********************************************************************************/

int bp_group_init(bp_group_t *group, uint8_t id) {
    int mcl_curve_id = -1;

    // Map OpenABE curve IDs to MCL curve IDs
    switch (id) {
        case OpenABE_BLS12_P381_ID:
            mcl_curve_id = MCL_BLS12_381;
            break;
        case OpenABE_BN_P254_ID:
        case OpenABE_BN_P256_ID:
            mcl_curve_id = MCL_BN254;
            break;
        case OpenABE_BN_P382_ID:
            mcl_curve_id = MCL_BLS12_381;
            break;
        default:
            fprintf(stderr, "MCL: Unsupported OpenABE curve ID: %d (0x%x)\n", id, id);
            return -1;
    }

    // Initialize the curve
    if (mcl_init_curve(mcl_curve_id) != 0) {
        return -1;
    }

    // Store curve ID in group handle
    *group = (bp_group_t)(uintptr_t)mcl_curve_id;

    return 0;
}

void bp_get_order(bp_group_t group, mclBnFr order) {
    char order_str[256];
    mclBn_getCurveOrder(order_str, sizeof(order_str));
    mclBnFr_setStr(&order, order_str, strlen(order_str), 10);
}

void bp_ensure_curve_params(uint8_t id) {
    (void)id;
}

/********************************************************************************
 * G1 Operations
 ********************************************************************************/

void g1_init(bp_group_t group, g1_ptr *e) {
    (void)group;
    mclBnG1_clear(e);
}

void g1_set_to_infinity(bp_group_t group, g1_ptr *e) {
    (void)group;
    mclBnG1_clear(e);
}

void g1_add_op(bp_group_t group, g1_ptr *z, const g1_ptr *x, const g1_ptr *y) {
    (void)group;
    mclBnG1_add(z, x, y);
}

void g1_sub_op(bp_group_t group, g1_ptr *z, const g1_ptr *x) {
    (void)group;
    mclBnG1_neg(z, x);
}

void g1_mul_op(bp_group_t group, g1_ptr *z, const g1_ptr *x, const mclBnFr *r) {
    (void)group;
    mclBnG1_mul(z, x, r);
}

void g1_rand_op(g1_ptr *g) {
    mclBnG1_hashAndMapTo(g, "random", 6);
}

void g1_map_op(const bp_group_t group, g1_ptr *g, uint8_t *msg, int msg_len) {
    (void)group;
    mclBnG1_hashAndMapTo(g, msg, (size_t)msg_len);
}

size_t g1_elem_len(const g1_ptr g) {
    (void)g;
    return mclBn_getG1ByteSize();
}

void g1_elem_in(g1_ptr *g, uint8_t *in, size_t len) {
    mclBnG1_deserialize(g, in, len);
}

void g1_elem_out(const g1_ptr *g, uint8_t *out, size_t len) {
    mclBnG1_serialize(out, len, g);
}

/********************************************************************************
 * G2 Operations
 ********************************************************************************/

void g2_init(bp_group_t group, g2_ptr *e) {
    (void)group;
    mclBnG2_clear(e);
}

void g2_set_to_infinity(bp_group_t group, g2_ptr *e) {
    (void)group;
    mclBnG2_clear(e);
}

void g2_mul_op(bp_group_t group, g2_ptr *z, const g2_ptr *x, const mclBnFr *r) {
    (void)group;
    mclBnG2_mul(z, x, r);
}

int g2_cmp_op(bp_group_t group, const g2_ptr *x, const g2_ptr *y) {
    (void)group;
    return mclBnG2_isEqual(x, y) ? 0 : 1;
}

size_t g2_elem_len(g2_ptr g) {
    (void)g;
    return mclBn_getG2ByteSize();
}

void g2_elem_in(g2_ptr *g, uint8_t *in, size_t len) {
    mclBnG2_deserialize(g, in, len);
}

void g2_elem_out(const g2_ptr *g, uint8_t *out, size_t len) {
    mclBnG2_serialize(out, len, g);
}

/********************************************************************************
 * GT Operations
 ********************************************************************************/

void gt_init(const bp_group_t group, gt_ptr *e) {
    (void)group;
    mclBnGT_clear(e);
}

void gt_set_to_infinity(bp_group_t group, gt_ptr *e) {
    (void)group;
    mclBnGT_setInt(e, 1);
}

void gt_mul_op(const bp_group_t group, gt_ptr *z, const gt_ptr *x, const gt_ptr *y) {
    (void)group;
    mclBnGT_mul(z, x, y);
}

void gt_div_op(const bp_group_t group, gt_ptr *z, const gt_ptr *x, const gt_ptr *y) {
    (void)group;
    mclBnGT gy_inv;
    mclBnGT_inv(&gy_inv, y);
    mclBnGT_mul(z, x, &gy_inv);
}

void gt_exp_op(const bp_group_t group, gt_ptr *y, const gt_ptr *x, const mclBnFr *r) {
    (void)group;
    mclBnGT_pow(y, x, r);
}

int gt_is_unity_check(const bp_group_t group, const gt_ptr *r) {
    (void)group;
    return mclBnGT_isOne(r);
}

size_t gt_elem_len(const gt_ptr *g, int should_compress) {
    (void)should_compress;
    // GT is Fp12, which is 12 * Fp elements
    // For BLS12-381: Fp is 48 bytes, so GT is 576 bytes
    // For BN254: Fp is 32 bytes, so GT is 384 bytes
    // Use actual serialization to determine size
    return mclBnGT_serialize(NULL, 0, g);
}

void gt_elem_in(gt_ptr *g, uint8_t *in, size_t len) {
    mclBnGT_deserialize(g, in, len);
}

void gt_elem_out(const gt_ptr *g, uint8_t *out, size_t len, int should_compress) {
    (void)should_compress;
    mclBnGT_serialize(out, len, g);
}

/********************************************************************************
 * Pairing Operation
 ********************************************************************************/

void bp_map_op(const bp_group_t group, gt_ptr *gt, const g1_ptr *g1, const g2_ptr *g2) {
    (void)group;
    mclBn_pairing(gt, g1, g2);
}

/********************************************************************************
 * Random Number Generation
 ********************************************************************************/

void zml_bignum_rand(mclBnFr *a, const mclBnFr *o) {
    (void)o;
    mclBnFr_setByCSPRNG(a);
}

int zml_check_error() {
    return 0;
}

int gt_is_unity(const gt_ptr a) {
    return mclBnGT_isOne(&a);
}

int bn_is_even(const mclBnFr a) {
    char buf[1024];
    size_t len = mclBnFr_getStr(buf, sizeof(buf), &a, 10);
    if (len == 0) return 1;
    return (buf[len-1] - '0') % 2 == 0;
}

void g1_rand(g1_ptr *g) {
    mclBnFr r;
    mclBnFr_setByCSPRNG(&r);
    mclBnG1 gen;
    mclBnG1_hashAndMapTo(&gen, "generator", 9);
    mclBnG1_mul(g, &gen, &r);
}

void g2_rand(g2_ptr *g) {
    mclBnFr r;
    mclBnFr_setByCSPRNG(&r);
    mclBnG2 gen;
    mclBnG2_hashAndMapTo(&gen, "generator", 9);
    mclBnG2_mul(g, &gen, &r);
}

void g2_rand_op(g2_ptr g) {
    mclBnG2_hashAndMapTo(&g, "random", 6);
}

void oabe_rand_seed(unsigned char* buf, int buf_len) {
    (void)buf;
    (void)buf_len;
}

} // extern "C"

#endif // BP_WITH_MCL
