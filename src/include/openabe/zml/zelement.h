/// 
/// Copyright (c) 2018 Zeutro, LLC. All rights reserved.
/// 
/// This file is part of Zeutro's OpenABE.
/// 
/// OpenABE is free software: you can redistribute it and/or modify
/// it under the terms of the GNU Affero General Public License as published by
/// the Free Software Foundation, either version 3 of the License, or
/// (at your option) any later version.
/// 
/// OpenABE is distributed in the hope that it will be useful,
/// but WITHOUT ANY WARRANTY; without even the implied warranty of
/// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
/// GNU Affero General Public License for more details.
/// 
/// You should have received a copy of the GNU Affero General Public
/// License along with OpenABE. If not, see <http://www.gnu.org/licenses/>.
/// 
/// You can be released from the requirements of the GNU Affero General
/// Public License and obtain additional features by purchasing a
/// commercial license. Buying such a license is mandatory if you
/// engage in commercial activities involving OpenABE that do not
/// comply with the open source requirements of the GNU Affero General
/// Public License. For more information on commerical licenses,
/// visit <http://www.zeutro.com>.
///
/// \file   zelement.h
///
/// \brief  Base class definition for ZTK groups (EC/pairings)
///
/// \author J. Ayo Akinyele
///

#ifndef __ZELEMENT_H__
#define __ZELEMENT_H__

// Bignum library: follows bilinear pairing library choice
#if defined(BP_WITH_OPENSSL)
#define BN_WITH_OPENSSL
#endif

#if defined(BP_WITH_MCL)
#define BN_WITH_MCL
#endif

// Elliptic Curve library: can be chosen independently via EC_WITH_MCL or EC_WITH_OPENSSL
// EC_WITH_MCL and EC_WITH_OPENSSL are set by Makefile.common based on EC_LIB variable
// If neither is explicitly set, default to OpenSSL for EC operations
#if !defined(EC_WITH_MCL) && !defined(EC_WITH_OPENSSL)
#define EC_WITH_OPENSSL
#endif

#if defined(BP_WITH_OPENSSL)
#include <openssl/bp.h>
#endif

#if defined(BP_WITH_MCL)
 /* MCL uses C API for BN254 pairing */
 #define MCLBN_FP_UNIT_SIZE 4
 #define MCLBN_FR_UNIT_SIZE 4
 #include <mcl/bn.h>
#endif

#if !defined(BP_WITH_OPENSSL) && !defined(BP_WITH_MCL)
 #include <relic/relic.h>
 #include <relic_ec/relic.h>
 #include <openabe/zml/relic_compat.h>
#endif

// Include OpenSSL EC headers when using OpenSSL for EC operations
#if defined(EC_WITH_OPENSSL)
 #include <openssl/ec.h>
 #include <openssl/bn.h>
 #include <openssl/obj_mac.h>
#endif

/*************************** BN Definitions *********************/
#define TRUE   1
#define FALSE  0

#if defined(BN_WITH_OPENSSL)

/* BEGIN OpenSSL macro definitions */

typedef BIGNUM* bignum_t;

#define zml_bignum_free(b)                BN_free(b)
#define zml_bignum_safe_free(b)           OPENSSL_free(b)

#define zml_bignum_fromHex(b, str, len)   BN_hex2bn(&b, str)
#define zml_bignum_fromBin(b, ustr, len)  BN_bin2bn(ustr, len, b)
#define zml_bignum_toBin(b, str, len)     BN_bn2bin(b, str)
#define zml_bignum_setuint(b, x)          BN_set_word(b, x)

// returns 1 if true, otherwise 0
#define zml_bignum_is_zero(b)             BN_is_zero(b)
#define zml_bignum_is_one(b)              BN_is_one(b)

/** BN_is_negative returns 1 if the BIGNUM is negative
 * \param  a  pointer to the BIGNUM object
 * \return 1 if a < 0 and 0 otherwise
 */
#define BN_POSITIVE      0
#define BN_NEGATIVE      1

#define BN_CMP_LT       -1
#define BN_CMP_EQ        0
#define BN_CMP_GT        1
#define G_CMP_EQ         BN_CMP_EQ

/* END OpenSSL macro definitions */

#elif defined(BN_WITH_MCL)

/* BEGIN MCL macro definitions */

typedef mclBnFr* bignum_t;

#define zml_bignum_free(b)                mclBnFr_clear(b); free(b)
#define zml_bignum_safe_free(b)           free(b)
#define zml_bignum_is_zero(b)             mclBnFr_isZero(b)
#define zml_bignum_is_one(b)              mclBnFr_isOne(b)

#define BN_POSITIVE      0
#define BN_NEGATIVE      1
#define BN_CMP_LT       -1
#define BN_CMP_EQ        0
#define BN_CMP_GT        1
#define G_CMP_EQ         BN_CMP_EQ
#define CMP_EQ           0
#define CMP_LT          -1
#define CMP_GT           1

// MCL function declarations (implemented in zelement_mcl.c)
int zml_bignum_fromHex(bignum_t b, const char *str, size_t len);
int zml_bignum_fromBin(bignum_t b, const uint8_t *buf, size_t len);
size_t zml_bignum_toBin(const bignum_t b, uint8_t *buf, size_t max_len);
void zml_bignum_setuint(bignum_t b, unsigned int x);
void zml_bignum_rand(bignum_t a, bignum_t o);
int zml_check_error();

/* END MCL macro definitions */

#else

/* BEGIN RELIC macro definitions (default if BN_WITH_OPENSSL or BN_WITH_MCL not set) */

typedef bn_t bignum_t;

#define zml_bignum_free(b)            bn_free(b)
#define zml_bignum_safe_free(b)       if(b != NULL) free(b)

#define zml_bignum_fromHex(b, str, len)   bn_read_str(b, str, len, 16)
#define zml_bignum_fromBin(b, ustr, len)  bn_read_bin(b, ustr, len)
#define zml_bignum_toBin(b, str, len)     bn_write_bin(str, len, b)

#define zml_bignum_setuint(b, x)          bn_set_dig(b, x)
// returns 1 if true, otherwise 0
#define zml_bignum_is_zero(b)             bn_is_zero(b)
#define zml_bignum_is_one(b)              bn_is_one(b)

#define BN_CMP_LT                     CMP_LT
#define BN_CMP_EQ                     CMP_EQ
#define BN_CMP_GT                     CMP_GT

#define BN_POSITIVE                   BN_POS
#define BN_NEGATIVE                   BN_NEG
#define G_CMP_EQ                      CMP_EQ

int bn_is_one(const bn_t a);
/* END of RELIC macro definitions */
int zml_check_error();
void zml_bignum_rand(bignum_t a, bignum_t o);

#endif

/*************************** EC Definitions *********************/

#if defined(EC_WITH_OPENSSL)

/* BEGIN OpenSSL macro definitions */

typedef EC_POINT* ec_point_t;
typedef EC_GROUP* ec_group_t;

/* Elliptic curve operations */
#define ec_point_free(e)        EC_POINT_clear_free(e)
#define ec_group_free(g)        EC_GROUP_free(g)

#define ec_point_set_null(e)    e = nullptr
#define is_ec_point_null(e)     e == nullptr
#define ec_get_ref(a)           a
/* END of OpenSSL macro definitions */

#elif defined(EC_WITH_MCL)

/* BEGIN MCL EC macro definitions */
typedef void* ec_point_t;
typedef void* ec_group_t;

#define ec_point_free(e)        free(e)
#define ec_group_free(g)        g = NULL;
#define ec_point_set_null(e)    e = nullptr
#define is_ec_point_null(e)     (e == nullptr)
#define ec_get_ref(a)           a

/* END MCL EC macro definitions */

#else
/* if EC_WITH_OPENSSL or EC_WITH_MCL not specifically defined,
 * then we use RELIC EC operations by default */

 /* BEGIN RELIC macro definitions */
typedef ep_t ec_point_t;
typedef void* ec_group_t;

#define ep_inits(g) \
        ep_null(g); \
        ep_new(g);

#define ec_point_free(e)        ep_free(e)
#define ec_group_free(g)        g = NULL;

#define ec_point_set_null(e)    /* do nothing here */
#define is_ec_point_null(e)     false
#define ec_get_ref(a)           &a

/* END of RELIC macro definitions */
#endif

// init/clean internal structures
void zml_init();
void zml_clean();

// abstract bignum operations
void zml_bignum_init(bignum_t *a);
void zml_bignum_copy(bignum_t to, const bignum_t from);
int zml_bignum_sign(const bignum_t a);
int zml_bignum_cmp(const bignum_t a, const bignum_t b);
void zml_bignum_setzero(bignum_t a);
int zml_bignum_countbytes(const bignum_t a);
int zml_bignum_mod_inv(bignum_t a, const bignum_t b, const bignum_t o);
void zml_bignum_mod(bignum_t x, const bignum_t o);
void zml_bignum_negate(bignum_t b, const bignum_t o);
void zml_bignum_add(bignum_t r, const bignum_t x, const bignum_t y, const bignum_t o);
void zml_bignum_sub(bignum_t r, const bignum_t x, const bignum_t y);
void zml_bignum_sub_order(bignum_t r, const bignum_t x, const bignum_t y, const bignum_t o);
void zml_bignum_mul(bignum_t r, const bignum_t x, const bignum_t y, const bignum_t o);
void zml_bignum_div(bignum_t r, const bignum_t x, const bignum_t y, const bignum_t o);
void zml_bignum_exp(bignum_t r, const bignum_t x, const bignum_t y, const bignum_t o);

// logical operators for bignums
void zml_bignum_lshift(bignum_t r, const bignum_t a, int n);
void zml_bignum_rshift(bignum_t r, const bignum_t a, int n);

// NOTE: must free the memory that is returned from bignum_toHex and bignum_toDec using bignum_safe_free
char *zml_bignum_toHex(const bignum_t b, int *length);
char *zml_bignum_toDec(const bignum_t b, int *length);

// abstract elliptic curve operations
int ec_group_init(ec_group_t *group, uint8_t id);
void ec_get_order(ec_group_t group, bignum_t order);
void ec_point_init(ec_group_t group, ec_point_t *e);
void ec_point_copy(ec_point_t to, const ec_point_t from);
void ec_point_set_inf(ec_group_t group, ec_point_t p);
int  ec_point_cmp(ec_group_t group, const ec_point_t a, const ec_point_t b);
int  ec_point_is_inf(ec_group_t group, ec_point_t p);
void ec_get_generator(ec_group_t group, ec_point_t p);
void ec_get_coordinates(ec_group_t group, bignum_t x, bignum_t y, const ec_point_t p);
int ec_convert_to_point(ec_group_t group, ec_point_t p, uint8_t *xstr, int len);
int  ec_point_is_on_curve(ec_group_t group, ec_point_t p);
void ec_point_add(ec_group_t g, ec_point_t r, const ec_point_t x, const ec_point_t y);
void ec_point_mul(ec_group_t g, ec_point_t r, const ec_point_t x, const bignum_t y);

size_t ec_point_elem_len(const ec_point_t g);
void ec_point_elem_in(ec_point_t g, uint8_t *in, size_t len);
void ec_point_elem_out(const ec_point_t g, uint8_t *out, size_t len);

/*************************** BP Definitions *********************/

#if defined(BP_WITH_OPENSSL)

/* BEGIN OpenSSL macro definitions */

typedef BP_GROUP* bp_group_t;
#define bp_group_free(g) BP_GROUP_free(g);

typedef G1_ELEM* g1_ptr;
typedef G2_ELEM* g2_ptr;
typedef GT_ELEM* gt_ptr;

#define g_set_null(g)   g = nullptr;
#define g1_copy_const   G1_ELEM_copy
#define g2_copy_const   G2_ELEM_copy
#define gt_copy_const   GT_ELEM_copy

#define g1_element_free G1_ELEM_clear_free
#define g2_element_free G2_ELEM_clear_free
#define gt_element_free GT_clear_free

#define is_elem_null(e) e == nullptr

#elif defined(BP_WITH_MCL)

/* BEGIN MCL macro definitions */

typedef void* bp_group_t;  // MCL doesn't use group objects
#define bp_group_free(g)   g = nullptr;

typedef mclBnG1* g1_ptr;
typedef mclBnG2* g2_ptr;
typedef mclBnGT* gt_ptr;

#define g_set_null(g)      g = nullptr
#define g1_copy_const      mclBnG1_copy
#define g2_copy_const      mclBnG2_copy
#define gt_copy_const      mclBnGT_copy

#define g1_element_free(e) mclBnG1_clear(e); free(e)
#define g2_element_free(e) mclBnG2_clear(e); free(e)
#define gt_element_free(e) mclBnGT_clear(e); free(e)

#define is_elem_null(e)    (e == nullptr)

// MCL helper function declarations
void mclBnG1_copy(mclBnG1* y, const mclBnG1* x);
void mclBnG2_copy(mclBnG2* y, const mclBnG2* x);
void mclBnGT_copy(mclBnGT* y, const mclBnGT* x);

// MCL pairing helper function declarations (for C++ layer compatibility)
int g1_cmp(const g1_ptr a, const g1_ptr b);
void g1_neg(g1_ptr r, const g1_ptr a);
void g1_rand(g1_ptr g);
void g2_add(g2_ptr r, const g2_ptr a, const g2_ptr b);
void g2_sub(g2_ptr r, const g2_ptr a, const g2_ptr b);
void g2_neg(g2_ptr r, const g2_ptr a);
void g2_norm(g2_ptr r, const g2_ptr a);
void g2_rand(g2_ptr g);
int gt_cmp(const gt_ptr a, const gt_ptr b);
void gt_exp(gt_ptr r, const gt_ptr a, const bignum_t b);
void gt_inv(gt_ptr r, const gt_ptr a);
void gt_set_unity(gt_ptr a);
int gt_is_unity(const gt_ptr a);
int bn_is_even(const bignum_t a);
void oabe_rand_seed(unsigned char* buf, int buf_len);

/* END MCL macro definitions */

#else
/* if BP_WITH_OPENSSL or BP_WITH_MCL not specifically defined,
 * then we use RELIC EC operations by default */

 /* BEGIN RELIC macro definitions */

// ZTK-specific macros for RELIC
#define bn_inits(b) \
        bn_null(b); \
        bn_new(b);

#define g1_inits(g) \
        ep_null(g); \
        ep_new(g);

#define ep2_inits(g) \
        ep2_null(g); \
        ep2_new(g);

#define fp12_inits(g) \
        fp12_null(g); \
        fp12_new(g);

#define g1_copy_const    CAT(G1_LOWER, copy_const)
#define g2_copy_const    CAT(G2_LOWER, copy_const)
#define gt_copy_const    CAT(GT_LOWER, copy_const)
#define g1_set_rand      CAT(G1_LOWER, set_rand)
#define g2_set_rand      CAT(G2_LOWER, set_rand)
#define gt_set_rand      CAT(GT_LOWER, set_rand)
#define g1_write_ostream CAT(G1_LOWER, write_ostream)
#define g2_write_ostream CAT(G2_LOWER, write_ostream)
#define gt_write_ostream CAT(GT_LOWER, write_ostream)
#define gt_is_zero       CAT(GT_LOWER, is_zero)

void bn_copy_const(bn_t c, const bn_t a);
void ep_copy_const(ep_t r, const ep_t p);
void fp_copy_const(fp_t c, const fp_t a);
void ep2_copy_const(ep2_t r, const ep2_t p);
void fp2_copy_const(fp2_t c, const fp2_t a);
void fp12_copy_const(fp12_t c, const fp12_t a);
void fp6_copy_const(fp6_t c, const fp6_t a);

int bn_cmp_const(bn_t a, const bn_t b);
int bn_cmp_abs_const(const bn_t a, const bn_t b);
int bn_cmpn_low_const(const dig_t *a, const dig_t *b, const int size);
int ep_cmp_const(ep_t p, const ep_t q);
int ep2_cmp_const(ep2_t p, const ep2_t q);
int fp12_cmp_const(fp12_t a, const fp12_t b);
int fp6_cmp_const(fp6_t a, const fp6_t b);
int fp2_cmp_const(fp2_t a, const fp2_t b);
int fp_cmp_const(fp_t a, const fp_t b);
int fp_cmpn_low_const(dig_t *a, const dig_t *b);

typedef void* bp_group_t;
#define bp_group_free(g)   g = nullptr;

typedef ep_t g1_ptr;
typedef ep2_t g2_ptr;
typedef fp12_t gt_ptr;

#define g_set_null(g)
#define g1_element_free   g1_free
#define g2_element_free   g2_free
#define gt_element_free   gt_free

#define is_elem_null(e)   FALSE
/* END of RELIC macro definitions */
#endif

// C helper functions to handle (OpenSSL/RELIC)
int bp_group_init(bp_group_t *group, uint8_t id);
void bp_get_order(bp_group_t group, bignum_t order);
void bp_ensure_curve_params(uint8_t id);

// ZML abstract methods for G1
void g1_init(bp_group_t group, g1_ptr *e);
void g1_set_to_infinity(bp_group_t group, g1_ptr *e);
void g1_add_op(bp_group_t group, g1_ptr z, const g1_ptr x, const g1_ptr y);
void g1_sub_op(bp_group_t group, g1_ptr z, const g1_ptr x);
void g1_mul_op(bp_group_t group, g1_ptr z, const g1_ptr x, const bignum_t r);
void g1_rand_op(g1_ptr g);
void g1_map_op(const bp_group_t group, g1_ptr g, uint8_t *msg, int msg_len);

#if !defined(BP_WITH_OPENSSL)
size_t g1_elem_len(const g1_ptr g);
void g1_elem_in(g1_ptr g, uint8_t *in, size_t len);
void g1_elem_out(const g1_ptr g, uint8_t *out, size_t len);
size_t g2_elem_len(g2_ptr g);
void g2_elem_in(g2_ptr g, uint8_t *in, size_t len);
void g2_elem_out(g2_ptr g, uint8_t *out, size_t len);
size_t gt_elem_len(gt_ptr g, int should_compress);
void gt_elem_in(gt_ptr g, uint8_t *in, size_t len);
void gt_elem_out(gt_ptr g, uint8_t *out, size_t len, int should_compress);
#endif

// ZML abstract methods for G2
void g2_init(bp_group_t group, g2_ptr *e);
void g2_set_to_infinity(bp_group_t group, g2_ptr *e);
int g2_cmp_op(bp_group_t group, g2_ptr x, g2_ptr y);
void g2_mul_op(bp_group_t group, g2_ptr z, g2_ptr x, bignum_t r);
void g2_rand_op(g2_ptr g);

// ZML abstract methods for GT
void gt_init(const bp_group_t group, gt_ptr *e);
void gt_set_to_infinity(bp_group_t group, gt_ptr *e);
void gt_mul_op(const bp_group_t group, gt_ptr z, gt_ptr x, gt_ptr y);
void gt_div_op(const bp_group_t group, gt_ptr z, gt_ptr x, gt_ptr y);
void gt_exp_op(const bp_group_t group, gt_ptr y, gt_ptr x, bignum_t r);
int gt_is_unity_check(const bp_group_t group, gt_ptr r);

// ZML (pairings & multi-pairings)
void bp_map_op(const bp_group_t group, gt_ptr gt, g1_ptr g1, g2_ptr g2);

#endif /* ifdef __ZELEMENT_H__ */
