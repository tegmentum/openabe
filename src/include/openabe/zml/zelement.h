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

#if defined(BP_WITH_OPENSSL)
#define EC_WITH_OPENSSL
#define BN_WITH_OPENSSL
#elif defined(BP_WITH_MCL)
#define BN_WITH_MCL
#elif defined(BP_WITH_RABE)
#define BN_WITH_RABE
#endif

#if defined(BP_WITH_OPENSSL)
#include <openssl/bp.h>
#endif

#if defined(EC_WITH_OPENSSL)
#include <openssl/ec.h>
#include <openssl/bn.h>
#endif

#if defined(BP_WITH_MCL)
 #include <mcl/bn.h>
 // For C++ builds, include MCL C++ template API before typedef
 #if defined(__cplusplus)
  #include <mcl/bls12_381.hpp>
  #include <new>  // For placement new
  #include <string>  // For std::string
 #endif
#elif defined(BP_WITH_RABE)
 // RABE backend - uses Rust FFI
 #include <rabe_bls12381.h>
#elif !defined(BP_WITH_OPENSSL)
 #include <relic/relic.h>
 #include <relic_ec/relic.h>
 #include <openabe/zml/relic_compat.h>
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

/* BEGIN MCL C++ API definitions */

// Use MCL's C++ template API directly - no more macros!
// The Fr class provides operator overloading (+, -, *, /, etc.)
// This eliminates ~80 lines of complex macro wrappers.

// IMPORTANT: MCL C++ template headers must be included OUTSIDE extern "C" blocks
// They are included in openabe.h before the extern "C" that includes this file
#ifdef __cplusplus
// Use MCL's Fr class directly as bignum_t (header included in openabe.h)
typedef mcl::bls12::Fr bignum_t;

// Helper functions for compatibility with existing OpenABE code
// These replace the old macros with inline functions

inline void zml_bignum_init(bignum_t* b) {
    // Fr default constructor already initializes to zero
    new (b) bignum_t();  // Placement new to ensure proper initialization
}

inline void zml_bignum_free(bignum_t& b) {
    // Fr destructor is trivial, just clear the value
    b.clear();
}

inline void zml_bignum_safe_free(void* p) {
    free(p);
}

inline void zml_bignum_fromHex(bignum_t& b, const char* str, size_t len) {
#ifdef CYBOZU_DONT_USE_STRING
    // WASM: use C string API (setStr expects bool*, const char*, ioMode)
    // Note: str must be null-terminated for WASM API
    bool err = false;
    b.setStr(&err, str, 16);
    (void)len;  // Unused in WASM - relies on null termination
#else
    // Native: use std::string API
    b.setStr(std::string(str, len), 16);
#endif
}

inline void zml_bignum_fromBin(bignum_t& b, const uint8_t* data, size_t len) {
    b.deserialize(data, len);
}

inline size_t zml_bignum_toBin(const bignum_t& b, uint8_t* data, size_t len) {
    return b.serialize(data, len);
}

inline void zml_bignum_setuint(bignum_t& b, uint32_t x) {
    b = (int)x;  // Fr supports assignment from int
}

inline bool zml_bignum_is_zero(const bignum_t& b) {
    return b.isZero();
}

inline bool zml_bignum_is_one(const bignum_t& b) {
    return b.isOne();
}

inline void zml_bignum_copy(bignum_t& to, const bignum_t& from) {
    to = from;  // Use C++ assignment operator
}

// Arithmetic operations using C++ operators
inline void zml_bignum_add(bignum_t& r, const bignum_t& x, const bignum_t& y, const bignum_t& o) {
    (void)o;  // order not needed for Fr operations (always mod p)
    r = x + y;
}

inline void zml_bignum_sub(bignum_t& r, const bignum_t& x, const bignum_t& y) {
    r = x - y;
}

inline void zml_bignum_sub_order(bignum_t& r, const bignum_t& x, const bignum_t& y, const bignum_t& o) {
    (void)o;
    r = x - y;
}

inline void zml_bignum_mul(bignum_t& r, const bignum_t& x, const bignum_t& y, const bignum_t& o) {
    (void)o;
    r = x * y;
}

inline void zml_bignum_div(bignum_t& r, const bignum_t& x, const bignum_t& y, const bignum_t& o) {
    (void)o;
    r = x / y;
}

inline void zml_bignum_negate(bignum_t& b, const bignum_t& o) {
    (void)o;
    b = -b;
}

inline void zml_bignum_mod(bignum_t& x, const bignum_t& o) {
    (void)o;
    // No-op: Fr elements are always reduced modulo the field order
}

inline void zml_bignum_exp(bignum_t& r, const bignum_t& x, const bignum_t& y, const bignum_t& o) {
    (void)o;
    // Power operation - need to convert y to integer
#ifdef CYBOZU_DONT_USE_STRING
    // WASM: use C string API (getStr requires buffer and size)
    char buf[256];
    y.getStr(buf, sizeof(buf), 10);
    unsigned long exp = strtoul(buf, NULL, 10);
#else
    // Native: use std::string API
    std::string y_str = y.getStr(10);
    unsigned long exp = strtoul(y_str.c_str(), NULL, 10);
#endif
    bignum_t result, base;
    result = 1;  // Fr supports assignment from int
    base = x;
    for (unsigned long i = 0; i < exp; i++) {
        result = result * base;
    }
    r = result;
}

inline void zml_bignum_lshift(bignum_t& r, const bignum_t& a, int n) {
    bignum_t two, power;
    two = 2;
    power = 1;
    for (int i = 0; i < n; i++) {
        power = power * two;
    }
    r = a * power;
}

inline void zml_bignum_rshift(bignum_t& r, const bignum_t& a, int n) {
    bignum_t two, power;
    two = 2;
    power = 1;
    for (int i = 0; i < n; i++) {
        power = power * two;
    }
    r = a / power;
}

inline int zml_bignum_mod_inv(bignum_t& a, const bignum_t& b, const bignum_t& o) {
    (void)o;
    bignum_t one;
    one = 1;
    a = one / b;  // In field arithmetic, division is multiplicative inverse
    return 1;
}

inline void zml_bignum_setzero(bignum_t& a) {
    a.clear();
}

#else
// C code still needs the old C API with mclBnFr struct
typedef mclBnFr bignum_t;
// Define C macros for C code (not shown for brevity)
#endif /* __cplusplus */

#define BN_CMP_LT                     -1
#define BN_CMP_EQ                     0
#define BN_CMP_GT                     1

#define BN_POSITIVE                   0
#define BN_NEGATIVE                   1
#define G_CMP_EQ                      0

/* END of MCL C++ API definitions */
int zml_check_error();
void zml_bignum_rand(bignum_t *a, const bignum_t *o);

#elif defined(BN_WITH_RABE)

/* BEGIN RABE C API definitions */

// RABE uses opaque pointer types for all elements
// Memory is managed by the Rust library via FFI

typedef RabeFr* bignum_t;

#define zml_bignum_free(b)            rabe_fr_free(b)
#define zml_bignum_safe_free(b)       if(b != NULL) free(b)

#define zml_bignum_setuint(b, x)      rabe_fr_set_int(b, x)
#define zml_bignum_is_zero(b)         rabe_fr_is_zero(b)
#define zml_bignum_is_one(b)          (0)  /* TODO: implement */

#define BN_CMP_LT                     -1
#define BN_CMP_EQ                     0
#define BN_CMP_GT                     1

#define BN_POSITIVE                   0
#define BN_NEGATIVE                   1
#define G_CMP_EQ                      0

/* Bignum conversion functions - implemented in zelement_rabe.cpp */
#ifdef __cplusplus
extern "C" {
#endif
void zml_bignum_fromHex(bignum_t b, const char* str, size_t len);
void zml_bignum_fromBin(bignum_t b, const uint8_t* data, size_t len);
void zml_bignum_toBin(const bignum_t b, uint8_t* data, size_t len);
int zml_check_error();
void zml_bignum_rand(bignum_t *a, const bignum_t *o);
#ifdef __cplusplus
}
#endif
/* END of RABE C API definitions */

#else

/* BEGIN RELIC macro definitions (default if BN_WITH_OPENSSL/MCL not set) */

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

#elif defined(BP_WITH_MCL)
/* When using MCL for BP operations, EC operations are not used.
 * Define dummy types and no-op macros for compatibility. */
typedef void* ec_point_t;
typedef void* ec_group_t;

/* Define no-op EC macros for MCL-only builds */
#define ec_point_free(e)        /* no-op */
#define ec_group_free(g)        /* no-op */
#define ec_point_set_null(e)    e = nullptr
#define is_ec_point_null(e)     (e == nullptr)
#define ec_get_ref(a)           a

#elif defined(BP_WITH_RABE)
/* When using RABE for BP operations, EC operations are not used.
 * Define dummy types and no-op macros for compatibility. */
typedef void* ec_point_t;
typedef void* ec_group_t;

/* Define no-op EC macros for RABE-only builds */
#define ec_point_free(e)        /* no-op */
#define ec_group_free(g)        /* no-op */
#define ec_point_set_null(e)    e = nullptr
#define is_ec_point_null(e)     (e == nullptr)
#define ec_get_ref(a)           a

#else
/* if EC_WITH_OPENSSL and BP_WITH_MCL/RABE not specifically defined,
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

// C function declarations - need C linkage when used from C++
#ifdef __cplusplus
extern "C" {
#endif

// init/clean internal structures
void zml_init();
void zml_clean();

// abstract bignum operations
// For MCL C++ backend, many functions are inline (defined above)
// For other backends, they're C function declarations
#if !defined(BN_WITH_MCL) || !defined(__cplusplus)
void zml_bignum_init(bignum_t *a);
void zml_bignum_copy(bignum_t to, const bignum_t from);
#endif
int zml_bignum_sign(const bignum_t a);
int zml_bignum_cmp(const bignum_t a, const bignum_t b);
int zml_bignum_countbytes(const bignum_t a);

// For MCL C++ backend, inline functions are used (defined above), no need for C declarations
// For other backends (OpenSSL, RELIC), we need C function declarations
#if !defined(BN_WITH_MCL) || !defined(__cplusplus)

void zml_bignum_setzero(bignum_t a);
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

#endif /* !BN_WITH_MCL || !__cplusplus */

// NOTE: must free the memory that is returned from bignum_toHex and bignum_toDec using bignum_safe_free
char *zml_bignum_toHex(const bignum_t b, int *length);
char *zml_bignum_toDec(const bignum_t b, int *length);

// Helper functions
int bn_is_even(const bignum_t a);

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

typedef void* bp_group_t;
#define bp_group_free(g)   g = nullptr;

typedef mclBnG1 g1_ptr;
typedef mclBnG2 g2_ptr;
typedef mclBnGT gt_ptr;

// MCL comparison constants (matching RELIC behavior)
#define CMP_EQ   0
#define CMP_NE   1
#define CMP_LT   -1
#define CMP_GT   1

#define g_set_null(g)   memset(&g, 0, sizeof(g))
#define g1_copy_const(r, p)   memcpy(&r, &p, sizeof(mclBnG1))
#define g2_copy_const(r, p)   memcpy(&r, &p, sizeof(mclBnG2))
#define gt_copy_const(r, p)   memcpy(&r, &p, sizeof(mclBnGT))

#define g1_element_free(e)   memset(&e, 0, sizeof(e))
#define g2_element_free(e)   memset(&e, 0, sizeof(e))
#define gt_element_free(e)   memset(&e, 0, sizeof(e))

#define is_elem_null(e)   FALSE

// FIX Bug #17: Use MCL's proper comparison functions instead of memcmp
// MCL's isEqual functions return non-zero (true) if equal, 0 (false) if not equal
#define g1_cmp(a, b)   (mclBnG1_isEqual(&(a), &(b)) ? CMP_EQ : CMP_NE)
#define g2_cmp(a, b)   (mclBnG2_isEqual(&(a), &(b)) ? CMP_EQ : CMP_NE)
#define gt_cmp(a, b)   (mclBnGT_isEqual(&(a), &(b)) ? CMP_EQ : CMP_NE)

// MCL group operation macros
#define g1_neg(r, p)         mclBnG1_neg(&r, &p)
#define g2_add(r, a, b)      mclBnG2_add(&r, &a, &b)
#define g2_sub(r, a, b)      mclBnG2_sub(&r, &a, &b)
#define g2_neg(r, p)         mclBnG2_neg(&r, &p)
#define g2_norm(r, p)        mclBnG2_normalize(&r, &p)
#define gt_inv(r, p)         mclBnGT_inv(&r, &p)
#define gt_set_unity(g)      mclBnGT_setInt(&g, 1)

/* END of MCL macro definitions */

#elif defined(BP_WITH_RABE)

/* BEGIN RABE macro definitions */

typedef void* bp_group_t;
#define bp_group_free(g)   g = nullptr;

// RABE uses wrapper structs containing opaque pointers
// This matches MCL's struct-based approach for API compatibility
typedef struct { RabeG1* ptr; } g1_ptr;
typedef struct { RabeG2* ptr; } g2_ptr;
typedef struct { RabeGt* ptr; } gt_ptr;

// RABE comparison constants (matching RELIC behavior)
#define CMP_EQ   0
#define CMP_NE   1
#define CMP_LT   -1
#define CMP_GT   1

#define g_set_null(g)   (g).ptr = nullptr
#define g1_copy_const(r, p)   rabe_g1_copy((r).ptr, (p).ptr)
#define g2_copy_const(r, p)   rabe_g2_copy((r).ptr, (p).ptr)
#define gt_copy_const(r, p)   rabe_gt_copy((r).ptr, (p).ptr)

#define g1_element_free(e)   do { if ((e).ptr) rabe_g1_free((e).ptr); (e).ptr = nullptr; } while(0)
#define g2_element_free(e)   do { if ((e).ptr) rabe_g2_free((e).ptr); (e).ptr = nullptr; } while(0)
#define gt_element_free(e)   do { if ((e).ptr) rabe_gt_free((e).ptr); (e).ptr = nullptr; } while(0)

#define is_elem_null(e)   ((e).ptr == nullptr)

// RABE comparison macros - return CMP_EQ (0) if equal, CMP_NE (1) otherwise
#define g1_cmp(a, b)   rabe_g1_cmp((a).ptr, (b).ptr)
#define g2_cmp(a, b)   rabe_g2_cmp((a).ptr, (b).ptr)
#define gt_cmp(a, b)   rabe_gt_cmp((a).ptr, (b).ptr)

// RABE group operation macros
#define g1_neg(r, p)         rabe_g1_neg((r).ptr, (p).ptr)
#define g2_add(r, a, b)      rabe_g2_add((r).ptr, (a).ptr, (b).ptr)
#define g2_sub(r, a, b)      rabe_g2_sub((r).ptr, (a).ptr, (b).ptr)
#define g2_neg(r, p)         rabe_g2_neg((r).ptr, (p).ptr)
#define g2_norm(r, p)        rabe_g2_copy((r).ptr, (p).ptr)  // No normalization needed
#define gt_inv(r, p)         rabe_gt_inv((r).ptr, (p).ptr)
#define gt_set_unity(g)      rabe_gt_set_one((g).ptr)

/* END of RABE macro definitions */

#else
/* if BP_WITH_OPENSSL and BP_WITH_MCL not defined,
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
#if defined(BP_WITH_MCL) || defined(BP_WITH_RABE)
// For MCL/RABE, g1_ptr is struct/pointer so must pass by pointer
void g1_add_op(bp_group_t group, g1_ptr *z, const g1_ptr *x, const g1_ptr *y);
void g1_sub_op(bp_group_t group, g1_ptr *z, const g1_ptr *x);
void g1_mul_op(bp_group_t group, g1_ptr *z, const g1_ptr *x, const bignum_t *r);
void g1_map_op(const bp_group_t group, g1_ptr *g, uint8_t *msg, int msg_len);
#else
void g1_add_op(bp_group_t group, g1_ptr z, const g1_ptr x, const g1_ptr y);
void g1_sub_op(bp_group_t group, g1_ptr z, const g1_ptr x);
void g1_mul_op(bp_group_t group, g1_ptr z, const g1_ptr x, const bignum_t r);
void g1_map_op(const bp_group_t group, g1_ptr g, uint8_t *msg, int msg_len);
#endif
#if defined(BP_WITH_MCL) || defined(BP_WITH_RABE)
// For MCL/RABE, g1_ptr is struct/pointer so must pass by pointer
void g1_rand_op(g1_ptr *g);
#else
void g1_rand_op(g1_ptr g);
#endif

#if !defined(BP_WITH_OPENSSL)
size_t g1_elem_len(const g1_ptr g);
#if defined(BP_WITH_MCL) || defined(BP_WITH_RABE)
// For MCL/RABE, g1_ptr is struct/pointer so must pass by pointer
void g1_elem_in(g1_ptr *g, uint8_t *in, size_t len);
void g1_elem_out(const g1_ptr *g, uint8_t *out, size_t len);
#else
void g1_elem_in(g1_ptr g, uint8_t *in, size_t len);
void g1_elem_out(const g1_ptr g, uint8_t *out, size_t len);
#endif
size_t g2_elem_len(g2_ptr g);
#if defined(BP_WITH_MCL) || defined(BP_WITH_RABE)
// For MCL/RABE, g2_ptr is struct/pointer so must pass by pointer
void g2_elem_in(g2_ptr *g, uint8_t *in, size_t len);
void g2_elem_out(const g2_ptr *g, uint8_t *out, size_t len);
#else
void g2_elem_in(g2_ptr g, uint8_t *in, size_t len);
void g2_elem_out(g2_ptr g, uint8_t *out, size_t len);
#endif
#if defined(BP_WITH_MCL) || defined(BP_WITH_RABE)
// For MCL/RABE, gt_ptr is struct/pointer so must pass by pointer
size_t gt_elem_len(const gt_ptr *g, int should_compress);
void gt_elem_in(gt_ptr *g, uint8_t *in, size_t len);
void gt_elem_out(const gt_ptr *g, uint8_t *out, size_t len, int should_compress);
#else
// FIX Bug #18: For RELIC with BLS12-381, gt_ptr is fp12_t (multidimensional array)
// Must pass by pointer to handle array types correctly
size_t gt_elem_len(const gt_ptr *g, int should_compress);
void gt_elem_in(gt_ptr *g, uint8_t *in, size_t len);
void gt_elem_out(const gt_ptr *g, uint8_t *out, size_t len, int should_compress);
#endif
#endif

// ZML abstract methods for G2
void g2_init(bp_group_t group, g2_ptr *e);
void g2_set_to_infinity(bp_group_t group, g2_ptr *e);
#if defined(BP_WITH_MCL) || defined(BP_WITH_RABE)
// For MCL/RABE, g2_ptr is struct/pointer so must pass by pointer
int g2_cmp_op(bp_group_t group, const g2_ptr *x, const g2_ptr *y);
void g2_mul_op(bp_group_t group, g2_ptr *z, const g2_ptr *x, const bignum_t *r);
#else
int g2_cmp_op(bp_group_t group, g2_ptr x, g2_ptr y);
void g2_mul_op(bp_group_t group, g2_ptr z, g2_ptr x, bignum_t r);
#endif
void g2_rand_op(g2_ptr g);

// ZML abstract methods for GT
void gt_init(const bp_group_t group, gt_ptr *e);
void gt_set_to_infinity(bp_group_t group, gt_ptr *e);
#if defined(BP_WITH_MCL) || defined(BP_WITH_RABE)
// For MCL/RABE, gt_ptr is struct/pointer so must pass by pointer
void gt_mul_op(const bp_group_t group, gt_ptr *z, const gt_ptr *x, const gt_ptr *y);
void gt_div_op(const bp_group_t group, gt_ptr *z, const gt_ptr *x, const gt_ptr *y);
void gt_exp_op(const bp_group_t group, gt_ptr *y, const gt_ptr *x, const bignum_t *r);
int gt_is_unity_check(const bp_group_t group, const gt_ptr *r);
#else
void gt_mul_op(const bp_group_t group, gt_ptr z, gt_ptr x, gt_ptr y);
void gt_div_op(const bp_group_t group, gt_ptr z, gt_ptr x, gt_ptr y);
void gt_exp_op(const bp_group_t group, gt_ptr y, gt_ptr x, bignum_t r);
int gt_is_unity_check(const bp_group_t group, gt_ptr r);
#endif

// GT helper functions
#if defined(BP_WITH_MCL) || defined(BP_WITH_RABE)
int gt_is_unity(const gt_ptr a);
#endif

// ZML (pairings & multi-pairings)
#if defined(BP_WITH_MCL) || defined(BP_WITH_RABE)
// For MCL/RABE, all ptr types are structs/pointers so must pass by pointer
void bp_map_op(const bp_group_t group, gt_ptr *gt, const g1_ptr *g1, const g2_ptr *g2);
#else
void bp_map_op(const bp_group_t group, gt_ptr gt, g1_ptr g1, g2_ptr g2);
#endif

#ifdef __cplusplus
}  // extern "C"
#endif

#endif /* ifdef __ZELEMENT_H__ */
