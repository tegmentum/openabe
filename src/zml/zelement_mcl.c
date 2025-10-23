///
/// \file   zelement_mcl.c
///
/// \brief  MCL backend implementation for ZML abstraction layer.
///         Implements bignum and pairing operations using MCL library.
///
/// \author OpenABE Contributors
///

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <openabe/zml/zelement.h>
#include <openabe/utils/zconstants.h>

#if defined(BP_WITH_MCL)

/********************************************************************************
 * MCL Library Initialization
 ********************************************************************************/

static int mcl_initialized = 0;
static int mcl_current_curve = -1;

// Initialize MCL with specific curve (called from bp_group_init)
int mcl_init_curve(int curve_id) {
  if (mcl_initialized && mcl_current_curve == curve_id) {
    // Already initialized with this curve
    return 0;
  }

  if (mcl_initialized && mcl_current_curve != curve_id) {
    // Need to switch curves - MCL requires re-initialization
    fprintf(stderr, "MCL: Switching from curve %d to curve %d\n",
            mcl_current_curve, curve_id);
    mcl_initialized = 0;
  }

  int ret = mclBn_init(curve_id, MCLBN_COMPILED_TIME_VAR);
  if (ret != 0) {
    fprintf(stderr, "MCL initialization failed for curve %d: %d\n", curve_id, ret);
    return -1;
  }

  mcl_initialized = 1;
  mcl_current_curve = curve_id;
  fprintf(stderr, "MCL: Initialized curve %d (%s)\n", curve_id,
          curve_id == MCL_BLS12_381 ? "BLS12-381" :
          curve_id == MCL_BLS12_377 ? "BLS12-377" :
          curve_id == MCL_BN254 ? "BN254" : "Unknown");
  return 0;
}

void zml_init() {
  // Default initialization with BLS12-381 (for backwards compatibility)
  // Note: bp_group_init will call mcl_init_curve with the actual curve needed
  if (!mcl_initialized) {
    mcl_init_curve(MCL_BLS12_381);
  }
}

void zml_clean() {
  // MCL doesn't require explicit cleanup
  mcl_initialized = 0;
  mcl_current_curve = -1;
}

/********************************************************************************
 * MCL Helper Functions
 ********************************************************************************/

void mclBnG1_copy(mclBnG1* y, const mclBnG1* x) {
  memcpy(y, x, sizeof(mclBnG1));
}

void mclBnG2_copy(mclBnG2* y, const mclBnG2* x) {
  memcpy(y, x, sizeof(mclBnG2));
}

void mclBnGT_copy(mclBnGT* y, const mclBnGT* x) {
  memcpy(y, x, sizeof(mclBnGT));
}

/********************************************************************************
 * Bignum Operations (Fr - Scalar Field)
 ********************************************************************************/

void zml_bignum_init(bignum_t *a) {
  // bignum_t is mclBnFr struct, just zero-initialize it
  memset(a, 0, sizeof(mclBnFr));
  mclBnFr_clear(a);
}

// zml_bignum_copy is now a macro for MCL (see zelement.h)
// The function version was buggy because it passed bignum_t by value,
// which doesn't work for struct types like mclBnFr.
// Using macro: #define zml_bignum_copy(to, from) ((to) = (from))

int zml_bignum_sign(const bignum_t a) {
  // MCL Fr elements are always in [0, r-1], so always non-negative
  return 0;
}

int zml_bignum_cmp(const bignum_t a, const bignum_t b) {
  if (mclBnFr_isEqual(&a, &b)) {
    return BN_CMP_EQ;
  }

  // Convert to decimal strings for comparison
  char buf_a[256], buf_b[256];
  size_t len_a = mclBnFr_getStr(buf_a, sizeof(buf_a), &a, 10);
  size_t len_b = mclBnFr_getStr(buf_b, sizeof(buf_b), &b, 10);

  // FIX Bug #3: Lexicographical string comparison doesn't work for numbers!
  // Example: "9" > "10" lexicographically, but 9 < 10 numerically
  // Solution: Compare string lengths first (longer = bigger for positive numbers)

  if (len_a < len_b) return BN_CMP_LT;
  if (len_a > len_b) return BN_CMP_GT;

  // Same length: strcmp works correctly for same-length decimal strings
  int cmp = strcmp(buf_a, buf_b);
  if (cmp < 0) return BN_CMP_LT;
  if (cmp > 0) return BN_CMP_GT;
  return BN_CMP_EQ;
}

// FIX Bug #15: These functions are now replaced by macros in zelement.h
// The macros directly call MCL functions with proper address-of operators (&)
// The function implementations below had pass-by-value bugs (bignum_t is a struct)
// and are no longer used when macros are active.
//
// NOTE: These are defined as macros in zelement.h:
// - zml_bignum_setzero, zml_bignum_mod, zml_bignum_negate
// - zml_bignum_add, zml_bignum_sub, zml_bignum_sub_order
// - zml_bignum_mul, zml_bignum_div, zml_bignum_exp
// - zml_bignum_mod_inv, zml_bignum_lshift, zml_bignum_rshift

int zml_bignum_countbytes(const bignum_t a) {
  // FIX Bug #15: MCL bignum_t is mclBnFr, use MCL serialization to get byte count
  // MCL already returns the minimal serialization, no need to trim zeros
  uint8_t buf[64];  // Fr elements are at most 32 bytes for BLS12-381
  size_t len = mclBnFr_serialize(buf, sizeof(buf), &a);
  return (int)len;
}

char *zml_bignum_toHex(const bignum_t b, int *length) {
  char *hex = (char*)malloc(256);
  if (hex == NULL) {
    *length = 0;
    return NULL;
  }

  *length = mclBnFr_getStr(hex, 256, &b, 16);
  return hex;
}

char *zml_bignum_toDec(const bignum_t b, int *length) {
  char *dec = (char*)malloc(256);
  if (dec == NULL) {
    *length = 0;
    return NULL;
  }

  *length = mclBnFr_getStr(dec, 256, &b, 10);
  return dec;
}

/********************************************************************************
 * Bignum I/O Operations
 ********************************************************************************/

// NOTE: zml_bignum_fromHex, zml_bignum_fromBin, zml_bignum_toBin, and zml_bignum_setuint
// are defined as macros in zelement.h for the MCL backend

/********************************************************************************
 * Pairing Group Initialization
 ********************************************************************************/

int bp_group_init(bp_group_t *group, uint8_t id) {
  int mcl_curve_id = -1;

  // Map OpenABE curve IDs to MCL curve IDs
  switch (id) {
    // BLS12 Curves (Pairing-friendly, modern, high security)
    case OpenABE_BLS12_P381_ID:
      mcl_curve_id = MCL_BLS12_381;  // 128-bit security
      break;

    // BN Curves (Pairing-friendly, legacy support)
    case OpenABE_BN_P254_ID:
      mcl_curve_id = MCL_BN254;      // ~100-bit security
      break;
    case OpenABE_BN_P256_ID:
      // BN256 is same as BN254 in MCL
      mcl_curve_id = MCL_BN254;
      break;
    case OpenABE_BN_P382_ID:
      // P382 maps to BLS12-381 for better standardization
      mcl_curve_id = MCL_BLS12_381;
      break;

    default:
      fprintf(stderr, "MCL: Unsupported curve ID: %d (0x%x)\n", id, id);
      return -1;
  }

  // Initialize MCL with the requested curve
  if (mcl_init_curve(mcl_curve_id) != 0) {
    return -1;
  }

  // Set group to a non-null value (MCL uses global state)
  *group = (void*)0x1;

  return 0;
}

void bp_get_order(bp_group_t group, bignum_t order) {
  // Get the order of the curve (same as Fr field order)
  char order_str[256];
  mclBn_getCurveOrder(order_str, sizeof(order_str));
  mclBnFr_setStr(&order, order_str, strlen(order_str), 10);
  (void)group;  // Suppress unused parameter warning
}

void bp_ensure_curve_params(uint8_t id) {
  // MCL doesn't need dynamic curve parameter setting
  // Curve is set during initialization
  (void)id;
}

/********************************************************************************
 * G1 Operations
 ********************************************************************************/

void g1_init(bp_group_t group, g1_ptr *e) {
  // g1_ptr is mclBnG1 struct, just zero-initialize it
  memset(e, 0, sizeof(mclBnG1));
  mclBnG1_clear(e);
  (void)group;
}

void g1_set_to_infinity(bp_group_t group, g1_ptr *e) {
  // g1_ptr is mclBnG1 struct, just zero-initialize it
  memset(e, 0, sizeof(mclBnG1));
  mclBnG1_clear(e);
  (void)group;
}

// FIX Bug #9: g1_ptr is mclBnG1 struct, must pass by pointer!
void g1_add_op(bp_group_t group, g1_ptr *z, const g1_ptr *x, const g1_ptr *y) {
  mclBnG1_add(z, x, y);
  (void)group;
}

// FIX Bug #9: g1_ptr is mclBnG1 struct, must pass by pointer!
void g1_sub_op(bp_group_t group, g1_ptr *z, const g1_ptr *x) {
  mclBnG1_sub(z, x, z);
  (void)group;
}

// FIX Bug #9: g1_ptr is mclBnG1 struct, must pass by pointer! CRITICAL for G1::exp
void g1_mul_op(bp_group_t group, g1_ptr *z, const g1_ptr *x, const bignum_t *r) {
  mclBnG1_mul(z, x, r);
  (void)group;
}

// FIX Bug #9: g1_ptr is mclBnG1 struct, must pass by pointer!
void g1_rand_op(g1_ptr *g) {
  // Generate random G1 element
  // In MCL, we can set a random Fr and multiply by generator
  mclBnFr r;
  memset(&r, 0, sizeof(r));
  // Use MCL's random function (note: requires proper RNG setup)
  mclBnFr_setByCSPRNG(&r);
  mclBnG1_hashAndMapTo(g, "", 0);  // Get a point
  mclBnG1_mul(g, g, &r);
}

// FIX Bug #9: g1_ptr is mclBnG1 struct, must pass by pointer! CRITICAL for hash-to-G1
void g1_map_op(const bp_group_t group, g1_ptr *g, uint8_t *msg, int msg_len) {
  mclBnG1_hashAndMapTo(g, msg, msg_len);
  (void)group;
}

size_t g1_elem_len(const g1_ptr g) {
  return mclBn_getG1ByteSize();
}

// FIX Bug #9: g1_ptr is mclBnG1 struct, must pass by pointer!
void g1_elem_in(g1_ptr *g, uint8_t *in, size_t len) {
  mclBnG1_deserialize(g, in, len);
}

// FIX Bug #9: g1_ptr is mclBnG1 struct, must pass by pointer!
void g1_elem_out(const g1_ptr *g, uint8_t *out, size_t len) {
  mclBnG1_serialize(out, len, g);
}

/********************************************************************************
 * G2 Operations
 ********************************************************************************/

void g2_init(bp_group_t group, g2_ptr *e) {
  // g2_ptr is mclBnG2 struct, just zero-initialize it
  memset(e, 0, sizeof(mclBnG2));
  mclBnG2_clear(e);
  (void)group;
}

void g2_set_to_infinity(bp_group_t group, g2_ptr *e) {
  // g2_ptr is mclBnG2 struct, just zero-initialize it
  memset(e, 0, sizeof(mclBnG2));
  mclBnG2_clear(e);
  (void)group;
}

// FIX Bug #9: g2_ptr is mclBnG2 struct, must pass by pointer! CRITICAL for G2::exp
void g2_mul_op(bp_group_t group, g2_ptr *z, const g2_ptr *x, const bignum_t *r) {
  mclBnG2_mul(z, x, r);
  (void)group;
}

// FIX Bug #9: g2_ptr is mclBnG2 struct, must pass by pointer!
int g2_cmp_op(bp_group_t group, const g2_ptr *x, const g2_ptr *y) {
  if (mclBnG2_isEqual(x, y)) {
    return G_CMP_EQ;
  }
  return 1;  // Not equal
  (void)group;
}

size_t g2_elem_len(g2_ptr g) {
  return mclBn_getG1ByteSize() * 2;  // G2 is twice the size of G1
}

// FIX Bug #9: g2_ptr is mclBnG2 struct, must pass by pointer!
void g2_elem_in(g2_ptr *g, uint8_t *in, size_t len) {
  mclBnG2_deserialize(g, in, len);
}

// FIX Bug #9: g2_ptr is mclBnG2 struct, must pass by pointer!
void g2_elem_out(const g2_ptr *g, uint8_t *out, size_t len) {
  mclBnG2_serialize(out, len, g);
}

/********************************************************************************
 * GT Operations
 ********************************************************************************/

void gt_init(const bp_group_t group, gt_ptr *e) {
  // gt_ptr is mclBnGT struct, just zero-initialize it
  memset(e, 0, sizeof(mclBnGT));
  // CRITICAL: Initialize to 1 (multiplicative identity)
  // All-zero GT elements are INVALID in MCL and break all operations!
  mclBnGT_setInt(e, 1);
  (void)group;
}

void gt_set_to_infinity(bp_group_t group, gt_ptr *e) {
  // gt_ptr is mclBnGT struct, just zero-initialize it
  memset(e, 0, sizeof(mclBnGT));
  mclBnGT_setInt(e, 1);  // Identity element
  (void)group;
}

// FIX Bug #9: gt_ptr is mclBnGT struct, must pass by pointer for output!
void gt_mul_op(const bp_group_t group, gt_ptr *z, const gt_ptr *x, const gt_ptr *y) {
  mclBnGT_mul(z, x, y);
  (void)group;
}

// FIX Bug #9: gt_ptr is mclBnGT struct, must pass by pointer for output!
void gt_div_op(const bp_group_t group, gt_ptr *z, const gt_ptr *x, const gt_ptr *y) {
  mclBnGT inv;
  memset(&inv, 0, sizeof(inv));
  mclBnGT_inv(&inv, y);
  mclBnGT_mul(z, x, &inv);
  (void)group;
}

// FIX Bug #9: gt_ptr is mclBnGT struct, must pass by pointer for output!
void gt_exp_op(const bp_group_t group, gt_ptr *y, const gt_ptr *x, const bignum_t *r) {
  mclBnGT_pow(y, x, r);
  (void)group;
}

// FIX Bug #9: gt_ptr is mclBnGT struct, must pass by pointer!
int gt_is_unity_check(const bp_group_t group, const gt_ptr *r) {
  return mclBnGT_isOne(r);
  (void)group;
}

// FIX Bug #9: For MCL, gt_ptr is struct so must pass by pointer
size_t gt_elem_len(const gt_ptr *g, int should_compress) {
  return mclBn_getG1ByteSize() * 12;  // GT is 12 times the size of G1
  (void)should_compress;
  (void)g;  // Not used for size calculation
}

// FIX Bug #9: For MCL, gt_ptr is struct so must pass by pointer
void gt_elem_in(gt_ptr *g, uint8_t *in, size_t len) {
  mclBnGT_deserialize(g, in, len);
}

// FIX Bug #9: For MCL, gt_ptr is struct so must pass by pointer
void gt_elem_out(const gt_ptr *g, uint8_t *out, size_t len, int should_compress) {
  mclBnGT_serialize(out, len, g);
  (void)should_compress;
}

/********************************************************************************
 * Pairing Operations
 ********************************************************************************/

// FIX Bug #9: For MCL, all ptr types are structs, must pass by pointer!
void bp_map_op(const bp_group_t group, gt_ptr *gt, const g1_ptr *g1, const g2_ptr *g2) {
  mclBn_pairing(gt, g1, g2);
  (void)group;
}

/********************************************************************************
 * Additional Helper Functions for C++ Layer
 ********************************************************************************/

// Random bignum generation
// FIX Bug #7: bignum_t is mclBnFr struct, must pass by pointer for output!
void zml_bignum_rand(bignum_t *a, const bignum_t *o) {
  mclBnFr_setByCSPRNG(a);
  (void)o;  // MCL handles modular reduction automatically
}

// Error checking (MCL doesn't have error states like RELIC)
int zml_check_error() {
  return 1;  // TRUE = no error (MCL doesn't have error tracking like RELIC)
}

// NOTE: g1_cmp, g1_neg, g2_add, g2_sub, g2_norm, gt_cmp, g2_neg, gt_exp, gt_inv, gt_set_unity
// are defined as macros in zelement.h for the MCL backend

// GT check if unity (identity element)
int gt_is_unity(const gt_ptr a) {
  return mclBnGT_isOne(&a);
}

// Check if bignum is even
int bn_is_even(const bignum_t a) {
  // Get the least significant bit
  // If LSB is 0, number is even (return 1)
  // If LSB is 1, number is odd (return 0)
  char buf[1];
  size_t n = mclBnFr_serialize(buf, 1, &a);
  if (n == 0) return 1;  // Zero is even
  return (buf[0] & 1) ? 0 : 1;
}

// G1 random generation (needed for setRandom)
// FIX Bug #9: g1_ptr is mclBnG1 struct, must pass by pointer!
void g1_rand(g1_ptr *g) {
  // Generate a random scalar
  mclBnFr r;
  mclBnFr_setByCSPRNG(&r);

  // Get a fixed base point by hashing a known string
  // This ensures we always use the same generator
  int ret = mclBnG1_hashAndMapTo(g, "OpenABE-G1-base", 15);
  if (ret != 0) {
    fprintf(stderr, "[G1_RAND ERROR] mclBnG1_hashAndMapTo failed with code %d\n", ret);
    return;
  }

  // Multiply by random scalar: g = generator * r
  mclBnG1_mul(g, g, &r);
}

// G2 random generation
// FIX Bug #9: g2_ptr is mclBnG2 struct, must pass by pointer!
void g2_rand(g2_ptr *g) {
  // Generate a random scalar
  mclBnFr r;
  mclBnFr_setByCSPRNG(&r);

  // Get a fixed base point by hashing a known string
  int ret = mclBnG2_hashAndMapTo(g, "OpenABE-G2-base", 15);
  if (ret != 0) {
    // Fallback: just return - the element will be invalid
    return;
  }

  // Multiply by random scalar: g = generator * r
  mclBnG2_mul(g, g, &r);
}

// RNG seed function (MCL uses system RNG, this is a no-op)
void oabe_rand_seed(unsigned char* buf, int buf_len) {
  (void)buf;
  (void)buf_len;
  // MCL uses system CSPRNG, no manual seeding needed
}

// EC (non-pairing) operations are now implemented in:
// - zelement_ec_mcl.cpp (when EC_WITH_MCL is defined)
// - zelement_ec_openssl.cpp (when EC_WITH_OPENSSL is defined)

#endif /* BP_WITH_MCL */
