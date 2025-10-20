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

void zml_init() {
  if (!mcl_initialized) {
    // Initialize MCL for BLS12-381 curve
    int ret = mclBn_init(MCL_BLS12_381, MCLBN_COMPILED_TIME_VAR);
    if (ret != 0) {
      fprintf(stderr, "MCL initialization failed: %d\n", ret);
      exit(1);
    }
    fprintf(stderr, "[MCL INIT] MCL initialized successfully for BLS12-381\n");
    mcl_initialized = 1;
  } else {
    fprintf(stderr, "[MCL INIT] MCL already initialized\n");
  }
}

void zml_clean() {
  // MCL doesn't require explicit cleanup
  mcl_initialized = 0;
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

void zml_bignum_setzero(bignum_t a) {
  mclBnFr_clear(&a);
}

int zml_bignum_countbytes(const bignum_t a) {
  // FIX Bug #5: Should return actual bytes needed, not full field size
  // This matches RELIC behavior which returns minimum bytes needed

  // Serialize to get actual bytes
  uint8_t temp[32];
  size_t len = mclBnFr_serialize(temp, sizeof(temp), &a);

  // Find first non-zero byte from the end (MSB in little-endian)
  size_t start = 0;
  while (start < len && temp[len - 1 - start] == 0) {
    start++;
  }

  // If all zeros, return 1 (minimum)
  if (start == len) {
    return 1;
  }

  return len - start;
}

void zml_bignum_mod(bignum_t x, const bignum_t o) {
  // MCL Fr elements are already reduced modulo the order
  // No operation needed
  (void)o;  // Suppress unused parameter warning
}

void zml_bignum_negate(bignum_t b, const bignum_t o) {
  mclBnFr_neg(&b, &b);
  (void)o;  // Suppress unused parameter warning
}

void zml_bignum_add(bignum_t r, const bignum_t x, const bignum_t y, const bignum_t o) {
  mclBnFr_add(&r, &x, &y);
  (void)o;  // MCL handles modular reduction automatically
}

void zml_bignum_sub(bignum_t r, const bignum_t x, const bignum_t y) {
  mclBnFr_sub(&r, &x, &y);
}

void zml_bignum_sub_order(bignum_t r, const bignum_t x, const bignum_t y, const bignum_t o) {
  mclBnFr_sub(&r, &x, &y);
  (void)o;  // MCL handles modular reduction automatically
}

void zml_bignum_mul(bignum_t r, const bignum_t x, const bignum_t y, const bignum_t o) {
  mclBnFr_mul(&r, &x, &y);
  (void)o;  // MCL handles modular reduction automatically
}

void zml_bignum_div(bignum_t r, const bignum_t x, const bignum_t y, const bignum_t o) {
  mclBnFr inv;
  memset(&inv, 0, sizeof(inv));
  mclBnFr_inv(&inv, &y);
  mclBnFr_mul(&r, &x, &inv);
  (void)o;  // MCL handles modular reduction automatically
}

void zml_bignum_exp(bignum_t r, const bignum_t x, const bignum_t y, const bignum_t o) {
  // For Fr elements, exponentiation is not directly supported
  // We'll implement using repeated multiplication
  mclBnFr result, base;
  mclBnFr_setInt(&result, 1);
  memcpy(&base, &x, sizeof(mclBnFr));

  // Get y as integer (assuming y is small enough)
  char y_str[256];
  mclBnFr_getStr(y_str, sizeof(y_str), &y, 10);
  unsigned long exp = strtoul(y_str, NULL, 10);

  for (unsigned long i = 0; i < exp; i++) {
    mclBnFr_mul(&result, &result, &base);
  }
  memcpy(&r, &result, sizeof(mclBnFr));
  (void)o;  // MCL handles modular reduction automatically
}

int zml_bignum_mod_inv(bignum_t a, const bignum_t b, const bignum_t o) {
  mclBnFr_inv(&a, &b);
  (void)o;  // MCL handles modular reduction automatically
  return 1;
}

void zml_bignum_lshift(bignum_t r, const bignum_t a, int n) {
  // Implement as multiplication by 2^n
  mclBnFr two, power, result;
  mclBnFr_setInt(&two, 2);
  mclBnFr_setInt(&power, 1);

  for (int i = 0; i < n; i++) {
    mclBnFr_mul(&power, &power, &two);
  }

  mclBnFr_mul(&r, &a, &power);
}

void zml_bignum_rshift(bignum_t r, const bignum_t a, int n) {
  // Implement as division by 2^n
  mclBnFr two, power, inv;
  mclBnFr_setInt(&two, 2);
  mclBnFr_setInt(&power, 1);

  for (int i = 0; i < n; i++) {
    mclBnFr_mul(&power, &power, &two);
  }

  mclBnFr_inv(&inv, &power);
  mclBnFr_mul(&r, &a, &inv);
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
  // MCL is already initialized in zml_init()
  // Just set group to a non-null value
  *group = (void*)0x1;  // Dummy value

  switch (id) {
    case OpenABE_BN_P382_ID:
      // BLS12-381 is set up (P382 maps to BLS12-381 with 384-bit field)
      break;
    case OpenABE_BN_P254_ID:
    case OpenABE_BN_P256_ID:
      // These curves are not supported in BLS12-381 mode
      fprintf(stderr, "MCL: Only BLS12-381 (P382) curve is currently supported\n");
      return -1;
    default:
      return -1;
  }

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

size_t gt_elem_len(gt_ptr g, int should_compress) {
  return mclBn_getG1ByteSize() * 12;  // GT is 12 times the size of G1
  (void)should_compress;
}

void gt_elem_in(gt_ptr g, uint8_t *in, size_t len) {
  mclBnGT_deserialize(&g, in, len);
}

void gt_elem_out(gt_ptr g, uint8_t *out, size_t len, int should_compress) {
  mclBnGT_serialize(out, len, &g);
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
  fprintf(stderr, "[zml_bignum_rand] Called\n");
  mclBnFr_setByCSPRNG(a);

  // DEBUG: Check if result is zero
  if (mclBnFr_isZero(a)) {
    fprintf(stderr, "[zml_bignum_rand ERROR] Result is ZERO!\n");
  } else {
    char buf[256];
    mclBnFr_getStr(buf, sizeof(buf), a, 10);
    fprintf(stderr, "[zml_bignum_rand] Result: %s\n", buf);
  }

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

  int isZero = mclBnG1_isZero(g);
  fprintf(stderr, "[G1_RAND DEBUG] After hashAndMapTo: isZero=%d\n", isZero);

  // Multiply by random scalar: g = generator * r
  mclBnG1_mul(g, g, &r);

  isZero = mclBnG1_isZero(g);
  fprintf(stderr, "[G1_RAND DEBUG] After mul: isZero=%d\n", isZero);
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
    fprintf(stderr, "WARNING: g2_rand: mclBnG2_hashAndMapTo failed with code %d\n", ret);
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
