/**
 * rabe-bls12381 C FFI Header
 *
 * C-compatible bindings for the Rust BLS12-381 pairing library.
 * This header provides functions matching the OpenABE zelement API.
 */

#ifndef RABE_BLS12381_H
#define RABE_BLS12381_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Opaque handle types */
typedef struct RabeFr RabeFr;
typedef struct RabeG1 RabeG1;
typedef struct RabeG2 RabeG2;
typedef struct RabeGt RabeGt;

/* Size constants */
extern const size_t RABE_FR_SIZE;
extern const size_t RABE_G1_SIZE;
extern const size_t RABE_G2_SIZE;
extern const size_t RABE_GT_SIZE;

/* Library initialization */
void rabe_zml_init(void);
void rabe_zml_clean(void);
int rabe_init_curve(int curve_id);

/* ============================================================================
 * Fr (Scalar Field) Operations
 * ============================================================================ */

RabeFr* rabe_fr_new(void);
void rabe_fr_free(RabeFr* fr);
void rabe_fr_clear(RabeFr* fr);
void rabe_fr_set_one(RabeFr* fr);
void rabe_fr_set_int(RabeFr* fr, int32_t val);
void rabe_fr_random(RabeFr* fr);
int rabe_fr_is_zero(const RabeFr* fr);
void rabe_fr_copy(RabeFr* dst, const RabeFr* src);

/* Arithmetic */
void rabe_fr_add(RabeFr* z, const RabeFr* x, const RabeFr* y);
void rabe_fr_sub(RabeFr* z, const RabeFr* x, const RabeFr* y);
void rabe_fr_mul(RabeFr* z, const RabeFr* x, const RabeFr* y);
void rabe_fr_div(RabeFr* z, const RabeFr* x, const RabeFr* y);
void rabe_fr_neg(RabeFr* z, const RabeFr* x);
int rabe_fr_inv(RabeFr* z, const RabeFr* x);
void rabe_fr_pow(RabeFr* z, const RabeFr* base, const RabeFr* exp);

/* Serialization */
size_t rabe_fr_serialize(uint8_t* out, size_t out_len, const RabeFr* fr);
int rabe_fr_deserialize(RabeFr* fr, const uint8_t* data, size_t len);
size_t rabe_fr_byte_size(void);
void rabe_fr_from_bytes_mod_order(RabeFr* fr, const uint8_t* data, size_t len);

/* ============================================================================
 * G1 Operations
 * ============================================================================ */

RabeG1* rabe_g1_new(void);
void rabe_g1_free(RabeG1* g1);
void rabe_g1_clear(RabeG1* g1);
void rabe_g1_set_generator(RabeG1* g1);
void rabe_g1_random(RabeG1* g1);
void rabe_g1_copy(RabeG1* dst, const RabeG1* src);

/* Group operations */
void rabe_g1_add(RabeG1* z, const RabeG1* x, const RabeG1* y);
void rabe_g1_sub(RabeG1* z, const RabeG1* x, const RabeG1* y);
void rabe_g1_neg(RabeG1* z, const RabeG1* x);
void rabe_g1_mul(RabeG1* z, const RabeG1* x, const RabeFr* r);
void rabe_g1_hash(RabeG1* g1, const uint8_t* msg, size_t msg_len);
int rabe_g1_is_zero(const RabeG1* g1);
int rabe_g1_cmp(const RabeG1* x, const RabeG1* y);

/* Serialization */
size_t rabe_g1_serialize(uint8_t* out, size_t out_len, const RabeG1* g1);
int rabe_g1_deserialize(RabeG1* g1, const uint8_t* data, size_t len);
size_t rabe_g1_byte_size(void);

/* ============================================================================
 * G2 Operations
 * ============================================================================ */

RabeG2* rabe_g2_new(void);
void rabe_g2_free(RabeG2* g2);
void rabe_g2_clear(RabeG2* g2);
void rabe_g2_set_generator(RabeG2* g2);
void rabe_g2_random(RabeG2* g2);
void rabe_g2_copy(RabeG2* dst, const RabeG2* src);

/* Group operations */
void rabe_g2_add(RabeG2* z, const RabeG2* x, const RabeG2* y);
void rabe_g2_sub(RabeG2* z, const RabeG2* x, const RabeG2* y);
void rabe_g2_neg(RabeG2* z, const RabeG2* x);
void rabe_g2_mul(RabeG2* z, const RabeG2* x, const RabeFr* r);
int rabe_g2_is_zero(const RabeG2* g2);
int rabe_g2_cmp(const RabeG2* x, const RabeG2* y);

/* Serialization */
size_t rabe_g2_serialize(uint8_t* out, size_t out_len, const RabeG2* g2);
int rabe_g2_deserialize(RabeG2* g2, const uint8_t* data, size_t len);
size_t rabe_g2_byte_size(void);

/* ============================================================================
 * GT Operations
 * ============================================================================ */

RabeGt* rabe_gt_new(void);
void rabe_gt_free(RabeGt* gt);
void rabe_gt_clear(RabeGt* gt);
void rabe_gt_set_one(RabeGt* gt);
void rabe_gt_copy(RabeGt* dst, const RabeGt* src);

/* Group operations */
void rabe_gt_mul(RabeGt* z, const RabeGt* x, const RabeGt* y);
void rabe_gt_div(RabeGt* z, const RabeGt* x, const RabeGt* y);
void rabe_gt_pow(RabeGt* z, const RabeGt* x, const RabeFr* r);
void rabe_gt_inv(RabeGt* z, const RabeGt* x);
int rabe_gt_is_one(const RabeGt* gt);
int rabe_gt_cmp(const RabeGt* x, const RabeGt* y);

/* Serialization */
size_t rabe_gt_serialize(uint8_t* out, size_t out_len, const RabeGt* gt);
int rabe_gt_deserialize(RabeGt* gt, const uint8_t* data, size_t len);
size_t rabe_gt_byte_size(void);

/* ============================================================================
 * Pairing Operations
 * ============================================================================ */

/* Compute pairing: gt = e(g1, g2) */
void rabe_pairing(RabeGt* gt, const RabeG1* g1, const RabeG2* g2);

/* Compute multi-pairing: gt = product of e(g1[i], g2[i]) */
void rabe_multi_pairing(
    RabeGt* gt,
    const RabeG1* const* g1s,
    const RabeG2* const* g2s,
    size_t count
);

#ifdef __cplusplus
}
#endif

#endif /* RABE_BLS12381_H */
