///
/// Copyright (c) 2018 Zeutro, LLC. All rights reserved.
///
/// \file   relic_compat.h
///
/// \brief  Compatibility layer for RELIC symbol renaming in WASM builds
///
/// In WASM builds, RELIC symbols are prefixed with "relic_" to avoid conflicts
/// with OpenSSL. This header provides compatibility macros to allow OpenABE
/// code to work with both native and WASM RELIC builds.
///

#ifndef __RELIC_COMPAT_H__
#define __RELIC_COMPAT_H__

// Use single RELIC library (no label separation)
#include <relic/relic.h>

// CAT macro was renamed to RLC_CAT in RELIC 0.7.0
#ifndef CAT
#define CAT(A, B) RLC_CAT(A, B)
#endif

// Backward compatibility macros for RELIC 0.7.0+ API changes
#ifndef BN_POS
#define BN_POS RLC_POS
#endif
#ifndef BN_NEG
#define BN_NEG RLC_NEG
#endif
#ifndef STS_OK
#define STS_OK RLC_OK
#endif
#ifndef STS_ERR
#define STS_ERR RLC_ERR
#endif
#ifndef FP_DIGS
#define FP_DIGS RLC_FP_DIGS
#endif
#ifndef EP_DTYPE
#define EP_DTYPE RLC_EP_DTYPE
#endif
#ifndef CMP_LT
#define CMP_LT RLC_LT
#endif
#ifndef CMP_EQ
#define CMP_EQ RLC_EQ
#endif
#ifndef CMP_GT
#define CMP_GT RLC_GT
#endif
#ifndef CMP_NE
#define CMP_NE RLC_NE
#endif

// Function name changes in RELIC 0.7.0
#ifndef ep_is_valid
#define ep_is_valid(P) ep_on_curve(P)
#endif
#ifndef ep_sub_projc
#define ep_sub_projc ep_sub
#endif

// Check if we're using renamed RELIC symbols (WASM build)
// In WASM builds with RELIC 0.5.0, symbols are prefixed with "relic_" and unprefixed names don't exist
// RELIC 0.7.0+ has proper macros built-in, so we don't need symbol renaming
// We disable symbol renaming for WASM builds now that we use RELIC 0.7.0
#if 0 // Disabled - now using RELIC 0.7.0 which has proper macros
#if defined(__wasm__)
#define RELIC_RENAMED_SYMBOLS 1
#endif
#endif

#ifdef RELIC_RENAMED_SYMBOLS

// Big number (bn_*) type and function mappings
#define bn_st           relic_bn_st
#define bn_t            relic_bn_t

// bn_* function mappings
#define bn_null         relic_bn_null
#define bn_new          relic_bn_new
#define bn_new_size     relic_bn_new_size
#define bn_free         relic_bn_free
#define bn_init         relic_bn_init
#define bn_clean        relic_bn_clean
#define bn_grow         relic_bn_grow
#define bn_trim         relic_bn_trim
#define bn_copy         relic_bn_copy
#define bn_abs          relic_bn_abs
#define bn_neg          relic_bn_neg
#define bn_sign         relic_bn_sign
#define bn_zero         relic_bn_zero
#define bn_is_zero      relic_bn_is_zero
#define bn_is_even      relic_bn_is_even
#define bn_bits         relic_bn_bits
#define bn_get_bit      relic_bn_get_bit
#define bn_set_bit      relic_bn_set_bit
#define bn_ham          relic_bn_ham
#define bn_get_dig      relic_bn_get_dig
#define bn_set_dig      relic_bn_set_dig
#define bn_set_2b       relic_bn_set_2b
#define bn_rand         relic_bn_rand
#define bn_rand_mod     relic_bn_rand_mod
#define bn_print        relic_bn_print
#define bn_size_str     relic_bn_size_str
#define bn_read_str     relic_bn_read_str
#define bn_write_str    relic_bn_write_str
#define bn_size_bin     relic_bn_size_bin
#define bn_read_bin     relic_bn_read_bin
#define bn_write_bin    relic_bn_write_bin
#define bn_size_raw     relic_bn_size_raw
#define bn_read_raw     relic_bn_read_raw
#define bn_write_raw    relic_bn_write_raw
#define bn_cmp_abs      relic_bn_cmp_abs
#define bn_cmp_dig      relic_bn_cmp_dig
#define bn_cmp          relic_bn_cmp
#define bn_add          relic_bn_add
#define bn_add_dig      relic_bn_add_dig
#define bn_sub          relic_bn_sub
#define bn_sub_dig      relic_bn_sub_dig
#define bn_mul          relic_bn_mul
#define bn_mul_dig      relic_bn_mul_dig
#define bn_mul_basic    relic_bn_mul_basic
#define bn_mul_comba    relic_bn_mul_comba
#define bn_mul_karat    relic_bn_mul_karat
#define bn_sqr          relic_bn_sqr
#define bn_sqr_basic    relic_bn_sqr_basic
#define bn_sqr_comba    relic_bn_sqr_comba
#define bn_sqr_karat    relic_bn_sqr_karat
#define bn_dbl          relic_bn_dbl
#define bn_hlv          relic_bn_hlv
#define bn_lsh          relic_bn_lsh
#define bn_rsh          relic_bn_rsh
#define bn_div          relic_bn_div
#define bn_div_rem      relic_bn_div_rem
#define bn_div_dig      relic_bn_div_dig
#define bn_div_rem_dig  relic_bn_div_rem_dig
#define bn_mod          relic_bn_mod
#define bn_mod_2b       relic_bn_mod_2b
#define bn_mod_dig      relic_bn_mod_dig
#define bn_mod_basic    relic_bn_mod_basic
#define bn_mod_pre_barrt relic_bn_mod_pre_barrt
#define bn_mod_barrt    relic_bn_mod_barrt
#define bn_mod_pre_monty relic_bn_mod_pre_monty
#define bn_mod_monty_conv relic_bn_mod_monty_conv
#define bn_mod_monty_back relic_bn_mod_monty_back
#define bn_mod_monty_basic relic_bn_mod_monty_basic
#define bn_mod_monty_comba relic_bn_mod_monty_comba
#define bn_mod_pre_pmers relic_bn_mod_pre_pmers
#define bn_mod_pmers    relic_bn_mod_pmers
#define bn_mxp          relic_bn_mxp
#define bn_mxp_basic    relic_bn_mxp_basic
#define bn_mxp_slide    relic_bn_mxp_slide
#define bn_mxp_monty    relic_bn_mxp_monty
#define bn_mxp_dig      relic_bn_mxp_dig
#define bn_srt          relic_bn_srt
#define bn_gcd          relic_bn_gcd
#define bn_gcd_basic    relic_bn_gcd_basic
#define bn_gcd_lehme    relic_bn_gcd_lehme
#define bn_gcd_stein    relic_bn_gcd_stein
#define bn_gcd_dig      relic_bn_gcd_dig
#define bn_gcd_ext      relic_bn_gcd_ext
#define bn_gcd_ext_basic relic_bn_gcd_ext_basic
#define bn_gcd_ext_lehme relic_bn_gcd_ext_lehme
#define bn_gcd_ext_stein relic_bn_gcd_ext_stein
#define bn_gcd_ext_mid  relic_bn_gcd_ext_mid
#define bn_gcd_ext_dig  relic_bn_gcd_ext_dig
#define bn_lcm          relic_bn_lcm
#define bn_smb_leg      relic_bn_smb_leg
#define bn_smb_jac      relic_bn_smb_jac
#define bn_get_prime    relic_bn_get_prime
#define bn_is_prime     relic_bn_is_prime
#define bn_is_prime_basic relic_bn_is_prime_basic
#define bn_is_prime_rabin relic_bn_is_prime_rabin
#define bn_is_prime_solov relic_bn_is_prime_solov
#define bn_gen_prime    relic_bn_gen_prime
#define bn_gen_prime_basic relic_bn_gen_prime_basic
#define bn_gen_prime_safep relic_bn_gen_prime_safep
#define bn_gen_prime_stron relic_bn_gen_prime_stron

// Note: Only bn_* symbols are renamed in WASM builds
// Other symbols (ep_*, gt_*, g1_*, g2_*, ec_*, pc_*, etc.) are NOT renamed
// and can be used as-is from RELIC headers

#endif // RELIC_RENAMED_SYMBOLS

// Define type-to-implementation mappings for BP (Barreto-Paterson) pairing
// These are needed by zelement.h macros that use CAT(G*_LOWER, function_name)
// With BP label enabled, RELIC headers add bp_ prefix automatically via macros
#ifndef BP_WITH_OPENSSL
#define G1_LOWER ep_
#define G2_LOWER ep2_
#define GT_LOWER fp12_
#endif

// OpenABE uses ec_* wrappers for RELIC functions
// With single library (no label), functions use standard RELIC names
#if !defined(BP_WITH_OPENSSL)
#define ec_core_init()              core_init()
#define ec_ep_param_set(p)          ep_param_set(p)
#define ec_ep_curve_get_ord(o)      ep_curve_get_ord(o)
#define ec_ep_curve_get_gen(g)      ep_curve_get_gen(g)
#define ec_ep_set_infty(p)          ep_set_infty(p)
#define ec_ep_is_infty(p)           ep_is_infty(p)
#define ec_ep_is_valid(p)           ep_is_valid(p)
#define ec_ep_cmp(a,b)              ep_cmp(a,b)
#define ec_ep_norm(r,p)             ep_norm(r,p)
#define ec_ep_mul_lwnaf(r,p,k)      ep_mul_lwnaf(r,p,k)
#define ec_ep_size_bin(a,p)         ep_size_bin(a,p)
#define ec_ep_read_bin(a,b,l)       ep_read_bin(a,b,l)
#define ec_ep_write_bin(b,l,a,p)    ep_write_bin(b,l,a,p)
#define ec_fp_prime_back(c,a)       fp_prime_back(c,a)
#define ec_fp_zero(a)               fp_zero(a)
#define ec_fp_set_dig(a,d)          fp_set_dig(a,d)

// WASM: rand_seed API changed - doesn't support callbacks
// In WASM, just skip the custom RNG callback (use default RAND_bytes)
#ifdef __wasm__
#define oabe_rand_seed(cb, ctx)     /* skip custom RNG in WASM */
#else
#define oabe_rand_seed(cb, ctx)     rand_seed(cb, ctx)
#endif

#endif

#endif // __RELIC_COMPAT_H__
