//! C FFI bindings for OpenABE integration
//!
//! This module provides C-compatible functions that match the OpenABE zelement API,
//! allowing OpenABE to use RABE's BLS12-381 implementation instead of MCL.

use crate::{Fr, G1, G2, Gt, pairing};
use std::ptr;
use std::slice;

// OpenABE curve IDs (from zconstants.h)
const OPENABE_BN_P254_ID: u8 = 0x6F;
const OPENABE_BN_P256_ID: u8 = 0x73;
const OPENABE_BN_P382_ID: u8 = 0xE4;
const OPENABE_BLS12_P381_ID: u8 = 0xA2;

// Opaque handle types for C
// We use Box to heap-allocate the Rust types
pub type RabeFr = Fr;
pub type RabeG1 = G1;
pub type RabeG2 = G2;
pub type RabeGt = Gt;

/// Initialize the library (no-op for arkworks, but required for API compatibility)
#[no_mangle]
pub extern "C" fn rabe_zml_init() {
    // Arkworks doesn't require explicit initialization
}

/// Clean up the library (no-op for arkworks)
#[no_mangle]
pub extern "C" fn rabe_zml_clean() {
    // No cleanup needed
}

/// Initialize curve with given ID
/// Returns 0 on success, -1 on failure
#[no_mangle]
pub extern "C" fn rabe_init_curve(curve_id: i32) -> i32 {
    // We only support BLS12-381
    match curve_id as u8 {
        OPENABE_BLS12_P381_ID | OPENABE_BN_P382_ID => 0,  // BLS12-381 variants
        OPENABE_BN_P254_ID | OPENABE_BN_P256_ID => {
            eprintln!("RABE: BN254 curve not supported, only BLS12-381");
            -1
        }
        _ => {
            eprintln!("RABE: Unsupported curve ID: {}", curve_id);
            -1
        }
    }
}

// =============================================================================
// Fr (Scalar Field) Operations
// =============================================================================

/// Allocate a new Fr element initialized to zero
#[no_mangle]
pub extern "C" fn rabe_fr_new() -> *mut RabeFr {
    Box::into_raw(Box::new(Fr::zero()))
}

/// Free an Fr element
#[no_mangle]
pub extern "C" fn rabe_fr_free(fr: *mut RabeFr) {
    if !fr.is_null() {
        unsafe { drop(Box::from_raw(fr)); }
    }
}

/// Set Fr to zero
#[no_mangle]
pub extern "C" fn rabe_fr_clear(fr: *mut RabeFr) {
    if !fr.is_null() {
        unsafe { *fr = Fr::zero(); }
    }
}

/// Set Fr to one
#[no_mangle]
pub extern "C" fn rabe_fr_set_one(fr: *mut RabeFr) {
    if !fr.is_null() {
        unsafe { *fr = Fr::one(); }
    }
}

/// Generate random Fr element
#[no_mangle]
pub extern "C" fn rabe_fr_random(fr: *mut RabeFr) {
    if !fr.is_null() {
        let mut rng = rand::thread_rng();
        unsafe { *fr = Fr::random(&mut rng); }
    }
}

/// Check if Fr is zero. Returns 1 if zero, 0 otherwise.
#[no_mangle]
pub extern "C" fn rabe_fr_is_zero(fr: *const RabeFr) -> i32 {
    if fr.is_null() { return 0; }
    if unsafe { (*fr).is_zero() } { 1 } else { 0 }
}

/// Set Fr to an integer value
#[no_mangle]
pub extern "C" fn rabe_fr_set_int(fr: *mut RabeFr, val: i32) {
    if !fr.is_null() {
        unsafe {
            // Create Fr from bytes (little-endian)
            let abs_val = val.unsigned_abs() as u64;
            let bytes = abs_val.to_le_bytes();
            let mut padded = [0u8; 32];
            padded[..8].copy_from_slice(&bytes);
            let result = Fr::from_slice(&padded).unwrap_or_else(Fr::zero);
            if val < 0 {
                *fr = -result;
            } else {
                *fr = result;
            }
        }
    }
}

/// Copy Fr: dst = src
#[no_mangle]
pub extern "C" fn rabe_fr_copy(dst: *mut RabeFr, src: *const RabeFr) {
    if !dst.is_null() && !src.is_null() {
        unsafe { *dst = *src; }
    }
}

/// Fr addition: z = x + y
#[no_mangle]
pub extern "C" fn rabe_fr_add(z: *mut RabeFr, x: *const RabeFr, y: *const RabeFr) {
    if z.is_null() || x.is_null() || y.is_null() { return; }
    unsafe { *z = *x + *y; }
}

/// Fr subtraction: z = x - y
#[no_mangle]
pub extern "C" fn rabe_fr_sub(z: *mut RabeFr, x: *const RabeFr, y: *const RabeFr) {
    if z.is_null() || x.is_null() || y.is_null() { return; }
    unsafe { *z = *x - *y; }
}

/// Fr multiplication: z = x * y
#[no_mangle]
pub extern "C" fn rabe_fr_mul(z: *mut RabeFr, x: *const RabeFr, y: *const RabeFr) {
    if z.is_null() || x.is_null() || y.is_null() { return; }
    unsafe { *z = *x * *y; }
}

/// Fr division: z = x / y
#[no_mangle]
pub extern "C" fn rabe_fr_div(z: *mut RabeFr, x: *const RabeFr, y: *const RabeFr) {
    if z.is_null() || x.is_null() || y.is_null() { return; }
    unsafe {
        if let Some(y_inv) = (*y).inverse() {
            *z = *x * y_inv;
        }
    }
}

/// Fr negation: z = -x
#[no_mangle]
pub extern "C" fn rabe_fr_neg(z: *mut RabeFr, x: *const RabeFr) {
    if z.is_null() || x.is_null() { return; }
    unsafe { *z = -(*x); }
}

/// Fr inverse: z = 1/x. Returns 0 on success, -1 if x is zero.
#[no_mangle]
pub extern "C" fn rabe_fr_inv(z: *mut RabeFr, x: *const RabeFr) -> i32 {
    if z.is_null() || x.is_null() { return -1; }
    unsafe {
        match (*x).inverse() {
            Some(inv) => { *z = inv; 0 }
            None => -1
        }
    }
}

/// Fr exponentiation: z = base^exp (in the scalar field).
/// This computes base raised to the power of exp using square-and-multiply.
#[no_mangle]
pub extern "C" fn rabe_fr_pow(z: *mut RabeFr, base: *const RabeFr, exp: *const RabeFr) {
    if z.is_null() || base.is_null() || exp.is_null() { return; }
    unsafe {
        // Get bytes of exp to iterate through bits
        let exp_bytes = (*exp).into_bytes();
        let mut result = Fr::one();
        let mut current_base = *base;

        // Square-and-multiply from LSB to MSB
        for byte in exp_bytes.iter() {
            for bit_pos in 0..8 {
                if (byte >> bit_pos) & 1 == 1 {
                    result = result * current_base;
                }
                current_base = current_base * current_base;
            }
        }
        *z = result;
    }
}

/// Serialize Fr to bytes. Returns number of bytes written.
#[no_mangle]
pub extern "C" fn rabe_fr_serialize(out: *mut u8, out_len: usize, fr: *const RabeFr) -> usize {
    if out.is_null() || fr.is_null() { return 0; }
    let bytes = unsafe { (*fr).into_bytes() };
    let copy_len = bytes.len().min(out_len);
    unsafe {
        ptr::copy_nonoverlapping(bytes.as_ptr(), out, copy_len);
    }
    copy_len
}

/// Deserialize Fr from bytes. Returns 0 on success, -1 on failure.
#[no_mangle]
pub extern "C" fn rabe_fr_deserialize(fr: *mut RabeFr, data: *const u8, len: usize) -> i32 {
    if fr.is_null() || data.is_null() { return -1; }
    let slice = unsafe { slice::from_raw_parts(data, len) };
    match Fr::from_slice(slice) {
        Some(val) => { unsafe { *fr = val; } 0 }
        None => -1
    }
}

/// Get byte size of serialized Fr
#[no_mangle]
pub extern "C" fn rabe_fr_byte_size() -> usize {
    32  // BLS12-381 Fr is 32 bytes
}

/// Interpret raw bytes as a field element (like MCL's setLittleEndianMod).
/// Takes arbitrary-length bytes and reduces modulo the curve order.
#[no_mangle]
pub extern "C" fn rabe_fr_from_bytes_mod_order(fr: *mut RabeFr, data: *const u8, len: usize) {
    if fr.is_null() || data.is_null() { return; }
    use ark_ff::PrimeField;
    let slice = unsafe { slice::from_raw_parts(data, len) };
    // from_le_bytes_mod_order interprets bytes as a little-endian integer
    // and reduces it modulo the field modulus
    let val = Fr(ark_bls12_381::Fr::from_le_bytes_mod_order(slice));
    unsafe { *fr = val; }
}

// =============================================================================
// G1 Operations
// =============================================================================

/// Allocate a new G1 element (identity/zero)
#[no_mangle]
pub extern "C" fn rabe_g1_new() -> *mut RabeG1 {
    Box::into_raw(Box::new(G1::zero()))
}

/// Free a G1 element
#[no_mangle]
pub extern "C" fn rabe_g1_free(g1: *mut RabeG1) {
    if !g1.is_null() {
        unsafe { drop(Box::from_raw(g1)); }
    }
}

/// Set G1 to identity (point at infinity)
#[no_mangle]
pub extern "C" fn rabe_g1_clear(g1: *mut RabeG1) {
    if !g1.is_null() {
        unsafe { *g1 = G1::zero(); }
    }
}

/// Set G1 to generator
#[no_mangle]
pub extern "C" fn rabe_g1_set_generator(g1: *mut RabeG1) {
    if !g1.is_null() {
        unsafe { *g1 = G1::one(); }
    }
}

/// Generate random G1 element
#[no_mangle]
pub extern "C" fn rabe_g1_random(g1: *mut RabeG1) {
    if !g1.is_null() {
        let mut rng = rand::thread_rng();
        unsafe { *g1 = G1::random(&mut rng); }
    }
}

/// G1 addition: z = x + y
#[no_mangle]
pub extern "C" fn rabe_g1_add(z: *mut RabeG1, x: *const RabeG1, y: *const RabeG1) {
    if z.is_null() || x.is_null() || y.is_null() { return; }
    unsafe { *z = *x + *y; }
}

/// G1 subtraction: z = x - y
#[no_mangle]
pub extern "C" fn rabe_g1_sub(z: *mut RabeG1, x: *const RabeG1, y: *const RabeG1) {
    if z.is_null() || x.is_null() || y.is_null() { return; }
    unsafe { *z = *x - *y; }
}

/// G1 negation: z = -x
#[no_mangle]
pub extern "C" fn rabe_g1_neg(z: *mut RabeG1, x: *const RabeG1) {
    if z.is_null() || x.is_null() { return; }
    unsafe { *z = -(*x); }
}

/// G1 scalar multiplication: z = x * r
#[no_mangle]
pub extern "C" fn rabe_g1_mul(z: *mut RabeG1, x: *const RabeG1, r: *const RabeFr) {
    if z.is_null() || x.is_null() || r.is_null() { return; }
    unsafe { *z = *x * *r; }
}

/// Hash to G1
#[no_mangle]
pub extern "C" fn rabe_g1_hash(g1: *mut RabeG1, msg: *const u8, msg_len: usize) {
    if g1.is_null() || msg.is_null() { return; }
    let slice = unsafe { slice::from_raw_parts(msg, msg_len) };
    unsafe { *g1 = G1::hash_to_curve(slice); }
}

/// Check if G1 is identity. Returns 1 if identity, 0 otherwise.
#[no_mangle]
pub extern "C" fn rabe_g1_is_zero(g1: *const RabeG1) -> i32 {
    if g1.is_null() { return 0; }
    if unsafe { (*g1).is_zero() } { 1 } else { 0 }
}

/// Check if two G1 elements are equal. Returns 0 if equal, 1 otherwise.
#[no_mangle]
pub extern "C" fn rabe_g1_cmp(x: *const RabeG1, y: *const RabeG1) -> i32 {
    if x.is_null() || y.is_null() { return 1; }
    if unsafe { *x == *y } { 0 } else { 1 }
}

/// Serialize G1 to bytes. Returns number of bytes written.
#[no_mangle]
pub extern "C" fn rabe_g1_serialize(out: *mut u8, out_len: usize, g1: *const RabeG1) -> usize {
    if out.is_null() || g1.is_null() { return 0; }
    let bytes = unsafe { (*g1).into_bytes() };
    let copy_len = bytes.len().min(out_len);
    unsafe {
        ptr::copy_nonoverlapping(bytes.as_ptr(), out, copy_len);
    }
    copy_len
}

/// Deserialize G1 from bytes. Returns 0 on success, -1 on failure.
#[no_mangle]
pub extern "C" fn rabe_g1_deserialize(g1: *mut RabeG1, data: *const u8, len: usize) -> i32 {
    if g1.is_null() || data.is_null() { return -1; }
    let slice = unsafe { slice::from_raw_parts(data, len) };
    match G1::from_slice(slice) {
        Some(val) => { unsafe { *g1 = val; } 0 }
        None => -1
    }
}

/// Get byte size of serialized G1 (compressed)
#[no_mangle]
pub extern "C" fn rabe_g1_byte_size() -> usize {
    48  // BLS12-381 G1 compressed is 48 bytes
}

/// Copy G1: dst = src
#[no_mangle]
pub extern "C" fn rabe_g1_copy(dst: *mut RabeG1, src: *const RabeG1) {
    if dst.is_null() || src.is_null() { return; }
    unsafe { *dst = *src; }
}

// =============================================================================
// G2 Operations
// =============================================================================

/// Allocate a new G2 element (identity/zero)
#[no_mangle]
pub extern "C" fn rabe_g2_new() -> *mut RabeG2 {
    Box::into_raw(Box::new(G2::zero()))
}

/// Free a G2 element
#[no_mangle]
pub extern "C" fn rabe_g2_free(g2: *mut RabeG2) {
    if !g2.is_null() {
        unsafe { drop(Box::from_raw(g2)); }
    }
}

/// Set G2 to identity
#[no_mangle]
pub extern "C" fn rabe_g2_clear(g2: *mut RabeG2) {
    if !g2.is_null() {
        unsafe { *g2 = G2::zero(); }
    }
}

/// Set G2 to generator
#[no_mangle]
pub extern "C" fn rabe_g2_set_generator(g2: *mut RabeG2) {
    if !g2.is_null() {
        unsafe { *g2 = G2::one(); }
    }
}

/// Generate random G2 element
#[no_mangle]
pub extern "C" fn rabe_g2_random(g2: *mut RabeG2) {
    if !g2.is_null() {
        let mut rng = rand::thread_rng();
        unsafe { *g2 = G2::random(&mut rng); }
    }
}

/// G2 addition: z = x + y
#[no_mangle]
pub extern "C" fn rabe_g2_add(z: *mut RabeG2, x: *const RabeG2, y: *const RabeG2) {
    if z.is_null() || x.is_null() || y.is_null() { return; }
    unsafe { *z = *x + *y; }
}

/// G2 subtraction: z = x - y
#[no_mangle]
pub extern "C" fn rabe_g2_sub(z: *mut RabeG2, x: *const RabeG2, y: *const RabeG2) {
    if z.is_null() || x.is_null() || y.is_null() { return; }
    unsafe { *z = *x - *y; }
}

/// G2 negation: z = -x
#[no_mangle]
pub extern "C" fn rabe_g2_neg(z: *mut RabeG2, x: *const RabeG2) {
    if z.is_null() || x.is_null() { return; }
    unsafe { *z = -(*x); }
}

/// G2 scalar multiplication: z = x * r
#[no_mangle]
pub extern "C" fn rabe_g2_mul(z: *mut RabeG2, x: *const RabeG2, r: *const RabeFr) {
    if z.is_null() || x.is_null() || r.is_null() { return; }
    unsafe { *z = *x * *r; }
}

/// Check if G2 is identity. Returns 1 if identity, 0 otherwise.
#[no_mangle]
pub extern "C" fn rabe_g2_is_zero(g2: *const RabeG2) -> i32 {
    if g2.is_null() { return 0; }
    if unsafe { (*g2).is_zero() } { 1 } else { 0 }
}

/// Check if two G2 elements are equal. Returns 0 if equal, 1 otherwise.
#[no_mangle]
pub extern "C" fn rabe_g2_cmp(x: *const RabeG2, y: *const RabeG2) -> i32 {
    if x.is_null() || y.is_null() { return 1; }
    if unsafe { *x == *y } { 0 } else { 1 }
}

/// Serialize G2 to bytes. Returns number of bytes written.
#[no_mangle]
pub extern "C" fn rabe_g2_serialize(out: *mut u8, out_len: usize, g2: *const RabeG2) -> usize {
    if out.is_null() || g2.is_null() { return 0; }
    let bytes = unsafe { (*g2).into_bytes() };
    let copy_len = bytes.len().min(out_len);
    unsafe {
        ptr::copy_nonoverlapping(bytes.as_ptr(), out, copy_len);
    }
    copy_len
}

/// Deserialize G2 from bytes. Returns 0 on success, -1 on failure.
#[no_mangle]
pub extern "C" fn rabe_g2_deserialize(g2: *mut RabeG2, data: *const u8, len: usize) -> i32 {
    if g2.is_null() || data.is_null() { return -1; }
    let slice = unsafe { slice::from_raw_parts(data, len) };
    match G2::from_slice(slice) {
        Some(val) => { unsafe { *g2 = val; } 0 }
        None => -1
    }
}

/// Get byte size of serialized G2 (compressed)
#[no_mangle]
pub extern "C" fn rabe_g2_byte_size() -> usize {
    96  // BLS12-381 G2 compressed is 96 bytes
}

/// Copy G2: dst = src
#[no_mangle]
pub extern "C" fn rabe_g2_copy(dst: *mut RabeG2, src: *const RabeG2) {
    if dst.is_null() || src.is_null() { return; }
    unsafe { *dst = *src; }
}

// =============================================================================
// GT Operations
// =============================================================================

/// Allocate a new GT element (identity/one)
#[no_mangle]
pub extern "C" fn rabe_gt_new() -> *mut RabeGt {
    Box::into_raw(Box::new(Gt::one()))
}

/// Free a GT element
#[no_mangle]
pub extern "C" fn rabe_gt_free(gt: *mut RabeGt) {
    if !gt.is_null() {
        unsafe { drop(Box::from_raw(gt)); }
    }
}

/// Set GT to identity (one)
#[no_mangle]
pub extern "C" fn rabe_gt_clear(gt: *mut RabeGt) {
    if !gt.is_null() {
        unsafe { *gt = Gt::one(); }
    }
}

/// Set GT to identity (one) - alias for clear
#[no_mangle]
pub extern "C" fn rabe_gt_set_one(gt: *mut RabeGt) {
    if !gt.is_null() {
        unsafe { *gt = Gt::one(); }
    }
}

/// GT multiplication: z = x * y
#[no_mangle]
pub extern "C" fn rabe_gt_mul(z: *mut RabeGt, x: *const RabeGt, y: *const RabeGt) {
    if z.is_null() || x.is_null() || y.is_null() { return; }
    unsafe { *z = *x * *y; }
}

/// GT division: z = x / y
#[no_mangle]
pub extern "C" fn rabe_gt_div(z: *mut RabeGt, x: *const RabeGt, y: *const RabeGt) {
    if z.is_null() || x.is_null() || y.is_null() { return; }
    unsafe { *z = *x * (*y).inverse(); }
}

/// GT exponentiation: z = x^r
#[no_mangle]
pub extern "C" fn rabe_gt_pow(z: *mut RabeGt, x: *const RabeGt, r: *const RabeFr) {
    if z.is_null() || x.is_null() || r.is_null() { return; }
    unsafe { *z = (*x).pow(&*r); }
}

/// GT inverse: z = 1/x
#[no_mangle]
pub extern "C" fn rabe_gt_inv(z: *mut RabeGt, x: *const RabeGt) {
    if z.is_null() || x.is_null() { return; }
    unsafe { *z = (*x).inverse(); }
}

/// Check if GT is identity (one). Returns 1 if one, 0 otherwise.
#[no_mangle]
pub extern "C" fn rabe_gt_is_one(gt: *const RabeGt) -> i32 {
    if gt.is_null() { return 0; }
    if unsafe { (*gt).is_one() } { 1 } else { 0 }
}

/// Check if two GT elements are equal. Returns 0 if equal, 1 otherwise.
#[no_mangle]
pub extern "C" fn rabe_gt_cmp(x: *const RabeGt, y: *const RabeGt) -> i32 {
    if x.is_null() || y.is_null() { return 1; }
    if unsafe { *x == *y } { 0 } else { 1 }
}

/// Serialize GT to bytes. Returns number of bytes written.
#[no_mangle]
pub extern "C" fn rabe_gt_serialize(out: *mut u8, out_len: usize, gt: *const RabeGt) -> usize {
    if out.is_null() || gt.is_null() { return 0; }
    let bytes = unsafe { (*gt).into_bytes() };
    let copy_len = bytes.len().min(out_len);
    unsafe {
        ptr::copy_nonoverlapping(bytes.as_ptr(), out, copy_len);
    }
    copy_len
}

/// Deserialize GT from bytes. Returns 0 on success, -1 on failure.
#[no_mangle]
pub extern "C" fn rabe_gt_deserialize(gt: *mut RabeGt, data: *const u8, len: usize) -> i32 {
    if gt.is_null() || data.is_null() { return -1; }
    let slice = unsafe { slice::from_raw_parts(data, len) };
    match Gt::from_slice(slice) {
        Some(val) => { unsafe { *gt = val; } 0 }
        None => -1
    }
}

/// Get byte size of serialized GT
#[no_mangle]
pub extern "C" fn rabe_gt_byte_size() -> usize {
    576  // BLS12-381 GT (Fp12) is 576 bytes
}

/// Copy GT: dst = src
#[no_mangle]
pub extern "C" fn rabe_gt_copy(dst: *mut RabeGt, src: *const RabeGt) {
    if dst.is_null() || src.is_null() { return; }
    unsafe { *dst = *src; }
}

// =============================================================================
// Pairing Operations
// =============================================================================

/// Compute pairing: gt = e(g1, g2)
#[no_mangle]
pub extern "C" fn rabe_pairing(gt: *mut RabeGt, g1: *const RabeG1, g2: *const RabeG2) {
    if gt.is_null() || g1.is_null() || g2.is_null() { return; }
    unsafe { *gt = pairing(*g1, *g2); }
}

/// Compute multi-pairing: gt = product of e(g1[i], g2[i])
#[no_mangle]
pub extern "C" fn rabe_multi_pairing(
    gt: *mut RabeGt,
    g1s: *const *const RabeG1,
    g2s: *const *const RabeG2,
    count: usize
) {
    if gt.is_null() || g1s.is_null() || g2s.is_null() || count == 0 { return; }

    let mut result = Gt::one();
    unsafe {
        for i in 0..count {
            let g1_ptr = *g1s.add(i);
            let g2_ptr = *g2s.add(i);
            if !g1_ptr.is_null() && !g2_ptr.is_null() {
                result = result * pairing(*g1_ptr, *g2_ptr);
            }
        }
        *gt = result;
    }
}

// =============================================================================
// OpenABE-compatible wrapper functions (matching zelement_mcl.cpp API)
// These use inline storage instead of heap allocation for compatibility
// =============================================================================

/// Size constants for inline storage
#[no_mangle]
pub static RABE_FR_SIZE: usize = std::mem::size_of::<Fr>();
#[no_mangle]
pub static RABE_G1_SIZE: usize = std::mem::size_of::<G1>();
#[no_mangle]
pub static RABE_G2_SIZE: usize = std::mem::size_of::<G2>();
#[no_mangle]
pub static RABE_GT_SIZE: usize = std::mem::size_of::<Gt>();
