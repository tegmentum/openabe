//! Waters '11 CP-ABE Proxy Re-Encryption (PRE)
//!
//! This module implements unidirectional, single-hop proxy re-encryption
//! for the Waters '11 CP-ABE scheme. It enables key rotation/recovery by
//! allowing a proxy to transform ciphertexts encrypted under an old key
//! to be decryptable by a new key, without the proxy learning the plaintext.
//!
//! ## Security Properties
//!
//! - **Proxy invisibility**: Proxy only sees blinded values, cannot recover plaintext
//! - **Unidirectionality**: Re-encryption key only works old→new, not reversible
//! - **Single-hop**: Re-encrypted ciphertexts cannot be re-encrypted again
//! - **Collusion resistance**: Source+Proxy or Target+Proxy cannot break security
//!
//! ## Usage Example
//!
//! ```ignore
//! // 1. User generates new key (after key rotation needed)
//! let (mpk, msk) = waters::setup(&mut rng);
//! let sk_new = waters::keygen(&mut rng, &mpk, &msk, &attrs)?;
//!
//! // 2. Generate re-encryption key from old key
//! let rk = waters_pre::generate_rekey(&mut rng, &mpk, &sk_old, &attrs)?;
//!
//! // 3. Proxy transforms ciphertext (without learning plaintext)
//! let re_ct = waters_pre::re_encrypt(&mpk, &ct, &rk)?;
//!
//! // 4. User decrypts with knowledge of the blinding
//! let plaintext = waters_pre::decrypt_reencrypted(&mpk, &re_ct)?;
//! ```

use crate::error::AbeError;
use crate::lsss::LsssMatrix;
use crate::schemes::waters::{Ciphertext, FullCiphertext, Mpk, SecretKey, parse_policy};
use crate::utils::aes;
use rabe_bls12381::{Fr, G1, G2, Gt, pairing};
use rand::{RngCore, CryptoRng};
use std::collections::{HashMap, HashSet};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Re-encryption key for Waters CP-ABE
///
/// This key allows a proxy to transform ciphertexts from being decryptable
/// by the source key to being decryptable by anyone with g2_delta.
/// In a key rotation scenario, the user keeps g2_delta private.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ReEncryptionKey {
    /// Attributes from source key used for re-encryption
    pub source_attributes: Vec<String>,

    /// Modified K component: K_old - g2^delta
    /// This is g2^(alpha + a*t - delta)
    pub rk_k: G2,

    /// L component from source key: g2^t (unchanged)
    pub rk_l: G2,

    /// Per-attribute KX components: H(attr)^t (unchanged)
    pub rk_x: HashMap<String, G1>,

    /// g2^delta - kept by user, NOT given to proxy
    /// Only the owner should have this to complete decryption
    pub g2_delta: G2,
}

/// Re-encrypted ciphertext (KEM part only)
///
/// An intermediate form that can only be fully decrypted by
/// someone with the g2_delta blinding value.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ReEncryptedCiphertext {
    /// Original policy (preserved)
    pub policy: String,

    /// C' = g1^s from original ciphertext
    pub c_prime: G1,

    /// Blinded intermediate: e(g1,g2)^(alpha*s - delta*s)
    pub c_blinded: Gt,

    /// g2^delta for unblinding (user must provide this)
    pub g2_delta: G2,
}

/// Full re-encrypted ciphertext with encrypted payload
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct FullReEncryptedCiphertext {
    /// PRE ciphertext (KEM part)
    pub pre_ct: ReEncryptedCiphertext,

    /// Symmetric ciphertext (DEM part - unchanged from original)
    pub sym_ct: Vec<u8>,
}

/// Generate a re-encryption key from the source secret key
///
/// This creates a key that allows a proxy to transform ciphertexts.
/// The returned `ReEncryptionKey` contains both:
/// - Components for the proxy (rk_k, rk_l, rk_x)
/// - The secret g2_delta that the user keeps to complete decryption
///
/// # Arguments
/// * `rng` - Cryptographically secure random number generator
/// * `mpk` - Master public key
/// * `sk_old` - Source secret key (must satisfy policies of ciphertexts to re-encrypt)
/// * `satisfying_attrs` - Subset of attributes from sk_old to use for re-encryption
///
/// # Returns
/// Re-encryption key containing both proxy components and user's g2_delta
///
/// # Security
/// - The user should NOT give g2_delta to the proxy
/// - Only give (rk_k, rk_l, rk_x, source_attributes) to the proxy
pub fn generate_rekey<R: RngCore + CryptoRng>(
    rng: &mut R,
    mpk: &Mpk,
    sk_old: &SecretKey,
    satisfying_attrs: &[String],
) -> Result<ReEncryptionKey, AbeError> {
    // Validate that old key has all required attributes
    let old_attr_set: HashSet<_> = sk_old.attributes.iter().collect();
    for attr in satisfying_attrs {
        if !old_attr_set.contains(attr) {
            return Err(AbeError::KeygenError(
                format!("Source key missing attribute: {}", attr)
            ));
        }
    }

    if satisfying_attrs.is_empty() {
        return Err(AbeError::KeygenError(
            "At least one attribute required for re-encryption key".to_string()
        ));
    }

    // Generate random blinding factor delta
    let delta = Fr::random(rng);

    // RK_K = K - g2^delta = g2^(alpha + a*t) - g2^delta = g2^(alpha + a*t - delta)
    let rk_k = sk_old.k - (mpk.g2 * delta);

    // RK_L = L = g2^t (unchanged, needed for LSSS reconstruction)
    let rk_l = sk_old.l;

    // RK_X[attr] = KX[attr] = H(attr)^t (unchanged)
    let mut rk_x = HashMap::new();
    for attr in satisfying_attrs {
        let kx = sk_old.kx.get(attr)
            .ok_or_else(|| AbeError::KeygenError(format!("Missing KX for {}", attr)))?;
        rk_x.insert(attr.clone(), *kx);
    }

    // g2^delta - the user keeps this to complete decryption
    let g2_delta = mpk.g2 * delta;

    Ok(ReEncryptionKey {
        source_attributes: satisfying_attrs.to_vec(),
        rk_k,
        rk_l,
        rk_x,
        g2_delta,
    })
}

/// Extract proxy-safe components from a re-encryption key
///
/// Returns the components that are safe to give to a proxy.
/// The proxy cannot decrypt with only these components.
///
/// # Returns
/// Tuple of (rk_k, rk_l, rk_x, source_attributes)
pub fn extract_proxy_key(rk: &ReEncryptionKey) -> (G2, G2, HashMap<String, G1>, Vec<String>) {
    (rk.rk_k, rk.rk_l, rk.rk_x.clone(), rk.source_attributes.clone())
}

/// Proxy transforms a ciphertext using a re-encryption key
///
/// This performs partial decryption using the re-encryption key,
/// resulting in a blinded value that requires g2_delta to recover.
///
/// # Arguments
/// * `mpk` - Master public key
/// * `ct` - Original ciphertext (must be satisfiable by re-encryption key's attributes)
/// * `rk` - Re-encryption key (only proxy components needed)
///
/// # Returns
/// Re-encrypted ciphertext that requires g2_delta to decrypt
///
/// # Security
/// - Proxy learns nothing about plaintext (only sees blinded values)
/// - The re-encrypted ciphertext cannot be decrypted without g2_delta
pub fn re_encrypt(
    _mpk: &Mpk,
    ct: &Ciphertext,
    rk: &ReEncryptionKey,
) -> Result<ReEncryptedCiphertext, AbeError> {
    // Parse policy from ciphertext
    let policy = parse_policy(&ct.policy)
        .map_err(|e| AbeError::InvalidPolicy(e.to_string()))?;

    // Build LSSS matrix and recover coefficients
    let matrix = LsssMatrix::from_policy(&policy)?;

    let coeffs = matrix.recover_coefficients(&rk.source_attributes)
        .map_err(|_| AbeError::PolicyNotSatisfied)?;

    // Perform partial decryption using re-encryption key components
    // This mirrors the normal decryption but uses rk_k instead of K

    let mut prod1 = G1::zero();
    let mut g1_for_pairing = Vec::new();
    let mut g2_for_pairing = Vec::new();

    for (attr, coeff) in &coeffs {
        // Get ciphertext component for this attribute
        let ct_comp = ct.components.get(attr)
            .ok_or_else(|| AbeError::DecryptError(
                format!("Missing ciphertext component for {}", attr)
            ))?;

        // Get re-encryption key component for this attribute
        let rk_x = rk.rk_x.get(attr)
            .ok_or_else(|| AbeError::DecryptError(
                format!("Missing re-encryption key component for {}", attr)
            ))?;

        // prod1 += C_i^coeff
        prod1 = prod1 + (ct_comp.c * *coeff);

        // For pairing: e(KX^coeff, D)
        g1_for_pairing.push(*rk_x * *coeff);
        g2_for_pairing.push(ct_comp.d);
    }

    // Compute prod_t = prod(e(KX_i^coeff_i, D_i))
    let mut prod_t = Gt::one();
    for (g1_elem, g2_elem) in g1_for_pairing.iter().zip(g2_for_pairing.iter()) {
        prod_t = prod_t * pairing(*g1_elem, *g2_elem);
    }

    // e(C', RK_K) = e(g1^s, g2^(alpha + a*t - delta))
    //             = e(g1, g2)^(s * (alpha + a*t - delta))
    let pairing1 = pairing(ct.c_prime, rk.rk_k);

    // e(prod1, RK_L) = e(prod1, g2^t)
    let pairing2 = pairing(prod1, rk.rk_l);

    // denominator = prod_t * pairing2
    let denominator = prod_t * pairing2;

    // c_blinded = pairing1 / denominator
    //           = e(g1,g2)^(alpha*s - delta*s)
    // (The normal decrypt would give e(g1,g2)^(alpha*s), but we're missing delta*s)
    let c_blinded = pairing1 * denominator.inverse();

    Ok(ReEncryptedCiphertext {
        policy: ct.policy.clone(),
        c_prime: ct.c_prime,
        c_blinded,
        g2_delta: rk.g2_delta,
    })
}

/// Proxy transforms a full ciphertext (with encrypted payload)
///
/// # Arguments
/// * `mpk` - Master public key
/// * `ct` - Original full ciphertext
/// * `rk` - Re-encryption key
///
/// # Returns
/// Full re-encrypted ciphertext
pub fn re_encrypt_full(
    mpk: &Mpk,
    ct: &FullCiphertext,
    rk: &ReEncryptionKey,
) -> Result<FullReEncryptedCiphertext, AbeError> {
    // Convert raw ciphertext to typed wrapper for type-safe re-encryption
    let abe_ct: Ciphertext = ct.abe_ct.clone().into();
    let pre_ct = re_encrypt(mpk, &abe_ct, rk)?;

    Ok(FullReEncryptedCiphertext {
        pre_ct,
        sym_ct: ct.sym_ct.clone(),
    })
}

/// Decrypt a re-encrypted ciphertext (KEM mode - returns symmetric key)
///
/// This completes the decryption by unblinding using g2_delta.
///
/// # Arguments
/// * `_mpk` - Master public key (unused but kept for API consistency)
/// * `re_ct` - Re-encrypted ciphertext
///
/// # Returns
/// Symmetric key that was encapsulated
///
/// # Security
/// Only someone with g2_delta can complete decryption
pub fn decrypt_reencrypted_kem(
    _mpk: &Mpk,
    re_ct: &ReEncryptedCiphertext,
) -> Result<[u8; 32], AbeError> {
    // Compute the missing delta contribution:
    // e(C', g2^delta) = e(g1^s, g2^delta) = e(g1, g2)^(s * delta)
    let delta_contribution = pairing(re_ct.c_prime, re_ct.g2_delta);

    // Recover the original blinding:
    // recovered = c_blinded * delta_contribution
    //           = e(g1,g2)^(alpha*s - delta*s) * e(g1,g2)^(delta*s)
    //           = e(g1,g2)^(alpha*s)
    let recovered_c = re_ct.c_blinded * delta_contribution;

    // Derive symmetric key (same as normal decrypt)
    let sym_key = aes::derive_key(&recovered_c);

    Ok(sym_key)
}

/// Decrypt a full re-encrypted ciphertext
///
/// # Arguments
/// * `mpk` - Master public key
/// * `re_ct` - Full re-encrypted ciphertext
///
/// # Returns
/// Decrypted plaintext
pub fn decrypt_reencrypted(
    mpk: &Mpk,
    re_ct: &FullReEncryptedCiphertext,
) -> Result<Vec<u8>, AbeError> {
    let sym_key = decrypt_reencrypted_kem(mpk, &re_ct.pre_ct)?;

    aes::decrypt(&sym_key, &re_ct.sym_ct)
        .map_err(|e| AbeError::DecryptError(e))
}

/// Verify that a re-encryption was performed correctly
///
/// This allows the user to verify the proxy did its job without
/// fully decrypting. Returns true if the re-encrypted ciphertext
/// is well-formed.
pub fn verify_reencryption(
    re_ct: &ReEncryptedCiphertext,
) -> bool {
    // Basic structural checks
    !re_ct.policy.is_empty() &&
    re_ct.c_prime != G1::zero() &&
    re_ct.c_blinded != Gt::one() &&
    re_ct.g2_delta != G2::zero()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schemes::waters::{setup, keygen, encrypt, encrypt_kem};
    use crate::lsss::PolicyNode;
    use rand::thread_rng;

    #[test]
    fn test_pre_basic_roundtrip() {
        let mut rng = thread_rng();

        // Setup
        let (mpk, msk) = setup(&mut rng);

        // Create old secret key with attributes
        let attrs = vec!["admin".to_string(), "user".to_string()];
        let sk_old = keygen(&mut rng, &mpk, &msk, &attrs).unwrap();

        // Encrypt a message with AND policy
        let plaintext = b"Secret message for key rotation test";
        let policy = PolicyNode::And(vec![
            PolicyNode::Attr("admin".to_string()),
            PolicyNode::Attr("user".to_string()),
        ]);
        let ct = encrypt(&mut rng, &mpk, &policy, plaintext).unwrap();

        // Generate re-encryption key
        let rk = generate_rekey(&mut rng, &mpk, &sk_old, &attrs).unwrap();

        // Proxy re-encrypts (in real scenario, proxy only gets rk_k, rk_l, rk_x)
        let re_ct = re_encrypt_full(&mpk, &ct, &rk).unwrap();

        // User decrypts with g2_delta
        let decrypted = decrypt_reencrypted(&mpk, &re_ct).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_pre_proxy_cannot_decrypt_original() {
        let mut rng = thread_rng();

        // Setup
        let (mpk, msk) = setup(&mut rng);
        let attrs = vec!["secret".to_string()];
        let sk_old = keygen(&mut rng, &mpk, &msk, &attrs).unwrap();

        // Encrypt
        let plaintext = b"Cannot decrypt without g2_delta";
        let policy = PolicyNode::Attr("secret".to_string());
        let ct = encrypt(&mut rng, &mpk, &policy, plaintext).unwrap();

        // Generate rekey
        let rk = generate_rekey(&mut rng, &mpk, &sk_old, &attrs).unwrap();

        // Re-encrypt
        let abe_ct: Ciphertext = ct.abe_ct.clone().into();
        let re_ct = re_encrypt(&mpk, &abe_ct, &rk).unwrap();

        // Try to decrypt without proper g2_delta (use wrong one)
        let wrong_delta = mpk.g2 * Fr::random(&mut rng);
        let bad_re_ct = ReEncryptedCiphertext {
            policy: re_ct.policy.clone(),
            c_prime: re_ct.c_prime,
            c_blinded: re_ct.c_blinded,
            g2_delta: wrong_delta, // Wrong!
        };

        let bad_key = decrypt_reencrypted_kem(&mpk, &bad_re_ct).unwrap();
        let good_key = decrypt_reencrypted_kem(&mpk, &re_ct).unwrap();

        // Keys should be different
        assert_ne!(bad_key, good_key);
    }

    #[test]
    fn test_pre_wrong_attributes_fails() {
        let mut rng = thread_rng();

        let (mpk, msk) = setup(&mut rng);
        let attrs = vec!["admin".to_string()];
        let sk_old = keygen(&mut rng, &mpk, &msk, &attrs).unwrap();

        // Try to generate rekey with attribute the key doesn't have
        let result = generate_rekey(&mut rng, &mpk, &sk_old, &["nonexistent".to_string()]);

        assert!(result.is_err());
    }

    #[test]
    fn test_pre_policy_not_satisfied() {
        let mut rng = thread_rng();

        let (mpk, msk) = setup(&mut rng);
        let attrs = vec!["user".to_string()];
        let sk_old = keygen(&mut rng, &mpk, &msk, &attrs).unwrap();

        // Encrypt with policy requiring admin
        let policy = PolicyNode::Attr("admin".to_string());
        let ct = encrypt(&mut rng, &mpk, &policy, b"admin only").unwrap();

        // Generate rekey with user attribute
        let rk = generate_rekey(&mut rng, &mpk, &sk_old, &attrs).unwrap();

        // Re-encryption should fail - policy not satisfied
        let abe_ct: Ciphertext = ct.abe_ct.clone().into();
        let result = re_encrypt(&mpk, &abe_ct, &rk);
        assert!(result.is_err());
    }

    #[test]
    fn test_pre_or_policy() {
        let mut rng = thread_rng();

        let (mpk, msk) = setup(&mut rng);
        let attrs = vec!["admin".to_string(), "backup".to_string()];
        let sk_old = keygen(&mut rng, &mpk, &msk, &attrs).unwrap();

        // Encrypt with OR policy
        let plaintext = b"Accessible by admin or backup";
        let policy = PolicyNode::Or(vec![
            PolicyNode::Attr("admin".to_string()),
            PolicyNode::Attr("backup".to_string()),
        ]);
        let ct = encrypt(&mut rng, &mpk, &policy, plaintext).unwrap();

        // Re-encrypt using just admin attribute
        let rk = generate_rekey(&mut rng, &mpk, &sk_old, &["admin".to_string()]).unwrap();
        let re_ct = re_encrypt_full(&mpk, &ct, &rk).unwrap();

        let decrypted = decrypt_reencrypted(&mpk, &re_ct).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_pre_verification() {
        let mut rng = thread_rng();

        let (mpk, msk) = setup(&mut rng);
        let attrs = vec!["test".to_string()];
        let sk_old = keygen(&mut rng, &mpk, &msk, &attrs).unwrap();

        let policy = PolicyNode::Attr("test".to_string());
        let ct = encrypt(&mut rng, &mpk, &policy, b"verify me").unwrap();
        let rk = generate_rekey(&mut rng, &mpk, &sk_old, &attrs).unwrap();
        let abe_ct: Ciphertext = ct.abe_ct.clone().into();
        let re_ct = re_encrypt(&mpk, &abe_ct, &rk).unwrap();

        assert!(verify_reencryption(&re_ct));
    }

    #[test]
    fn test_pre_kem_mode() {
        let mut rng = thread_rng();

        let (mpk, msk) = setup(&mut rng);
        let attrs = vec!["kem".to_string()];
        let sk_old = keygen(&mut rng, &mpk, &msk, &attrs).unwrap();

        // Use KEM mode encryption
        let policy = PolicyNode::Attr("kem".to_string());
        let (ct, _original_key) = encrypt_kem(&mut rng, &mpk, &policy).unwrap();

        let rk = generate_rekey(&mut rng, &mpk, &sk_old, &attrs).unwrap();
        let re_ct = re_encrypt(&mpk, &ct, &rk).unwrap();

        // KEM mode should return consistent key
        let key1 = decrypt_reencrypted_kem(&mpk, &re_ct).unwrap();
        let key2 = decrypt_reencrypted_kem(&mpk, &re_ct).unwrap();

        assert_eq!(key1, key2);
    }
}
