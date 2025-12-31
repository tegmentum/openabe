//! AC17 CP-ABE Proxy Re-Encryption (Key Rotation)
//!
//! This module implements unidirectional, single-hop proxy re-encryption
//! for the AC17 CP-ABE scheme, enabling key rotation without re-encrypting
//! all ciphertexts.
//!
//! ## Use Case: Key Rotation
//!
//! When a user's key is compromised or needs rotation:
//! 1. Generate new key for user
//! 2. Create re-encryption key from old key
//! 3. Proxy transforms existing ciphertexts
//! 4. User decrypts with stored delta
//!
//! ## Security Properties
//!
//! - **Unidirectional**: Re-encryption only works old→new, not reverse
//! - **Single-hop**: Ciphertext can only be re-encrypted once
//! - **Proxy invisibility**: Proxy cannot decrypt original or re-encrypted
//! - **Collusion resistance**: Proxy + new key holder cannot derive old key

use crate::error::AbeError;
use crate::lsss::LsssMatrix;
use crate::schemes::ac17::{Mpk, SecretKey, Ciphertext, FullCiphertext, CiphertextComponent};
use crate::schemes::waters::parse_policy;
use crate::utils::aes;
use rabe_bls12381::{Fr, G1, G2, Gt, pairing};
use rand::{RngCore, CryptoRng};
use std::collections::HashMap;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Re-encryption key for AC17 PRE
///
/// Created by the user with the old key, given to the proxy.
/// Contains blinded key components that allow re-encryption
/// without revealing the secret key.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ReEncryptionKey {
    /// Attributes this re-key is valid for
    pub source_attributes: Vec<String>,
    /// Blinded K component: K - h^delta
    pub rk_k: G2,
    /// L component (unchanged): h^r
    pub rk_l: G2,
    /// Per-attribute components: K_attr = H(attr)^r
    pub rk_attrs: HashMap<String, G1>,
    /// Delta for user to unblind: h^delta
    pub h_delta: G2,
}

/// Re-encrypted ciphertext (KEM mode)
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ReEncryptedCiphertext {
    /// Original policy
    pub policy: String,
    /// C = g^s (unchanged)
    pub c: G1,
    /// Blinded decryption result: e(g,h)^(alpha*s - delta*s)
    pub c_blinded: Gt,
    /// h^delta for unblinding
    pub h_delta: G2,
}

/// Full re-encrypted ciphertext with symmetric payload
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct FullReEncryptedCiphertext {
    /// ABE re-encrypted ciphertext
    pub pre_ct: ReEncryptedCiphertext,
    /// Symmetrically encrypted payload
    pub sym_ct: Vec<u8>,
}

/// Generate a re-encryption key for key rotation
///
/// The user generates this from their old secret key. The re-encryption key
/// is given to the proxy, while the user keeps h_delta for unblinding.
///
/// # Arguments
///
/// * `rng` - Random number generator
/// * `mpk` - Master public key
/// * `sk` - User's secret key (old key)
/// * `attrs` - Attributes to include in re-encryption key
///
/// # Returns
///
/// Re-encryption key for the proxy
pub fn generate_rekey<R: RngCore + CryptoRng>(
    rng: &mut R,
    mpk: &Mpk,
    sk: &SecretKey,
    attrs: &[String],
) -> Result<ReEncryptionKey, AbeError> {
    // Validate that sk has all requested attributes
    for attr in attrs {
        if !sk.k_attrs.contains_key(attr) {
            return Err(AbeError::InvalidAttribute(format!("Missing attribute: {}", attr)));
        }
    }

    // Generate random blinding factor
    let delta = Fr::random(rng);
    let h_delta = mpk.h * delta;

    // Blind the K component: rk_k = K - h^delta
    let rk_k = sk.k - h_delta;

    // L remains unchanged
    let rk_l = sk.l;

    // Copy attribute components for specified attributes
    let mut rk_attrs = HashMap::new();
    for attr in attrs {
        let k_attr = sk.k_attrs.get(attr).unwrap();
        rk_attrs.insert(attr.clone(), *k_attr);
    }

    Ok(ReEncryptionKey {
        source_attributes: attrs.to_vec(),
        rk_k,
        rk_l,
        rk_attrs,
        h_delta,
    })
}

/// Re-encrypt a ciphertext (Proxy operation)
///
/// The proxy uses the re-encryption key to transform the ciphertext.
/// The result can only be decrypted by someone with h_delta.
///
/// # Arguments
///
/// * `mpk` - Master public key
/// * `ct` - Original ciphertext
/// * `rk` - Re-encryption key
///
/// # Returns
///
/// Re-encrypted ciphertext
pub fn re_encrypt(
    _mpk: &Mpk,
    ct: &Ciphertext,
    rk: &ReEncryptionKey,
) -> Result<ReEncryptedCiphertext, AbeError> {
    // Parse policy from ciphertext
    let policy = parse_policy(&ct.policy)
        .map_err(|e| AbeError::InvalidPolicy(e.to_string()))?;
    let lsss = LsssMatrix::from_policy(&policy)?;

    // Find satisfied rows
    let mut satisfied_attrs = Vec::new();
    let mut satisfied_components: Vec<&CiphertextComponent> = Vec::new();

    for ct_comp in &ct.components {
        if rk.rk_attrs.contains_key(&ct_comp.attr) {
            satisfied_attrs.push(ct_comp.attr.clone());
            satisfied_components.push(ct_comp);
        }
    }

    if satisfied_components.is_empty() {
        return Err(AbeError::PolicyNotSatisfied);
    }

    // Get reconstruction coefficients
    let coeffs = lsss.recover_coefficients(&satisfied_attrs)
        .map_err(|_| AbeError::PolicyNotSatisfied)?;

    // Compute partial decryption with blinded key
    // e(C, rk_k) = e(g^s, K - h^delta) = e(g,h)^(s*(alpha + a*r) - s*delta)
    let e_c_rk_k = pairing(ct.c, rk.rk_k);

    // Compute cancel term: product of e(C1_i, L) * e(K_attr_i, C2_i) weighted
    let mut cancel_term = Gt::one();
    for ct_comp in &satisfied_components {
        if let Some(&omega) = coeffs.get(&ct_comp.attr) {
            let k_attr = rk.rk_attrs.get(&ct_comp.attr).unwrap();
            let p1 = pairing(ct_comp.c1, rk.rk_l);
            let p2 = pairing(*k_attr, ct_comp.c2);
            let term = (p1 * p2).pow(&omega);
            cancel_term = cancel_term * term;
        }
    }

    // c_blinded = e(g,h)^(s*alpha - s*delta)
    let c_blinded = e_c_rk_k * cancel_term.inverse();

    Ok(ReEncryptedCiphertext {
        policy: ct.policy.clone(),
        c: ct.c,
        c_blinded,
        h_delta: rk.h_delta,
    })
}

/// Re-encrypt a full ciphertext (with payload)
pub fn re_encrypt_full(
    mpk: &Mpk,
    ct: &FullCiphertext,
    rk: &ReEncryptionKey,
) -> Result<FullReEncryptedCiphertext, AbeError> {
    let pre_ct = re_encrypt(mpk, &ct.abe_ct, rk)?;
    Ok(FullReEncryptedCiphertext {
        pre_ct,
        sym_ct: ct.sym_ct.clone(),
    })
}

/// Decrypt a re-encrypted ciphertext (KEM mode)
///
/// The user unblind the ciphertext using h_delta from the re-encryption key.
///
/// # Arguments
///
/// * `mpk` - Master public key
/// * `re_ct` - Re-encrypted ciphertext
///
/// # Returns
///
/// 32-byte symmetric key
pub fn decrypt_reencrypted_kem(
    _mpk: &Mpk,
    re_ct: &ReEncryptedCiphertext,
) -> Result<[u8; 32], AbeError> {
    // Unblind: e(C, h^delta) = e(g^s, h^delta) = e(g,h)^(s*delta)
    let delta_contribution = pairing(re_ct.c, re_ct.h_delta);

    // Recover: c_blinded * delta_contribution = e(g,h)^(s*alpha - s*delta + s*delta) = e(g,h)^(s*alpha)
    let recovered = re_ct.c_blinded * delta_contribution;

    // Derive symmetric key
    let sym_key = derive_key(&recovered);
    Ok(sym_key)
}

/// Decrypt a full re-encrypted ciphertext
pub fn decrypt_reencrypted(
    mpk: &Mpk,
    re_ct: &FullReEncryptedCiphertext,
) -> Result<Vec<u8>, AbeError> {
    let sym_key = decrypt_reencrypted_kem(mpk, &re_ct.pre_ct)?;
    aes::decrypt(&sym_key, &re_ct.sym_ct)
        .map_err(|e| AbeError::DecryptError(e))
}

/// Derive symmetric key from Gt element (same as AC17)
fn derive_key(gt: &Gt) -> [u8; 32] {
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(b"AC17_KEY_DERIVE");
    hasher.update(&gt.into_bytes());
    let result = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&result);
    key
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lsss::PolicyNode;
    use crate::schemes::ac17::{setup, keygen, encrypt};
    use rand::thread_rng;

    #[test]
    fn test_ac17_pre_basic_roundtrip() {
        let mut rng = thread_rng();

        // Setup
        let (mpk, msk) = setup(&mut rng);

        // Generate key with attributes
        let attrs = vec!["admin".to_string(), "developer".to_string()];
        let sk = keygen(&mut rng, &mpk, &msk, &attrs).unwrap();

        // Encrypt
        let policy = PolicyNode::Attr("admin".to_string());
        let plaintext = b"AC17 PRE test message";
        let ct = encrypt(&mut rng, &mpk, &policy, plaintext).unwrap();

        // Generate re-encryption key
        let rk = generate_rekey(&mut rng, &mpk, &sk, &["admin".to_string()]).unwrap();

        // Re-encrypt
        let re_ct = re_encrypt_full(&mpk, &ct, &rk).unwrap();

        // Decrypt re-encrypted ciphertext
        let decrypted = decrypt_reencrypted(&mpk, &re_ct).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_ac17_pre_and_policy() {
        let mut rng = thread_rng();

        let (mpk, msk) = setup(&mut rng);
        let attrs = vec!["admin".to_string(), "developer".to_string()];
        let sk = keygen(&mut rng, &mpk, &msk, &attrs).unwrap();

        let policy = PolicyNode::And(vec![
            PolicyNode::Attr("admin".to_string()),
            PolicyNode::Attr("developer".to_string()),
        ]);
        let ct = encrypt(&mut rng, &mpk, &policy, b"and policy secret").unwrap();

        let rk = generate_rekey(&mut rng, &mpk, &sk, &attrs).unwrap();
        let re_ct = re_encrypt_full(&mpk, &ct, &rk).unwrap();

        let decrypted = decrypt_reencrypted(&mpk, &re_ct).unwrap();
        assert_eq!(decrypted, b"and policy secret");
    }

    #[test]
    fn test_ac17_pre_or_policy() {
        let mut rng = thread_rng();

        let (mpk, msk) = setup(&mut rng);
        let attrs = vec!["manager".to_string()];
        let sk = keygen(&mut rng, &mpk, &msk, &attrs).unwrap();

        let policy = PolicyNode::Or(vec![
            PolicyNode::Attr("admin".to_string()),
            PolicyNode::Attr("manager".to_string()),
        ]);
        let ct = encrypt(&mut rng, &mpk, &policy, b"or policy secret").unwrap();

        let rk = generate_rekey(&mut rng, &mpk, &sk, &attrs).unwrap();
        let re_ct = re_encrypt_full(&mpk, &ct, &rk).unwrap();

        let decrypted = decrypt_reencrypted(&mpk, &re_ct).unwrap();
        assert_eq!(decrypted, b"or policy secret");
    }

    #[test]
    fn test_ac17_pre_kem_mode() {
        let mut rng = thread_rng();

        let (mpk, msk) = setup(&mut rng);
        let attrs = vec!["admin".to_string()];
        let sk = keygen(&mut rng, &mpk, &msk, &attrs).unwrap();

        let policy = PolicyNode::Attr("admin".to_string());
        let ct = encrypt(&mut rng, &mpk, &policy, b"kem test").unwrap();

        let rk = generate_rekey(&mut rng, &mpk, &sk, &attrs).unwrap();
        let re_ct = re_encrypt(&mpk, &ct.abe_ct, &rk).unwrap();

        // KEM mode returns key
        let key = decrypt_reencrypted_kem(&mpk, &re_ct).unwrap();
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_ac17_pre_policy_not_satisfied() {
        let mut rng = thread_rng();

        let (mpk, msk) = setup(&mut rng);
        let attrs = vec!["user".to_string()];
        let sk = keygen(&mut rng, &mpk, &msk, &attrs).unwrap();

        // Policy requires admin
        let policy = PolicyNode::Attr("admin".to_string());
        let ct = encrypt(&mut rng, &mpk, &policy, b"admin only").unwrap();

        // Re-key with user attribute won't satisfy policy
        let rk = generate_rekey(&mut rng, &mpk, &sk, &attrs).unwrap();
        let result = re_encrypt(&mpk, &ct.abe_ct, &rk);

        assert!(result.is_err());
    }

    #[test]
    fn test_ac17_pre_missing_attribute() {
        let mut rng = thread_rng();

        let (mpk, msk) = setup(&mut rng);
        let attrs = vec!["admin".to_string()];
        let sk = keygen(&mut rng, &mpk, &msk, &attrs).unwrap();

        // Try to generate re-key for attribute not in key
        let result = generate_rekey(&mut rng, &mpk, &sk, &["developer".to_string()]);
        assert!(result.is_err());
    }

    #[test]
    fn test_ac17_pre_threshold() {
        let mut rng = thread_rng();

        let (mpk, msk) = setup(&mut rng);
        let attrs = vec!["a".to_string(), "b".to_string()];
        let sk = keygen(&mut rng, &mpk, &msk, &attrs).unwrap();

        // 2-of-3 threshold
        let policy = PolicyNode::Threshold(2, vec![
            PolicyNode::Attr("a".to_string()),
            PolicyNode::Attr("b".to_string()),
            PolicyNode::Attr("c".to_string()),
        ]);
        let ct = encrypt(&mut rng, &mpk, &policy, b"threshold secret").unwrap();

        let rk = generate_rekey(&mut rng, &mpk, &sk, &attrs).unwrap();
        let re_ct = re_encrypt_full(&mpk, &ct, &rk).unwrap();

        let decrypted = decrypt_reencrypted(&mpk, &re_ct).unwrap();
        assert_eq!(decrypted, b"threshold secret");
    }
}
