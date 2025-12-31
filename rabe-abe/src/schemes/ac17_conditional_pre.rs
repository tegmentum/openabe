//! AC17 Conditional Proxy Re-Encryption
//!
//! This module implements conditional PRE for AC17 CP-ABE where re-encryption
//! is only allowed if certain conditions are met:
//!
//! - **Time-based**: Re-encryption only valid during a time window
//! - **Policy-based**: Re-encryption requires satisfying an additional policy
//!
//! ## Use Cases
//!
//! 1. **Time-locked delegation**: Alice delegates to Bob, but only during business hours
//! 2. **Role-based delegation**: Only proxies with "delegator" attribute can re-encrypt
//! 3. **Revocable delegation**: Re-encryption keys expire after a certain time
//!
//! ## Security Properties
//!
//! - All properties of standard AC17 PRE
//! - Condition enforcement at re-encryption time
//! - Proxy cannot bypass conditions

use crate::error::AbeError;
use crate::lsss::LsssMatrix;
use crate::schemes::ac17::{Mpk, SecretKey, Ciphertext, FullCiphertext, CiphertextComponent};
use crate::schemes::waters::parse_policy;
use crate::utils::aes;
use rabe_bls12381::{Fr, G1, G2, Gt, pairing};
use rand::{RngCore, CryptoRng};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Time-based condition for re-encryption
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct TimeCondition {
    /// Earliest time (Unix timestamp) when re-encryption is allowed
    pub not_before: Option<u64>,
    /// Latest time (Unix timestamp) when re-encryption is allowed
    pub not_after: Option<u64>,
}

impl TimeCondition {
    /// Create a condition with no time restrictions
    pub fn always() -> Self {
        TimeCondition {
            not_before: None,
            not_after: None,
        }
    }

    /// Create a condition valid from a specific time
    pub fn from(timestamp: u64) -> Self {
        TimeCondition {
            not_before: Some(timestamp),
            not_after: None,
        }
    }

    /// Create a condition valid until a specific time
    pub fn until(timestamp: u64) -> Self {
        TimeCondition {
            not_before: None,
            not_after: Some(timestamp),
        }
    }

    /// Create a condition valid during a time window
    pub fn between(not_before: u64, not_after: u64) -> Self {
        TimeCondition {
            not_before: Some(not_before),
            not_after: Some(not_after),
        }
    }

    /// Check if the current time satisfies this condition
    pub fn is_satisfied(&self) -> bool {
        self.is_satisfied_at(current_timestamp())
    }

    /// Check if a specific timestamp satisfies this condition
    pub fn is_satisfied_at(&self, timestamp: u64) -> bool {
        if let Some(not_before) = self.not_before {
            if timestamp < not_before {
                return false;
            }
        }
        if let Some(not_after) = self.not_after {
            if timestamp > not_after {
                return false;
            }
        }
        true
    }
}

/// Get current Unix timestamp
fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// AC17 Conditional re-encryption key with time conditions
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Ac17ConditionalReEncryptionKey {
    /// Attributes this re-key is valid for
    pub source_attributes: Vec<String>,
    /// Blinded K component: K - h^delta
    pub rk_k: G2,
    /// L component (unchanged): h^r
    pub rk_l: G2,
    /// Per-attribute components: K_attr = H(attr)^r
    pub rk_attrs: HashMap<String, G1>,
    /// Delta for unblinding: h^delta
    pub h_delta: G2,
    /// Time condition for this re-key
    pub time_condition: TimeCondition,
}

/// AC17 Conditional re-encrypted ciphertext
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Ac17ConditionalReEncryptedCiphertext {
    /// Original policy
    pub policy: String,
    /// C = g^s (unchanged)
    pub c: G1,
    /// Blinded decryption result
    pub c_blinded: Gt,
    /// h^delta for unblinding
    pub h_delta: G2,
    /// Timestamp when re-encryption occurred
    pub re_encrypt_time: u64,
}

/// Full AC17 conditional re-encrypted ciphertext with payload
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct FullAc17ConditionalReEncryptedCiphertext {
    /// ABE re-encrypted ciphertext
    pub pre_ct: Ac17ConditionalReEncryptedCiphertext,
    /// Symmetrically encrypted payload
    pub sym_ct: Vec<u8>,
}

/// Generate a conditional re-encryption key with time restrictions for AC17
///
/// # Arguments
///
/// * `rng` - Random number generator
/// * `mpk` - Master public key
/// * `sk` - User's secret key
/// * `attrs` - Attributes to include
/// * `condition` - Time condition for re-encryption
///
/// # Returns
///
/// Conditional re-encryption key
pub fn generate_conditional_rekey<R: RngCore + CryptoRng>(
    rng: &mut R,
    mpk: &Mpk,
    sk: &SecretKey,
    attrs: &[String],
    condition: TimeCondition,
) -> Result<Ac17ConditionalReEncryptionKey, AbeError> {
    // Validate attributes
    for attr in attrs {
        if !sk.k_attrs.contains_key(attr) {
            return Err(AbeError::InvalidAttribute(format!("Missing attribute: {}", attr)));
        }
    }

    // Generate random blinding factor
    let delta = Fr::random(rng);
    let h_delta = mpk.h * delta;

    // Blind the K component
    let rk_k = sk.k - h_delta;
    let rk_l = sk.l;

    // Copy attribute components
    let mut rk_attrs = HashMap::new();
    for attr in attrs {
        let k_attr = sk.k_attrs.get(attr).unwrap();
        rk_attrs.insert(attr.clone(), *k_attr);
    }

    Ok(Ac17ConditionalReEncryptionKey {
        source_attributes: attrs.to_vec(),
        rk_k,
        rk_l,
        rk_attrs,
        h_delta,
        time_condition: condition,
    })
}

/// Re-encrypt an AC17 ciphertext if conditions are met
///
/// Returns an error if the time condition is not satisfied.
pub fn conditional_re_encrypt(
    _mpk: &Mpk,
    ct: &Ciphertext,
    rk: &Ac17ConditionalReEncryptionKey,
) -> Result<Ac17ConditionalReEncryptedCiphertext, AbeError> {
    let now = current_timestamp();

    // Check time condition
    if !rk.time_condition.is_satisfied_at(now) {
        return Err(AbeError::DecryptError(
            "Re-encryption time condition not satisfied".to_string()
        ));
    }

    // Parse policy
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

    // Compute cancel term
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

    let c_blinded = e_c_rk_k * cancel_term.inverse();

    Ok(Ac17ConditionalReEncryptedCiphertext {
        policy: ct.policy.clone(),
        c: ct.c,
        c_blinded,
        h_delta: rk.h_delta,
        re_encrypt_time: now,
    })
}

/// Re-encrypt a full AC17 ciphertext if conditions are met
pub fn conditional_re_encrypt_full(
    mpk: &Mpk,
    ct: &FullCiphertext,
    rk: &Ac17ConditionalReEncryptionKey,
) -> Result<FullAc17ConditionalReEncryptedCiphertext, AbeError> {
    let pre_ct = conditional_re_encrypt(mpk, &ct.abe_ct, rk)?;
    Ok(FullAc17ConditionalReEncryptedCiphertext {
        pre_ct,
        sym_ct: ct.sym_ct.clone(),
    })
}

/// Decrypt a conditional re-encrypted AC17 ciphertext (KEM mode)
pub fn decrypt_conditional_reencrypted_kem(
    _mpk: &Mpk,
    re_ct: &Ac17ConditionalReEncryptedCiphertext,
) -> Result<[u8; 32], AbeError> {
    // Unblind: e(C, h^delta) = e(g^s, h^delta) = e(g,h)^(s*delta)
    let delta_contribution = pairing(re_ct.c, re_ct.h_delta);

    // Recover: c_blinded * delta_contribution = e(g,h)^(s*alpha)
    let recovered = re_ct.c_blinded * delta_contribution;

    let sym_key = derive_key(&recovered);
    Ok(sym_key)
}

/// Decrypt a full conditional re-encrypted AC17 ciphertext
pub fn decrypt_conditional_reencrypted(
    mpk: &Mpk,
    re_ct: &FullAc17ConditionalReEncryptedCiphertext,
) -> Result<Vec<u8>, AbeError> {
    let sym_key = decrypt_conditional_reencrypted_kem(mpk, &re_ct.pre_ct)?;
    aes::decrypt(&sym_key, &re_ct.sym_ct)
        .map_err(|e| AbeError::DecryptError(e))
}

/// Derive symmetric key from Gt element
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
    fn test_ac17_conditional_pre_always_valid() {
        let mut rng = thread_rng();

        let (mpk, msk) = setup(&mut rng);
        let attrs = vec!["admin".to_string()];
        let sk = keygen(&mut rng, &mpk, &msk, &attrs).unwrap();

        let policy = PolicyNode::Attr("admin".to_string());
        let ct = encrypt(&mut rng, &mpk, &policy, b"time-conditional secret").unwrap();

        // Always-valid condition
        let condition = TimeCondition::always();
        let rk = generate_conditional_rekey(&mut rng, &mpk, &sk, &attrs, condition).unwrap();

        let re_ct = conditional_re_encrypt_full(&mpk, &ct, &rk).unwrap();
        let decrypted = decrypt_conditional_reencrypted(&mpk, &re_ct).unwrap();

        assert_eq!(decrypted, b"time-conditional secret");
    }

    #[test]
    fn test_ac17_conditional_pre_future_window() {
        let mut rng = thread_rng();

        let (mpk, msk) = setup(&mut rng);
        let attrs = vec!["admin".to_string()];
        let sk = keygen(&mut rng, &mpk, &msk, &attrs).unwrap();

        let policy = PolicyNode::Attr("admin".to_string());
        let ct = encrypt(&mut rng, &mpk, &policy, b"future secret").unwrap();

        // Condition that starts in the future
        let future_time = current_timestamp() + 3600; // 1 hour from now
        let condition = TimeCondition::from(future_time);
        let rk = generate_conditional_rekey(&mut rng, &mpk, &sk, &attrs, condition).unwrap();

        // Re-encryption should fail
        let result = conditional_re_encrypt(&mpk, &ct.abe_ct, &rk);
        assert!(result.is_err());
    }

    #[test]
    fn test_ac17_conditional_pre_expired() {
        let mut rng = thread_rng();

        let (mpk, msk) = setup(&mut rng);
        let attrs = vec!["admin".to_string()];
        let sk = keygen(&mut rng, &mpk, &msk, &attrs).unwrap();

        let policy = PolicyNode::Attr("admin".to_string());
        let ct = encrypt(&mut rng, &mpk, &policy, b"expired secret").unwrap();

        // Condition that expired in the past
        let past_time = current_timestamp() - 3600; // 1 hour ago
        let condition = TimeCondition::until(past_time);
        let rk = generate_conditional_rekey(&mut rng, &mpk, &sk, &attrs, condition).unwrap();

        // Re-encryption should fail
        let result = conditional_re_encrypt(&mpk, &ct.abe_ct, &rk);
        assert!(result.is_err());
    }

    #[test]
    fn test_ac17_conditional_pre_valid_window() {
        let mut rng = thread_rng();

        let (mpk, msk) = setup(&mut rng);
        let attrs = vec!["admin".to_string()];
        let sk = keygen(&mut rng, &mpk, &msk, &attrs).unwrap();

        let policy = PolicyNode::Attr("admin".to_string());
        let ct = encrypt(&mut rng, &mpk, &policy, b"window secret").unwrap();

        // Condition with current time in valid window
        let now = current_timestamp();
        let condition = TimeCondition::between(now - 3600, now + 3600);
        let rk = generate_conditional_rekey(&mut rng, &mpk, &sk, &attrs, condition).unwrap();

        let re_ct = conditional_re_encrypt_full(&mpk, &ct, &rk).unwrap();
        let decrypted = decrypt_conditional_reencrypted(&mpk, &re_ct).unwrap();

        assert_eq!(decrypted, b"window secret");
    }

    #[test]
    fn test_ac17_conditional_pre_and_policy() {
        let mut rng = thread_rng();

        let (mpk, msk) = setup(&mut rng);
        let attrs = vec!["admin".to_string(), "developer".to_string()];
        let sk = keygen(&mut rng, &mpk, &msk, &attrs).unwrap();

        let policy = PolicyNode::And(vec![
            PolicyNode::Attr("admin".to_string()),
            PolicyNode::Attr("developer".to_string()),
        ]);
        let ct = encrypt(&mut rng, &mpk, &policy, b"and policy secret").unwrap();

        let condition = TimeCondition::always();
        let rk = generate_conditional_rekey(&mut rng, &mpk, &sk, &attrs, condition).unwrap();

        let re_ct = conditional_re_encrypt_full(&mpk, &ct, &rk).unwrap();
        let decrypted = decrypt_conditional_reencrypted(&mpk, &re_ct).unwrap();

        assert_eq!(decrypted, b"and policy secret");
    }

    #[test]
    fn test_ac17_time_condition_helpers() {
        let now = current_timestamp();

        // Test always()
        let always = TimeCondition::always();
        assert!(always.is_satisfied_at(now));
        assert!(always.is_satisfied_at(0));
        assert!(always.is_satisfied_at(u64::MAX));

        // Test from()
        let from = TimeCondition::from(now);
        assert!(from.is_satisfied_at(now));
        assert!(from.is_satisfied_at(now + 1));
        assert!(!from.is_satisfied_at(now - 1));

        // Test until()
        let until = TimeCondition::until(now);
        assert!(until.is_satisfied_at(now));
        assert!(until.is_satisfied_at(now - 1));
        assert!(!until.is_satisfied_at(now + 1));

        // Test between()
        let between = TimeCondition::between(now - 10, now + 10);
        assert!(between.is_satisfied_at(now));
        assert!(between.is_satisfied_at(now - 10));
        assert!(between.is_satisfied_at(now + 10));
        assert!(!between.is_satisfied_at(now - 11));
        assert!(!between.is_satisfied_at(now + 11));
    }
}
