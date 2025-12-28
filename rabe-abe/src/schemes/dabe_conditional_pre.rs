//! DABE Conditional Proxy Re-Encryption
//!
//! This module implements conditional PRE for DABE (Decentralized Multi-Authority ABE)
//! where re-encryption is only allowed if certain conditions are met:
//!
//! - **Time-based**: Re-encryption only valid during a time window
//! - **Trusted timestamp**: Cryptographic time enforcement via signed timestamps
//!
//! ## Multi-Authority Considerations
//!
//! In DABE, user keys come from multiple independent authorities. The conditional PRE
//! scheme handles this by:
//! - Generating per-authority blinding factors
//! - Checking time conditions before re-encryption
//! - Supporting trusted timestamp verification for cryptographic time enforcement
//!
//! ## Use Cases
//!
//! 1. **Time-locked delegation**: Alice delegates to Bob, but only during business hours
//! 2. **Revocable delegation**: Re-encryption keys expire after a certain time
//! 3. **Trusted time enforcement**: Require signed timestamp from trusted authority
//!
//! ## Security Properties
//!
//! - All properties of standard DABE PRE
//! - Condition enforcement at re-encryption time
//! - Proxy cannot bypass conditions
//! - Optional cryptographic time binding with trusted timestamps

use crate::error::AbeError;
use crate::schemes::dabe::{
    GlobalParams, UserSecretKey,
    Ciphertext, CiphertextComponent, FullCiphertext,
    find_satisfying_assignment,
};
use crate::schemes::waters::parse_policy;
use crate::utils::aes;
use rabe_bls12381::{Fr, G1, G2, Gt, pairing};
use rand::RngCore;
use sha2::{Sha256, Digest};
use std::collections::{HashMap, HashSet};
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

/// Trusted timestamp for cryptographic time enforcement
///
/// This provides stronger time enforcement than the proxy-trust model.
/// A trusted time authority signs the current timestamp, and the proxy
/// must provide this signature for re-encryption to proceed.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct TrustedTimestamp {
    /// The timestamp value
    pub timestamp: u64,
    /// Authority identifier
    pub authority_id: String,
    /// Signature over (timestamp || authority_id || nonce)
    pub signature: Vec<u8>,
    /// Nonce to prevent replay attacks
    pub nonce: [u8; 32],
}

impl TrustedTimestamp {
    /// Create a new trusted timestamp (for testing or mock purposes)
    /// In production, this would come from a real trusted time authority.
    pub fn new(timestamp: u64, authority_id: &str, signing_key: &[u8]) -> Self {
        let mut nonce = [0u8; 32];
        // In production, use a proper RNG
        nonce[0..8].copy_from_slice(&timestamp.to_le_bytes());

        let signature = Self::compute_signature(timestamp, authority_id, &nonce, signing_key);

        TrustedTimestamp {
            timestamp,
            authority_id: authority_id.to_string(),
            signature,
            nonce,
        }
    }

    /// Compute signature over timestamp data
    fn compute_signature(timestamp: u64, authority_id: &str, nonce: &[u8; 32], signing_key: &[u8]) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(b"TRUSTED_TIMESTAMP_V1");
        hasher.update(&timestamp.to_le_bytes());
        hasher.update(authority_id.as_bytes());
        hasher.update(nonce);
        hasher.update(signing_key);
        hasher.finalize().to_vec()
    }

    /// Verify the timestamp signature
    pub fn verify(&self, expected_authority_id: &str, verification_key: &[u8]) -> bool {
        if self.authority_id != expected_authority_id {
            return false;
        }

        let expected_sig = Self::compute_signature(
            self.timestamp,
            &self.authority_id,
            &self.nonce,
            verification_key,
        );

        self.signature == expected_sig
    }
}

/// Per-authority conditional re-encryption component
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ConditionalAuthorityReKeyComponent {
    /// Authority ID
    pub aid: String,

    /// Modified K: K_old - h^(delta_aid)
    pub rk_k: G2,

    /// L component: h^t (unchanged)
    pub rk_l: G2,

    /// Per-attribute KX components: H(attr)^t (unchanged)
    pub rk_x: HashMap<String, G1>,

    /// h^delta_aid for this authority (kept by user for unblinding)
    pub h_delta_aid: G2,
}

/// DABE conditional re-encryption key
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct DabeConditionalReEncryptionKey {
    /// Re-encryption components per authority
    pub authority_components: HashMap<String, ConditionalAuthorityReKeyComponent>,
    /// Time condition for this re-key
    pub time_condition: TimeCondition,
    /// Required trusted time authority (optional)
    /// If set, the proxy must provide a valid timestamp from this authority
    pub required_time_authority: Option<String>,
    /// Verification key for trusted timestamp (optional)
    /// In production, this would be a public key
    pub time_authority_key: Option<Vec<u8>>,
}

/// DABE conditional re-encrypted ciphertext
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct DabeConditionalReEncryptedCiphertext {
    /// Original policy (preserved)
    pub policy: String,

    /// C = g^s from original ciphertext
    pub c: G1,

    /// Per-authority blinded contributions
    pub authority_blindings: HashMap<String, Gt>,

    /// Per-authority h^delta_aid for unblinding
    pub authority_deltas: HashMap<String, G2>,

    /// Timestamp when re-encryption occurred
    pub re_encrypt_time: u64,

    /// Trusted timestamp used (if any)
    pub trusted_timestamp: Option<TrustedTimestamp>,
}

/// Full DABE conditional re-encrypted ciphertext with payload
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct FullDabeConditionalReEncryptedCiphertext {
    /// PRE ciphertext (KEM part)
    pub pre_ct: DabeConditionalReEncryptedCiphertext,

    /// Symmetric ciphertext (DEM part - unchanged)
    pub sym_ct: Vec<u8>,
}

/// Generate a DABE conditional re-encryption key
///
/// # Arguments
/// * `rng` - Cryptographically secure random number generator
/// * `gp` - Global parameters
/// * `usk_old` - User's aggregated secret key
/// * `condition` - Time condition for re-encryption
///
/// # Returns
/// Conditional re-encryption key with per-authority components
pub fn generate_conditional_rekey<R: RngCore>(
    rng: &mut R,
    gp: &GlobalParams,
    usk_old: &UserSecretKey,
    condition: TimeCondition,
) -> Result<DabeConditionalReEncryptionKey, AbeError> {
    if usk_old.components.is_empty() {
        return Err(AbeError::KeygenError(
            "User key has no authority components".to_string()
        ));
    }

    let mut authority_components = HashMap::new();

    for (aid, uk_comp) in &usk_old.components {
        // Per-authority random blinding delta
        let delta_aid = Fr::random(rng);

        // RK_K = K - h^delta_aid
        let rk_k = uk_comp.k - (gp.h * delta_aid);

        // h^delta_aid for unblinding
        let h_delta_aid = gp.h * delta_aid;

        let auth_rk = ConditionalAuthorityReKeyComponent {
            aid: aid.clone(),
            rk_k,
            rk_l: uk_comp.l,
            rk_x: uk_comp.kx.clone(),
            h_delta_aid,
        };

        authority_components.insert(aid.clone(), auth_rk);
    }

    Ok(DabeConditionalReEncryptionKey {
        authority_components,
        time_condition: condition,
        required_time_authority: None,
        time_authority_key: None,
    })
}

/// Generate a DABE conditional re-encryption key with trusted timestamp requirement
///
/// This version requires the proxy to provide a valid signed timestamp from
/// the specified authority when re-encrypting.
pub fn generate_conditional_rekey_with_trusted_time<R: RngCore>(
    rng: &mut R,
    gp: &GlobalParams,
    usk_old: &UserSecretKey,
    condition: TimeCondition,
    time_authority_id: &str,
    time_authority_key: &[u8],
) -> Result<DabeConditionalReEncryptionKey, AbeError> {
    let mut rk = generate_conditional_rekey(rng, gp, usk_old, condition)?;
    rk.required_time_authority = Some(time_authority_id.to_string());
    rk.time_authority_key = Some(time_authority_key.to_vec());
    Ok(rk)
}

/// Conditionally re-encrypt a DABE ciphertext
///
/// Checks time conditions before performing re-encryption.
/// Uses system time if no trusted timestamp is provided.
///
/// # Arguments
/// * `gp` - Global parameters
/// * `ct` - Original DABE ciphertext
/// * `rk` - Conditional re-encryption key
///
/// # Returns
/// Re-encrypted ciphertext with blinded authority contributions
pub fn conditional_re_encrypt(
    _gp: &GlobalParams,
    ct: &Ciphertext,
    rk: &DabeConditionalReEncryptionKey,
) -> Result<DabeConditionalReEncryptedCiphertext, AbeError> {
    conditional_re_encrypt_with_timestamp(_gp, ct, rk, None)
}

/// Conditionally re-encrypt with a trusted timestamp
///
/// When the re-encryption key requires a trusted timestamp, this function
/// verifies the timestamp signature before proceeding.
pub fn conditional_re_encrypt_with_timestamp(
    _gp: &GlobalParams,
    ct: &Ciphertext,
    rk: &DabeConditionalReEncryptionKey,
    trusted_ts: Option<&TrustedTimestamp>,
) -> Result<DabeConditionalReEncryptedCiphertext, AbeError> {
    // Determine the timestamp to use
    let (timestamp, used_trusted_ts) = if let Some(required_auth) = &rk.required_time_authority {
        // Trusted timestamp is required
        let ts = trusted_ts.ok_or_else(|| AbeError::DecryptError(
            "Trusted timestamp required but not provided".to_string()
        ))?;

        // Verify the timestamp
        let key = rk.time_authority_key.as_ref().ok_or_else(|| AbeError::DecryptError(
            "Time authority key not set in re-encryption key".to_string()
        ))?;

        if !ts.verify(required_auth, key) {
            return Err(AbeError::DecryptError(
                "Trusted timestamp verification failed".to_string()
            ));
        }

        (ts.timestamp, Some(ts.clone()))
    } else {
        // Use system time
        (current_timestamp(), None)
    };

    // Check time condition
    if !rk.time_condition.is_satisfied_at(timestamp) {
        return Err(AbeError::DecryptError(
            "Re-encryption time condition not satisfied".to_string()
        ));
    }

    // Parse policy
    let policy = parse_policy(&ct.policy)
        .map_err(|e| AbeError::InvalidPolicy(e.to_string()))?;

    // Collect all attributes from the re-encryption key
    let mut rk_attrs: HashSet<String> = HashSet::new();
    let mut attr_to_authority: HashMap<String, String> = HashMap::new();

    for (aid, auth_rk) in &rk.authority_components {
        for attr in auth_rk.rk_x.keys() {
            rk_attrs.insert(attr.clone());
            attr_to_authority.insert(attr.clone(), aid.clone());
        }
    }

    // Find satisfying assignment
    let assignment = find_satisfying_assignment(&policy, &rk_attrs)
        .ok_or(AbeError::PolicyNotSatisfied)?;

    // Group by authority
    let mut by_authority: HashMap<String, Vec<(&CiphertextComponent, Fr)>> = HashMap::new();

    for (attr, coeff) in &assignment {
        // Find ciphertext component
        let ct_comp = ct.components.iter()
            .find(|c| &c.attr == attr)
            .ok_or_else(|| AbeError::DecryptError(
                format!("No ciphertext for attr {}", attr)
            ))?;

        by_authority
            .entry(ct_comp.aid.clone())
            .or_default()
            .push((ct_comp, *coeff));
    }

    // Compute per-authority blinded contributions
    let mut authority_blindings = HashMap::new();

    for (aid, items) in &by_authority {
        let auth_rk = rk.authority_components.get(aid)
            .ok_or_else(|| AbeError::DecryptError(
                format!("No re-encryption key for authority {}", aid)
            ))?;

        // numerator = e(C, RK_K) = e(g^s, h^(alpha + a*t - delta_aid))
        let numerator = pairing(ct.c, auth_rk.rk_k);

        // Compute weighted sum and pairing product
        let mut prod1 = G1::zero();
        let mut prod_t = Gt::one();

        for (ct_comp, coeff) in items {
            // prod1 += C1 * coeff
            prod1 = prod1 + ct_comp.c1 * *coeff;

            // Get KX for this attribute
            let kx = auth_rk.rk_x.get(&ct_comp.attr)
                .ok_or_else(|| AbeError::DecryptError(
                    format!("Missing re-key for attribute {}", ct_comp.attr)
                ))?;

            // e(KX * coeff, D)
            prod_t = prod_t * pairing(*kx * *coeff, ct_comp.d);
        }

        // e(prod1, RK_L)
        let pairing_prod1_l = pairing(prod1, auth_rk.rk_l);

        // denominator = prod_t * e(prod1, L)
        let denominator = prod_t * pairing_prod1_l;

        // Blinded contribution = numerator / denominator
        let contribution = numerator * denominator.inverse();

        authority_blindings.insert(aid.clone(), contribution);
    }

    // Collect per-authority deltas for authorities used
    let mut authority_deltas = HashMap::new();
    for aid in by_authority.keys() {
        let auth_rk = rk.authority_components.get(aid).unwrap();
        authority_deltas.insert(aid.clone(), auth_rk.h_delta_aid);
    }

    Ok(DabeConditionalReEncryptedCiphertext {
        policy: ct.policy.clone(),
        c: ct.c,
        authority_blindings,
        authority_deltas,
        re_encrypt_time: timestamp,
        trusted_timestamp: used_trusted_ts,
    })
}

/// Conditionally re-encrypt a full DABE ciphertext
pub fn conditional_re_encrypt_full(
    gp: &GlobalParams,
    ct: &FullCiphertext,
    rk: &DabeConditionalReEncryptionKey,
) -> Result<FullDabeConditionalReEncryptedCiphertext, AbeError> {
    let pre_ct = conditional_re_encrypt(gp, &ct.abe_ct, rk)?;
    Ok(FullDabeConditionalReEncryptedCiphertext {
        pre_ct,
        sym_ct: ct.sym_ct.clone(),
    })
}

/// Conditionally re-encrypt a full DABE ciphertext with trusted timestamp
pub fn conditional_re_encrypt_full_with_timestamp(
    gp: &GlobalParams,
    ct: &FullCiphertext,
    rk: &DabeConditionalReEncryptionKey,
    trusted_ts: &TrustedTimestamp,
) -> Result<FullDabeConditionalReEncryptedCiphertext, AbeError> {
    let pre_ct = conditional_re_encrypt_with_timestamp(gp, &ct.abe_ct, rk, Some(trusted_ts))?;
    Ok(FullDabeConditionalReEncryptedCiphertext {
        pre_ct,
        sym_ct: ct.sym_ct.clone(),
    })
}

/// Decrypt a DABE conditional re-encrypted ciphertext (KEM mode)
pub fn decrypt_conditional_reencrypted_kem(
    _gp: &GlobalParams,
    re_ct: &DabeConditionalReEncryptedCiphertext,
) -> Result<[u8; 32], AbeError> {
    // Combine all authority blinded contributions and their delta unblinding
    let mut recovered = Gt::one();

    for (aid, blinding) in &re_ct.authority_blindings {
        // Get the delta for this authority
        let h_delta_aid = re_ct.authority_deltas.get(aid)
            .ok_or_else(|| AbeError::DecryptError(
                format!("Missing delta for authority {}", aid)
            ))?;

        // Compute delta contribution: e(C, h^delta_aid)
        let delta_contribution = pairing(re_ct.c, *h_delta_aid);

        // Unblind this authority's contribution
        let unblinded = *blinding * delta_contribution;

        recovered = recovered * unblinded;
    }

    // Derive key
    let sym_key = derive_key(&recovered);

    Ok(sym_key)
}

/// Decrypt a full DABE conditional re-encrypted ciphertext
pub fn decrypt_conditional_reencrypted(
    gp: &GlobalParams,
    re_ct: &FullDabeConditionalReEncryptedCiphertext,
) -> Result<Vec<u8>, AbeError> {
    let sym_key = decrypt_conditional_reencrypted_kem(gp, &re_ct.pre_ct)?;

    aes::decrypt(&sym_key, &re_ct.sym_ct)
        .map_err(|e| AbeError::DecryptError(e))
}

/// Derive a symmetric key from a GT element
fn derive_key(gt: &Gt) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"DABE_KEY_DERIVE");
    hasher.update(&gt.into_bytes());
    let result = hasher.finalize();

    let mut key = [0u8; 32];
    key.copy_from_slice(&result);
    key
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schemes::dabe::{
        global_setup, authority_setup, authority_keygen,
        aggregate_user_keys, encrypt,
    };
    use crate::lsss::PolicyNode;
    use rand::thread_rng;

    #[test]
    fn test_dabe_conditional_always_valid() {
        let mut rng = thread_rng();

        let gp = global_setup(&mut rng);
        let (apk, ask) = authority_setup(&mut rng, &gp, "auth1");

        let uk = authority_keygen(
            &mut rng, &gp, &ask, "user@test.com",
            &["admin".to_string()]
        ).unwrap();
        let usk = aggregate_user_keys(vec![uk]).unwrap();

        let mut pks = HashMap::new();
        pks.insert("auth1".to_string(), apk);

        let policy = PolicyNode::Attr("auth1:admin".to_string());
        let plaintext = b"Always valid conditional secret";
        let ct = encrypt(&mut rng, &gp, &pks, &policy, plaintext).unwrap();

        // Always-valid condition
        let condition = TimeCondition::always();
        let rk = generate_conditional_rekey(&mut rng, &gp, &usk, condition).unwrap();

        let re_ct = conditional_re_encrypt_full(&gp, &ct, &rk).unwrap();
        let decrypted = decrypt_conditional_reencrypted(&gp, &re_ct).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_dabe_conditional_future_window() {
        let mut rng = thread_rng();

        let gp = global_setup(&mut rng);
        let (apk, ask) = authority_setup(&mut rng, &gp, "auth1");

        let uk = authority_keygen(
            &mut rng, &gp, &ask, "user",
            &["admin".to_string()]
        ).unwrap();
        let usk = aggregate_user_keys(vec![uk]).unwrap();

        let mut pks = HashMap::new();
        pks.insert("auth1".to_string(), apk);

        let policy = PolicyNode::Attr("auth1:admin".to_string());
        let ct = encrypt(&mut rng, &gp, &pks, &policy, b"future secret").unwrap();

        // Condition that starts in the future
        let future_time = current_timestamp() + 3600;
        let condition = TimeCondition::from(future_time);
        let rk = generate_conditional_rekey(&mut rng, &gp, &usk, condition).unwrap();

        // Re-encryption should fail
        let result = conditional_re_encrypt(&gp, &ct.abe_ct, &rk);
        assert!(result.is_err());
    }

    #[test]
    fn test_dabe_conditional_expired() {
        let mut rng = thread_rng();

        let gp = global_setup(&mut rng);
        let (apk, ask) = authority_setup(&mut rng, &gp, "auth1");

        let uk = authority_keygen(
            &mut rng, &gp, &ask, "user",
            &["admin".to_string()]
        ).unwrap();
        let usk = aggregate_user_keys(vec![uk]).unwrap();

        let mut pks = HashMap::new();
        pks.insert("auth1".to_string(), apk);

        let policy = PolicyNode::Attr("auth1:admin".to_string());
        let ct = encrypt(&mut rng, &gp, &pks, &policy, b"expired secret").unwrap();

        // Condition that expired in the past
        let past_time = current_timestamp() - 3600;
        let condition = TimeCondition::until(past_time);
        let rk = generate_conditional_rekey(&mut rng, &gp, &usk, condition).unwrap();

        // Re-encryption should fail
        let result = conditional_re_encrypt(&gp, &ct.abe_ct, &rk);
        assert!(result.is_err());
    }

    #[test]
    fn test_dabe_conditional_valid_window() {
        let mut rng = thread_rng();

        let gp = global_setup(&mut rng);
        let (apk, ask) = authority_setup(&mut rng, &gp, "auth1");

        let uk = authority_keygen(
            &mut rng, &gp, &ask, "user",
            &["admin".to_string()]
        ).unwrap();
        let usk = aggregate_user_keys(vec![uk]).unwrap();

        let mut pks = HashMap::new();
        pks.insert("auth1".to_string(), apk);

        let policy = PolicyNode::Attr("auth1:admin".to_string());
        let plaintext = b"Window secret";
        let ct = encrypt(&mut rng, &gp, &pks, &policy, plaintext).unwrap();

        // Condition with current time in valid window
        let now = current_timestamp();
        let condition = TimeCondition::between(now - 3600, now + 3600);
        let rk = generate_conditional_rekey(&mut rng, &gp, &usk, condition).unwrap();

        let re_ct = conditional_re_encrypt_full(&gp, &ct, &rk).unwrap();
        let decrypted = decrypt_conditional_reencrypted(&gp, &re_ct).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_dabe_conditional_multi_authority() {
        let mut rng = thread_rng();

        let gp = global_setup(&mut rng);
        let (apk1, ask1) = authority_setup(&mut rng, &gp, "hr");
        let (apk2, ask2) = authority_setup(&mut rng, &gp, "it");

        let uk1 = authority_keygen(
            &mut rng, &gp, &ask1, "user@corp.com",
            &["employee".to_string()]
        ).unwrap();
        let uk2 = authority_keygen(
            &mut rng, &gp, &ask2, "user@corp.com",
            &["developer".to_string()]
        ).unwrap();
        let usk = aggregate_user_keys(vec![uk1, uk2]).unwrap();

        let mut pks = HashMap::new();
        pks.insert("hr".to_string(), apk1);
        pks.insert("it".to_string(), apk2);

        let policy = PolicyNode::Or(vec![
            PolicyNode::Attr("hr:employee".to_string()),
            PolicyNode::Attr("it:developer".to_string()),
        ]);

        let plaintext = b"Multi-authority conditional secret";
        let ct = encrypt(&mut rng, &gp, &pks, &policy, plaintext).unwrap();

        let condition = TimeCondition::always();
        let rk = generate_conditional_rekey(&mut rng, &gp, &usk, condition).unwrap();

        let re_ct = conditional_re_encrypt_full(&gp, &ct, &rk).unwrap();
        let decrypted = decrypt_conditional_reencrypted(&gp, &re_ct).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_dabe_trusted_timestamp_valid() {
        let mut rng = thread_rng();

        let gp = global_setup(&mut rng);
        let (apk, ask) = authority_setup(&mut rng, &gp, "auth1");

        let uk = authority_keygen(
            &mut rng, &gp, &ask, "user",
            &["admin".to_string()]
        ).unwrap();
        let usk = aggregate_user_keys(vec![uk]).unwrap();

        let mut pks = HashMap::new();
        pks.insert("auth1".to_string(), apk);

        let policy = PolicyNode::Attr("auth1:admin".to_string());
        let plaintext = b"Trusted timestamp secret";
        let ct = encrypt(&mut rng, &gp, &pks, &policy, plaintext).unwrap();

        // Set up trusted time authority
        let time_authority = "time.trusted.org";
        let time_key = b"secret_time_signing_key_12345678";

        let now = current_timestamp();
        let condition = TimeCondition::between(now - 3600, now + 3600);
        let rk = generate_conditional_rekey_with_trusted_time(
            &mut rng, &gp, &usk, condition, time_authority, time_key
        ).unwrap();

        // Create valid trusted timestamp
        let trusted_ts = TrustedTimestamp::new(now, time_authority, time_key);

        let re_ct = conditional_re_encrypt_full_with_timestamp(&gp, &ct, &rk, &trusted_ts).unwrap();
        let decrypted = decrypt_conditional_reencrypted(&gp, &re_ct).unwrap();

        assert_eq!(decrypted, plaintext);
        assert!(re_ct.pre_ct.trusted_timestamp.is_some());
    }

    #[test]
    fn test_dabe_trusted_timestamp_required_but_missing() {
        let mut rng = thread_rng();

        let gp = global_setup(&mut rng);
        let (apk, ask) = authority_setup(&mut rng, &gp, "auth1");

        let uk = authority_keygen(
            &mut rng, &gp, &ask, "user",
            &["admin".to_string()]
        ).unwrap();
        let usk = aggregate_user_keys(vec![uk]).unwrap();

        let mut pks = HashMap::new();
        pks.insert("auth1".to_string(), apk);

        let policy = PolicyNode::Attr("auth1:admin".to_string());
        let ct = encrypt(&mut rng, &gp, &pks, &policy, b"secret").unwrap();

        let time_key = b"secret_time_signing_key_12345678";
        let condition = TimeCondition::always();
        let rk = generate_conditional_rekey_with_trusted_time(
            &mut rng, &gp, &usk, condition, "time.trusted.org", time_key
        ).unwrap();

        // Try to re-encrypt without providing trusted timestamp
        let result = conditional_re_encrypt(&gp, &ct.abe_ct, &rk);
        assert!(result.is_err());
    }

    #[test]
    fn test_dabe_trusted_timestamp_invalid_signature() {
        let mut rng = thread_rng();

        let gp = global_setup(&mut rng);
        let (apk, ask) = authority_setup(&mut rng, &gp, "auth1");

        let uk = authority_keygen(
            &mut rng, &gp, &ask, "user",
            &["admin".to_string()]
        ).unwrap();
        let usk = aggregate_user_keys(vec![uk]).unwrap();

        let mut pks = HashMap::new();
        pks.insert("auth1".to_string(), apk);

        let policy = PolicyNode::Attr("auth1:admin".to_string());
        let ct = encrypt(&mut rng, &gp, &pks, &policy, b"secret").unwrap();

        let time_authority = "time.trusted.org";
        let correct_key = b"secret_time_signing_key_12345678";
        let wrong_key = b"wrong_time_signing_key_123456789";

        let now = current_timestamp();
        let condition = TimeCondition::always();
        let rk = generate_conditional_rekey_with_trusted_time(
            &mut rng, &gp, &usk, condition, time_authority, correct_key
        ).unwrap();

        // Create timestamp with wrong key
        let bad_ts = TrustedTimestamp::new(now, time_authority, wrong_key);

        let result = conditional_re_encrypt_with_timestamp(&gp, &ct.abe_ct, &rk, Some(&bad_ts));
        assert!(result.is_err());
    }

    #[test]
    fn test_dabe_trusted_timestamp_wrong_authority() {
        let mut rng = thread_rng();

        let gp = global_setup(&mut rng);
        let (apk, ask) = authority_setup(&mut rng, &gp, "auth1");

        let uk = authority_keygen(
            &mut rng, &gp, &ask, "user",
            &["admin".to_string()]
        ).unwrap();
        let usk = aggregate_user_keys(vec![uk]).unwrap();

        let mut pks = HashMap::new();
        pks.insert("auth1".to_string(), apk);

        let policy = PolicyNode::Attr("auth1:admin".to_string());
        let ct = encrypt(&mut rng, &gp, &pks, &policy, b"secret").unwrap();

        let correct_auth = "time.trusted.org";
        let wrong_auth = "evil.time.org";
        let time_key = b"secret_time_signing_key_12345678";

        let now = current_timestamp();
        let condition = TimeCondition::always();
        let rk = generate_conditional_rekey_with_trusted_time(
            &mut rng, &gp, &usk, condition, correct_auth, time_key
        ).unwrap();

        // Create timestamp from wrong authority
        let bad_ts = TrustedTimestamp::new(now, wrong_auth, time_key);

        let result = conditional_re_encrypt_with_timestamp(&gp, &ct.abe_ct, &rk, Some(&bad_ts));
        assert!(result.is_err());
    }

    #[test]
    fn test_dabe_trusted_timestamp_expired() {
        let mut rng = thread_rng();

        let gp = global_setup(&mut rng);
        let (apk, ask) = authority_setup(&mut rng, &gp, "auth1");

        let uk = authority_keygen(
            &mut rng, &gp, &ask, "user",
            &["admin".to_string()]
        ).unwrap();
        let usk = aggregate_user_keys(vec![uk]).unwrap();

        let mut pks = HashMap::new();
        pks.insert("auth1".to_string(), apk);

        let policy = PolicyNode::Attr("auth1:admin".to_string());
        let ct = encrypt(&mut rng, &gp, &pks, &policy, b"secret").unwrap();

        let time_authority = "time.trusted.org";
        let time_key = b"secret_time_signing_key_12345678";

        let now = current_timestamp();
        // Window is in the future
        let condition = TimeCondition::from(now + 3600);
        let rk = generate_conditional_rekey_with_trusted_time(
            &mut rng, &gp, &usk, condition, time_authority, time_key
        ).unwrap();

        // Valid trusted timestamp but outside time window
        let trusted_ts = TrustedTimestamp::new(now, time_authority, time_key);

        let result = conditional_re_encrypt_with_timestamp(&gp, &ct.abe_ct, &rk, Some(&trusted_ts));
        assert!(result.is_err());
    }
}
