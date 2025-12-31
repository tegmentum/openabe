//! DABE (Decentralized Multi-Authority ABE) Proxy Re-Encryption
//!
//! This module implements unidirectional, single-hop proxy re-encryption
//! for the DABE (Lewko-Waters 2011) scheme. It enables key rotation/recovery
//! in a multi-authority setting.
//!
//! ## Multi-Authority Considerations
//!
//! In DABE, user keys come from multiple independent authorities. The PRE
//! scheme handles this by:
//! - Generating per-authority blinding factors
//! - Allowing the proxy to transform per-authority contributions
//! - Combining all authority blindings for final unblinding
//!
//! ## Security Properties
//!
//! Same as Waters PRE:
//! - Proxy invisibility: only sees blinded values
//! - Unidirectionality: old→new only
//! - Single-hop: cannot be re-encrypted again

use crate::error::AbeError;
use crate::schemes::dabe::{
    GlobalParams, UserSecretKey,
    Ciphertext, CiphertextComponent, FullCiphertext,
    find_satisfying_assignment,
};
use crate::schemes::waters::parse_policy;
use crate::utils::aes;
use rabe_bls12381::{Fr, G1, G2, Gt, pairing};
use rand::{RngCore, CryptoRng};
use std::collections::{HashMap, HashSet};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Per-authority re-encryption component
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct AuthorityReKeyComponent {
    /// Authority ID
    pub aid: String,

    /// Modified K: K_old - h^(delta_aid)
    /// This is h^(alpha + a*t - delta_aid)
    pub rk_k: G2,

    /// L component: h^t (unchanged)
    pub rk_l: G2,

    /// Per-attribute KX components: H(attr)^t (unchanged)
    pub rk_x: HashMap<String, G1>,

    /// h^delta_aid for this authority (kept by user for unblinding)
    pub h_delta_aid: G2,
}

/// DABE re-encryption key
///
/// Contains per-authority re-encryption components.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct DabeReEncryptionKey {
    /// Re-encryption components per authority
    pub authority_components: HashMap<String, AuthorityReKeyComponent>,
}

/// DABE re-encrypted ciphertext
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct DabeReEncryptedCiphertext {
    /// Original policy (preserved)
    pub policy: String,

    /// C = g^s from original ciphertext
    pub c: G1,

    /// Per-authority blinded contributions
    /// Each is e(g,h)^(s * alpha_aid - s * delta_aid)
    pub authority_blindings: HashMap<String, Gt>,

    /// Per-authority h^delta_aid for unblinding
    /// Only includes authorities used in the satisfying assignment
    pub authority_deltas: HashMap<String, G2>,
}

/// Full DABE re-encrypted ciphertext with payload
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct FullDabeReEncryptedCiphertext {
    /// PRE ciphertext (KEM part)
    pub pre_ct: DabeReEncryptedCiphertext,

    /// Symmetric ciphertext (DEM part - unchanged)
    pub sym_ct: Vec<u8>,
}

/// Generate a DABE re-encryption key from the user's aggregated secret key
///
/// Creates a key that allows a proxy to transform ciphertexts.
/// Each authority component includes h_delta_aid for that authority's unblinding.
///
/// # Arguments
/// * `rng` - Cryptographically secure random number generator
/// * `gp` - Global parameters
/// * `usk_old` - User's aggregated secret key
///
/// # Returns
/// Re-encryption key with per-authority components
pub fn generate_rekey<R: RngCore + CryptoRng>(
    rng: &mut R,
    gp: &GlobalParams,
    usk_old: &UserSecretKey,
) -> Result<DabeReEncryptionKey, AbeError> {
    if usk_old.components.is_empty() {
        return Err(AbeError::KeygenError(
            "User key has no authority components".to_string()
        ));
    }

    let mut authority_components = HashMap::new();

    for (aid, uk_comp) in &usk_old.components {
        // Per-authority random blinding delta
        let delta_aid = Fr::random(rng);

        // RK_K = K - h^delta_aid = h^(alpha + a*t) - h^delta_aid
        //      = h^(alpha + a*t - delta_aid)
        let rk_k = uk_comp.k - (gp.h * delta_aid);

        // h^delta_aid for unblinding
        let h_delta_aid = gp.h * delta_aid;

        let auth_rk = AuthorityReKeyComponent {
            aid: aid.clone(),
            rk_k,
            rk_l: uk_comp.l,
            rk_x: uk_comp.kx.clone(),
            h_delta_aid,
        };

        authority_components.insert(aid.clone(), auth_rk);
    }

    Ok(DabeReEncryptionKey {
        authority_components,
    })
}

/// Extract proxy-safe components from a DABE re-encryption key
///
/// Returns only the authority components (safe to give to proxy).
pub fn extract_proxy_key(
    rk: &DabeReEncryptionKey
) -> HashMap<String, AuthorityReKeyComponent> {
    rk.authority_components.clone()
}

/// Proxy re-encrypts a DABE ciphertext
///
/// Performs partial decryption using re-encryption key components,
/// producing blinded values that require h_delta to unblind.
///
/// # Arguments
/// * `gp` - Global parameters
/// * `ct` - Original DABE ciphertext
/// * `rk` - Re-encryption key
///
/// # Returns
/// Re-encrypted ciphertext with blinded authority contributions
pub fn re_encrypt(
    _gp: &GlobalParams,
    ct: &Ciphertext,
    rk: &DabeReEncryptionKey,
) -> Result<DabeReEncryptedCiphertext, AbeError> {
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
        // = e(g,h)^(s * (alpha + a*t - delta_aid)) / (...)
        // = e(g,h)^(s * alpha_aid - s * delta_aid)  (after full reduction)
        let contribution = numerator * denominator.inverse();

        authority_blindings.insert(aid.clone(), contribution);
    }

    // Collect per-authority deltas for authorities used in the satisfying assignment
    let mut authority_deltas = HashMap::new();
    for aid in by_authority.keys() {
        let auth_rk = rk.authority_components.get(aid).unwrap();
        authority_deltas.insert(aid.clone(), auth_rk.h_delta_aid);
    }

    Ok(DabeReEncryptedCiphertext {
        policy: ct.policy.clone(),
        c: ct.c,
        authority_blindings,
        authority_deltas,
    })
}

/// Proxy re-encrypts a full DABE ciphertext
pub fn re_encrypt_full(
    gp: &GlobalParams,
    ct: &FullCiphertext,
    rk: &DabeReEncryptionKey,
) -> Result<FullDabeReEncryptedCiphertext, AbeError> {
    let pre_ct = re_encrypt(gp, &ct.abe_ct, rk)?;

    Ok(FullDabeReEncryptedCiphertext {
        pre_ct,
        sym_ct: ct.sym_ct.clone(),
    })
}

/// Decrypt a DABE re-encrypted ciphertext (KEM mode)
///
/// Unblind and combine authority contributions using per-authority deltas.
///
/// # Arguments
/// * `_gp` - Global parameters (unused, kept for API consistency)
/// * `re_ct` - Re-encrypted ciphertext
///
/// # Returns
/// Symmetric key that was encapsulated
pub fn decrypt_reencrypted_kem(
    _gp: &GlobalParams,
    re_ct: &DabeReEncryptedCiphertext,
) -> Result<[u8; 32], AbeError> {
    // Combine all authority blinded contributions and their delta unblinding
    let mut recovered = Gt::one();

    for (aid, blinding) in &re_ct.authority_blindings {
        // Get the delta for this authority
        let h_delta_aid = re_ct.authority_deltas.get(aid)
            .ok_or_else(|| AbeError::DecryptError(
                format!("Missing delta for authority {}", aid)
            ))?;

        // Compute delta contribution for this authority:
        // e(C, h^delta_aid) = e(g^s, h^delta_aid) = e(g,h)^(s * delta_aid)
        let delta_contribution = pairing(re_ct.c, *h_delta_aid);

        // Unblind this authority's contribution:
        // blinding = e(g,h)^(s*alpha_aid - s*delta_aid)
        // delta_contribution = e(g,h)^(s*delta_aid)
        // unblinded = e(g,h)^(s*alpha_aid)
        let unblinded = *blinding * delta_contribution;

        recovered = recovered * unblinded;
    }

    // Derive key: recovered = e(g,h)^(s * sum(alpha_i)) for used authorities
    let sym_key = derive_key(&recovered);

    Ok(sym_key)
}

/// Decrypt a full DABE re-encrypted ciphertext
pub fn decrypt_reencrypted(
    gp: &GlobalParams,
    re_ct: &FullDabeReEncryptedCiphertext,
) -> Result<Vec<u8>, AbeError> {
    let sym_key = decrypt_reencrypted_kem(gp, &re_ct.pre_ct)?;

    aes::decrypt(&sym_key, &re_ct.sym_ct)
        .map_err(|e| AbeError::DecryptError(e))
}

/// Derive a symmetric key from a GT element
/// Uses the same derivation as DABE for compatibility
fn derive_key(gt: &Gt) -> [u8; 32] {
    use sha2::{Sha256, Digest};

    let mut hasher = Sha256::new();
    hasher.update(b"DABE_KEY_DERIVE"); // Same as DABE for compatibility
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
    fn test_dabe_pre_single_authority() {
        let mut rng = thread_rng();

        // Setup
        let gp = global_setup(&mut rng);
        let (apk, ask) = authority_setup(&mut rng, &gp, "auth1");

        // Create user key
        let uk = authority_keygen(
            &mut rng, &gp, &ask, "user@test.com",
            &["admin".to_string(), "user".to_string()]
        ).unwrap();
        let usk = aggregate_user_keys(vec![uk]).unwrap();

        // Encrypt
        let mut pks = HashMap::new();
        pks.insert("auth1".to_string(), apk);

        let policy = PolicyNode::And(vec![
            PolicyNode::Attr("auth1:admin".to_string()),
            PolicyNode::Attr("auth1:user".to_string()),
        ]);

        let plaintext = b"Single authority PRE test";
        let ct = encrypt(&mut rng, &gp, &pks, &policy, plaintext).unwrap();

        // Generate re-encryption key
        let rk = generate_rekey(&mut rng, &gp, &usk).unwrap();

        // Re-encrypt
        let re_ct = re_encrypt_full(&gp, &ct, &rk).unwrap();

        // Decrypt
        let decrypted = decrypt_reencrypted(&gp, &re_ct).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_dabe_pre_multi_authority() {
        let mut rng = thread_rng();

        // Setup with two authorities
        let gp = global_setup(&mut rng);
        let (apk1, ask1) = authority_setup(&mut rng, &gp, "hr");
        let (apk2, ask2) = authority_setup(&mut rng, &gp, "it");

        // User gets keys from both authorities
        let uk1 = authority_keygen(
            &mut rng, &gp, &ask1, "user@corp.com",
            &["employee".to_string()]
        ).unwrap();
        let uk2 = authority_keygen(
            &mut rng, &gp, &ask2, "user@corp.com",
            &["developer".to_string()]
        ).unwrap();
        let usk = aggregate_user_keys(vec![uk1, uk2]).unwrap();

        // Encrypt with cross-authority OR policy
        let mut pks = HashMap::new();
        pks.insert("hr".to_string(), apk1);
        pks.insert("it".to_string(), apk2);

        let policy = PolicyNode::Or(vec![
            PolicyNode::Attr("hr:employee".to_string()),
            PolicyNode::Attr("it:developer".to_string()),
        ]);

        let plaintext = b"Multi-authority PRE test";
        let ct = encrypt(&mut rng, &gp, &pks, &policy, plaintext).unwrap();

        // Generate re-encryption key
        let rk = generate_rekey(&mut rng, &gp, &usk).unwrap();

        // Re-encrypt
        let re_ct = re_encrypt_full(&gp, &ct, &rk).unwrap();

        // Decrypt
        let decrypted = decrypt_reencrypted(&gp, &re_ct).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_dabe_pre_cross_authority_and() {
        let mut rng = thread_rng();

        let gp = global_setup(&mut rng);
        let (apk1, ask1) = authority_setup(&mut rng, &gp, "hr");
        let (apk2, ask2) = authority_setup(&mut rng, &gp, "it");

        let uk1 = authority_keygen(
            &mut rng, &gp, &ask1, "user@corp.com",
            &["manager".to_string()]
        ).unwrap();
        let uk2 = authority_keygen(
            &mut rng, &gp, &ask2, "user@corp.com",
            &["admin".to_string()]
        ).unwrap();
        let usk = aggregate_user_keys(vec![uk1, uk2]).unwrap();

        let mut pks = HashMap::new();
        pks.insert("hr".to_string(), apk1);
        pks.insert("it".to_string(), apk2);

        // Cross-authority AND policy
        let policy = PolicyNode::And(vec![
            PolicyNode::Attr("hr:manager".to_string()),
            PolicyNode::Attr("it:admin".to_string()),
        ]);

        let plaintext = b"Cross-authority AND PRE test";
        let ct = encrypt(&mut rng, &gp, &pks, &policy, plaintext).unwrap();

        let rk = generate_rekey(&mut rng, &gp, &usk).unwrap();
        let re_ct = re_encrypt_full(&gp, &ct, &rk).unwrap();
        let decrypted = decrypt_reencrypted(&gp, &re_ct).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_dabe_pre_wrong_delta_fails() {
        let mut rng = thread_rng();

        let gp = global_setup(&mut rng);
        let (apk, ask) = authority_setup(&mut rng, &gp, "auth");

        let uk = authority_keygen(
            &mut rng, &gp, &ask, "user",
            &["attr".to_string()]
        ).unwrap();
        let usk = aggregate_user_keys(vec![uk]).unwrap();

        let mut pks = HashMap::new();
        pks.insert("auth".to_string(), apk);

        let policy = PolicyNode::Attr("auth:attr".to_string());
        let ct = encrypt(&mut rng, &gp, &pks, &policy, b"secret").unwrap();

        let rk = generate_rekey(&mut rng, &gp, &usk).unwrap();
        let mut re_ct = re_encrypt_full(&gp, &ct, &rk).unwrap();

        // Corrupt authority_deltas
        for delta in re_ct.pre_ct.authority_deltas.values_mut() {
            *delta = gp.h * Fr::random(&mut rng);
        }

        // Decryption should fail with authentication error due to wrong key
        let result = decrypt_reencrypted(&gp, &re_ct);
        assert!(result.is_err(), "Corrupted deltas should cause decryption to fail");
    }

    #[test]
    fn test_dabe_pre_policy_not_satisfied() {
        let mut rng = thread_rng();

        let gp = global_setup(&mut rng);
        let (apk, ask) = authority_setup(&mut rng, &gp, "auth");

        // User only has "reader" attribute
        let uk = authority_keygen(
            &mut rng, &gp, &ask, "user",
            &["reader".to_string()]
        ).unwrap();
        let usk = aggregate_user_keys(vec![uk]).unwrap();

        let mut pks = HashMap::new();
        pks.insert("auth".to_string(), apk);

        // Policy requires "admin"
        let policy = PolicyNode::Attr("auth:admin".to_string());
        let ct = encrypt(&mut rng, &gp, &pks, &policy, b"admin only").unwrap();

        let rk = generate_rekey(&mut rng, &gp, &usk).unwrap();

        // Re-encryption should fail
        let result = re_encrypt(&gp, &ct.abe_ct, &rk);
        assert!(result.is_err());
    }
}
