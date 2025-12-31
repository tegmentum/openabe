//! DABE (Decentralized Multi-Authority ABE) User-to-User Proxy Re-Encryption
//!
//! This module implements unidirectional, single-hop proxy re-encryption
//! for the DABE scheme, allowing Alice to delegate decryption rights to
//! Bob in a multi-authority setting.
//!
//! ## Multi-Authority Considerations
//!
//! In DABE, user keys come from multiple independent authorities. The U2U PRE
//! scheme handles this by:
//! - Generating per-authority blinding factors
//! - El-Gamal encrypting the combined delta for Bob
//! - Allowing the proxy to transform per-authority contributions
//!
//! ## Security Properties
//!
//! Same as Waters U2U PRE:
//! - Proxy invisibility: cannot recover plaintext
//! - Recipient specificity: only Bob can decrypt
//! - Non-transferability: Bob cannot re-delegate

use crate::error::AbeError;
use crate::schemes::dabe::{
    GlobalParams, UserSecretKey,
    Ciphertext, CiphertextComponent, FullCiphertext,
    find_satisfying_assignment,
};
use crate::schemes::waters::parse_policy;
use crate::schemes::waters_u2u_pre::{TargetPublicKey, TargetSecret, DelegationKeyPair};
use crate::utils::aes;
use rabe_bls12381::{Fr, G1, G2, Gt, pairing};
use rand::{RngCore, CryptoRng};
use std::collections::{HashMap, HashSet};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Generate a delegation key pair for Bob using DABE global parameters
///
/// This version uses h from the global parameters as the generator.
pub fn generate_delegation_keypair<R: RngCore + CryptoRng>(rng: &mut R, gp: &GlobalParams) -> DelegationKeyPair {
    let sk = Fr::random(rng);
    let pk = gp.h * sk;
    DelegationKeyPair { pk, sk }
}

/// Per-authority re-encryption component for U2U
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct U2UAuthorityReKeyComponent {
    /// Authority ID
    pub aid: String,
    /// Blinded K component: K_old - h^(delta_aid)
    pub rk_k: G2,
    /// L component: h^t (unchanged)
    pub rk_l: G2,
    /// Per-attribute components: H(attr)^t
    pub rk_x: HashMap<String, G1>,
    /// El-Gamal encrypted delta: h^delta_aid + pk_bob^r (encrypted for Bob)
    pub w_aid: G2,
}

/// DABE user-to-user re-encryption key
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct DabeU2UReEncryptionKey {
    /// Per-authority re-encryption components
    pub authority_components: HashMap<String, U2UAuthorityReKeyComponent>,
    /// El-Gamal component 1: h^r
    pub u: G2,
    /// El-Gamal component 2: h^(sum of deltas) * target_pk^r
    pub w: G2,
}

/// DABE user-to-user re-encrypted ciphertext (KEM mode)
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct DabeU2UReEncryptedCiphertext {
    /// Original policy string
    pub policy: String,
    /// C = g^s (unchanged)
    pub c: G1,
    /// Per-authority blinded contributions
    pub authority_blindings: HashMap<String, Gt>,
    /// El-Gamal component 1: h^r (shared across all authorities)
    pub u: G2,
    /// Per-authority El-Gamal component 2: aid -> h^delta_aid + pk_bob^r
    /// Only Bob can recover h^delta_aid from each entry
    pub w_per_authority: HashMap<String, G2>,
}

/// Full DABE user-to-user re-encrypted ciphertext with payload
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct FullDabeU2UReEncryptedCiphertext {
    /// ABE re-encrypted ciphertext
    pub pre_ct: DabeU2UReEncryptedCiphertext,
    /// Symmetrically encrypted payload
    pub sym_ct: Vec<u8>,
}

/// Generate a user-to-user re-encryption key for DABE
///
/// Alice generates this using her DABE user secret key and Bob's public key.
///
/// # Arguments
///
/// * `rng` - Random number generator
/// * `gp` - Global parameters
/// * `usk_alice` - Alice's DABE user secret key
/// * `target_pk` - Bob's public key
///
/// # Returns
///
/// Re-encryption key for the proxy
pub fn generate_u2u_rekey<R: RngCore + CryptoRng>(
    rng: &mut R,
    gp: &GlobalParams,
    usk_alice: &UserSecretKey,
    target_pk: &TargetPublicKey,
) -> Result<DabeU2UReEncryptionKey, AbeError> {
    // El-Gamal: use a single randomness r for all per-authority encryptions
    let r = Fr::random(rng);
    let u = gp.h * r;

    let bob_pk = match target_pk {
        TargetPublicKey::Simple(pk) => *pk,
        TargetPublicKey::AbeKey(l) => *l,
    };
    let bob_pk_r = bob_pk * r;

    let mut authority_components = HashMap::new();
    let mut delta_sum = Fr::zero();

    // Generate per-authority blinded components with El-Gamal encrypted deltas
    for (aid, uk) in &usk_alice.components {
        let delta_aid = Fr::random(rng);
        delta_sum = delta_sum + delta_aid;

        let h_delta_aid = gp.h * delta_aid;
        let rk_k = uk.k - h_delta_aid;

        let mut rk_x = HashMap::new();
        for (attr, kx) in &uk.kx {
            rk_x.insert(attr.clone(), *kx);
        }

        // El-Gamal encrypt this authority's delta: w_aid = h^delta_aid + pk_bob^r
        // Only Bob can recover h^delta_aid = w_aid - pk_bob^r = w_aid - u^sk_bob
        let w_aid = h_delta_aid + bob_pk_r;

        authority_components.insert(aid.clone(), U2UAuthorityReKeyComponent {
            aid: aid.clone(),
            rk_k,
            rk_l: uk.l,
            rk_x,
            w_aid,
        });
    }

    // Also compute combined delta for potential future use
    let h_delta_sum = gp.h * delta_sum;
    let w = h_delta_sum + bob_pk_r;

    Ok(DabeU2UReEncryptionKey {
        authority_components,
        u,
        w,
    })
}

/// Re-encrypt a DABE ciphertext for the target user (Proxy operation)
pub fn u2u_re_encrypt(
    _gp: &GlobalParams,
    ct: &Ciphertext,
    rk: &DabeU2UReEncryptionKey,
) -> Result<DabeU2UReEncryptedCiphertext, AbeError> {
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
    let mut w_per_authority = HashMap::new();

    for (aid, items) in &by_authority {
        let auth_rk = rk.authority_components.get(aid)
            .ok_or_else(|| AbeError::DecryptError(
                format!("No re-encryption key for authority {}", aid)
            ))?;

        // Compute partial decryption for this authority
        let mut prod1 = G1::zero();
        let mut prod_t = Gt::one();

        for (ct_comp, coeff) in items {
            let rk_x_attr = auth_rk.rk_x.get(&ct_comp.attr)
                .ok_or_else(|| AbeError::DecryptError(
                    format!("Missing re-key for attr {}", ct_comp.attr)
                ))?;

            prod1 = prod1 + (ct_comp.c1 * *coeff);
            let kx_scaled = *rk_x_attr * *coeff;
            prod_t = prod_t * pairing(kx_scaled, ct_comp.d);
        }

        let pairing1 = pairing(ct.c, auth_rk.rk_k);
        let pairing2 = pairing(prod1, auth_rk.rk_l);
        let denominator = prod_t * pairing2;
        let blinding = pairing1 * denominator.inverse();

        authority_blindings.insert(aid.clone(), blinding);
        // Store the El-Gamal encrypted delta (only Bob can decrypt)
        w_per_authority.insert(aid.clone(), auth_rk.w_aid);
    }

    Ok(DabeU2UReEncryptedCiphertext {
        policy: ct.policy.clone(),
        c: ct.c,
        authority_blindings,
        u: rk.u,
        w_per_authority,
    })
}

/// Re-encrypt a full DABE ciphertext (with payload)
pub fn u2u_re_encrypt_full(
    gp: &GlobalParams,
    ct: &FullCiphertext,
    rk: &DabeU2UReEncryptionKey,
) -> Result<FullDabeU2UReEncryptedCiphertext, AbeError> {
    let pre_ct = u2u_re_encrypt(gp, &ct.abe_ct, rk)?;
    Ok(FullDabeU2UReEncryptedCiphertext {
        pre_ct,
        sym_ct: ct.sym_ct.clone(),
    })
}

/// Decrypt a DABE user-to-user re-encrypted ciphertext (KEM mode)
pub fn u2u_decrypt_reencrypted_kem(
    _gp: &GlobalParams,
    re_ct: &DabeU2UReEncryptedCiphertext,
    target_secret: &TargetSecret,
) -> Result<[u8; 32], AbeError> {
    // Extract the secret scalar
    let secret = match target_secret {
        TargetSecret::Simple(sk) => *sk,
        TargetSecret::AbeKey(t) => *t,
    };

    // Compute pk_bob^r = u^sk_bob (used to decrypt each per-authority delta)
    let u_secret = re_ct.u * secret;

    // Unblind each authority's contribution
    let mut recovered = Gt::one();

    for (aid, blinding) in &re_ct.authority_blindings {
        // Recover h^delta_aid from El-Gamal:
        // w_aid = h^delta_aid + pk_bob^r
        // h^delta_aid = w_aid - u^sk_bob
        let w_aid = re_ct.w_per_authority.get(aid)
            .ok_or_else(|| AbeError::DecryptError(
                format!("Missing encrypted delta for authority {}", aid)
            ))?;
        let h_delta_aid = *w_aid - u_secret;

        // Unblind: blinding * e(c, h^delta_aid)
        let delta_contribution = pairing(re_ct.c, h_delta_aid);
        let unblinded = *blinding * delta_contribution;
        recovered = recovered * unblinded;
    }

    let sym_key = derive_key(&recovered);
    Ok(sym_key)
}

/// Decrypt a full DABE user-to-user re-encrypted ciphertext
pub fn u2u_decrypt_reencrypted(
    gp: &GlobalParams,
    full_re_ct: &FullDabeU2UReEncryptedCiphertext,
    target_secret: &TargetSecret,
) -> Result<Vec<u8>, AbeError> {
    let sym_key = u2u_decrypt_reencrypted_kem(gp, &full_re_ct.pre_ct, target_secret)?;
    aes::decrypt(&sym_key, &full_re_ct.sym_ct)
        .map_err(|e| AbeError::DecryptError(e))
}

/// Derive symmetric key from Gt element
fn derive_key(gt: &Gt) -> [u8; 32] {
    use sha2::{Sha256, Digest};
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
        global_setup, authority_setup, authority_keygen, aggregate_user_keys, encrypt,
    };
    use crate::lsss::PolicyNode;
    use rand::thread_rng;

    #[test]
    fn test_dabe_u2u_single_authority() {
        let mut rng = thread_rng();

        // Setup
        let gp = global_setup(&mut rng);
        let (apk, ask) = authority_setup(&mut rng, &gp, "auth");

        // Alice has attributes
        let alice_uk = authority_keygen(
            &mut rng, &gp, &ask, "alice",
            &["admin".to_string()]
        ).unwrap();
        let alice_usk = aggregate_user_keys(vec![alice_uk]).unwrap();

        // Bob generates delegation key pair
        let bob_keys = generate_delegation_keypair(&mut rng, &gp);

        // Encrypt
        let mut pks = HashMap::new();
        pks.insert("auth".to_string(), apk);

        let policy = PolicyNode::Attr("auth:admin".to_string());
        let plaintext = b"secret for dabe bob";
        let ct = encrypt(&mut rng, &gp, &pks, &policy, plaintext).unwrap();

        // Alice generates re-key for Bob
        let target_pk = TargetPublicKey::Simple(bob_keys.pk);
        let rk = generate_u2u_rekey(&mut rng, &gp, &alice_usk, &target_pk).unwrap();

        // Proxy re-encrypts
        let re_ct = u2u_re_encrypt_full(&gp, &ct, &rk).unwrap();

        // Bob decrypts
        let target_secret = TargetSecret::Simple(bob_keys.sk);
        let decrypted = u2u_decrypt_reencrypted(&gp, &re_ct, &target_secret).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_dabe_u2u_multi_authority_or() {
        let mut rng = thread_rng();

        // Setup with two authorities
        let gp = global_setup(&mut rng);
        let (apk1, ask1) = authority_setup(&mut rng, &gp, "auth1");
        let (apk2, ask2) = authority_setup(&mut rng, &gp, "auth2");

        // Alice has attributes from both authorities
        let alice_uk1 = authority_keygen(&mut rng, &gp, &ask1, "alice", &["admin".to_string()]).unwrap();
        let alice_uk2 = authority_keygen(&mut rng, &gp, &ask2, "alice", &["manager".to_string()]).unwrap();
        let alice_usk = aggregate_user_keys(vec![alice_uk1, alice_uk2]).unwrap();

        let bob_keys = generate_delegation_keypair(&mut rng, &gp);

        // OR policy across authorities
        let mut pks = HashMap::new();
        pks.insert("auth1".to_string(), apk1);
        pks.insert("auth2".to_string(), apk2);

        let policy = PolicyNode::Or(vec![
            PolicyNode::Attr("auth1:admin".to_string()),
            PolicyNode::Attr("auth2:manager".to_string()),
        ]);
        let ct = encrypt(&mut rng, &gp, &pks, &policy, b"multi-auth secret").unwrap();

        let target_pk = TargetPublicKey::Simple(bob_keys.pk);
        let rk = generate_u2u_rekey(&mut rng, &gp, &alice_usk, &target_pk).unwrap();
        let re_ct = u2u_re_encrypt_full(&gp, &ct, &rk).unwrap();

        let target_secret = TargetSecret::Simple(bob_keys.sk);
        let decrypted = u2u_decrypt_reencrypted(&gp, &re_ct, &target_secret).unwrap();

        assert_eq!(decrypted, b"multi-auth secret");
    }

    #[test]
    fn test_dabe_u2u_cross_authority_and() {
        let mut rng = thread_rng();

        let gp = global_setup(&mut rng);
        let (apk1, ask1) = authority_setup(&mut rng, &gp, "auth1");
        let (apk2, ask2) = authority_setup(&mut rng, &gp, "auth2");

        // Alice has both attributes
        let alice_uk1 = authority_keygen(&mut rng, &gp, &ask1, "alice", &["attr1".to_string()]).unwrap();
        let alice_uk2 = authority_keygen(&mut rng, &gp, &ask2, "alice", &["attr2".to_string()]).unwrap();
        let alice_usk = aggregate_user_keys(vec![alice_uk1, alice_uk2]).unwrap();

        let bob_keys = generate_delegation_keypair(&mut rng, &gp);

        // AND policy across authorities
        let mut pks = HashMap::new();
        pks.insert("auth1".to_string(), apk1);
        pks.insert("auth2".to_string(), apk2);

        let policy = PolicyNode::And(vec![
            PolicyNode::Attr("auth1:attr1".to_string()),
            PolicyNode::Attr("auth2:attr2".to_string()),
        ]);
        let ct = encrypt(&mut rng, &gp, &pks, &policy, b"cross-auth and").unwrap();

        let target_pk = TargetPublicKey::Simple(bob_keys.pk);
        let rk = generate_u2u_rekey(&mut rng, &gp, &alice_usk, &target_pk).unwrap();
        let re_ct = u2u_re_encrypt_full(&gp, &ct, &rk).unwrap();

        let target_secret = TargetSecret::Simple(bob_keys.sk);
        let decrypted = u2u_decrypt_reencrypted(&gp, &re_ct, &target_secret).unwrap();

        assert_eq!(decrypted, b"cross-auth and");
    }

    #[test]
    fn test_dabe_u2u_wrong_key_fails() {
        let mut rng = thread_rng();

        let gp = global_setup(&mut rng);
        let (apk, ask) = authority_setup(&mut rng, &gp, "auth");

        let alice_uk = authority_keygen(&mut rng, &gp, &ask, "alice", &["attr".to_string()]).unwrap();
        let alice_usk = aggregate_user_keys(vec![alice_uk]).unwrap();

        let bob_keys = generate_delegation_keypair(&mut rng, &gp);
        let carol_keys = generate_delegation_keypair(&mut rng, &gp);

        let mut pks = HashMap::new();
        pks.insert("auth".to_string(), apk);

        let policy = PolicyNode::Attr("auth:attr".to_string());
        let ct = encrypt(&mut rng, &gp, &pks, &policy, b"for bob only").unwrap();

        // Re-key for Bob
        let target_pk = TargetPublicKey::Simple(bob_keys.pk);
        let rk = generate_u2u_rekey(&mut rng, &gp, &alice_usk, &target_pk).unwrap();
        let re_ct = u2u_re_encrypt_full(&gp, &ct, &rk).unwrap();

        // Carol tries to decrypt - should fail with authentication error
        let carol_secret = TargetSecret::Simple(carol_keys.sk);
        let result = u2u_decrypt_reencrypted(&gp, &re_ct, &carol_secret);

        assert!(result.is_err(), "Carol should not be able to decrypt Bob's ciphertext");
    }
}
