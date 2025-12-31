//! DABE Multi-Hop Proxy Re-Encryption
//!
//! This module implements multi-hop PRE for DABE (Decentralized Multi-Authority ABE)
//! where a ciphertext can be re-encrypted multiple times through a chain of proxies:
//!
//! ```text
//! Alice → Bob → Carol → Dave
//! ```
//!
//! ## Multi-Authority Design
//!
//! In DABE, user keys come from multiple independent authorities. The multi-hop PRE
//! scheme handles this by:
//! - The first hop uses DABE ABE keys (multi-authority)
//! - Subsequent hops use simple DH key pairs for delegation
//! - Each hop adds a blinding factor encrypted for the next recipient
//!
//! ## Use Cases
//!
//! 1. **Hierarchical delegation**: Manager → Team Lead → Developer
//! 2. **Forwarding**: Alice shares with Bob, who can forward to Carol
//! 3. **Cascading access**: Data flows through organizational hierarchy
//!
//! ## Security Properties
//!
//! - Each hop is independent (compromise of one doesn't affect others)
//! - Maximum hop count can be enforced
//! - Each intermediate party can decrypt or forward

use crate::error::AbeError;
use crate::schemes::dabe::{
    GlobalParams, UserSecretKey,
    Ciphertext, CiphertextComponent, FullCiphertext,
    find_satisfying_assignment,
};
use crate::schemes::waters::parse_policy;
use crate::schemes::waters_u2u_pre::{DelegationKeyPair, TargetPublicKey, TargetSecret};
use crate::utils::aes;
use rabe_bls12381::{Fr, G1, G2, Gt, pairing};
use rand::{RngCore, CryptoRng};
use sha2::{Sha256, Digest};
use std::collections::{HashMap, HashSet};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Maximum allowed hops (security limit)
pub const MAX_HOPS: usize = 10;

/// A single hop in the re-encryption chain
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct DabeHopInfo {
    /// El-Gamal component 1: h^r
    pub u: G2,
    /// El-Gamal component 2: h^delta * pk_recipient^r
    pub w: G2,
    /// Hop index (0 = first re-encryption)
    pub hop_index: usize,
}

/// Per-authority re-encryption component for multi-hop
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct MultiHopAuthorityReKeyComponent {
    /// Authority ID
    pub aid: String,

    /// Modified K: K - h^delta_aid
    pub rk_k: G2,

    /// L component: h^t (unchanged)
    pub rk_l: G2,

    /// Per-attribute KX components
    pub rk_x: HashMap<String, G1>,

    /// Combined delta for this authority
    pub delta_aid: Fr,
}

/// DABE multi-hop re-encryption key (for first hop)
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct DabeMultiHopReEncryptionKey {
    /// Re-encryption components per authority
    pub authority_components: HashMap<String, MultiHopAuthorityReKeyComponent>,
    /// El-Gamal encrypted combined delta for next recipient
    pub hop: DabeHopInfo,
    /// Maximum hops allowed after this one
    pub max_remaining_hops: usize,
}

/// DABE multi-hop re-encrypted ciphertext
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct DabeMultiHopReEncryptedCiphertext {
    /// Original policy
    pub policy: String,
    /// C = g^s from original ciphertext
    pub c: G1,
    /// Blinded decryption result (accumulated across all hops)
    pub c_blinded: Gt,
    /// Chain of hops (each with El-Gamal encrypted delta)
    pub hops: Vec<DabeHopInfo>,
    /// Current hop count
    pub hop_count: usize,
    /// Maximum allowed hops
    pub max_hops: usize,
}

/// Full DABE multi-hop re-encrypted ciphertext
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct FullDabeMultiHopReEncryptedCiphertext {
    /// ABE re-encrypted ciphertext
    pub pre_ct: DabeMultiHopReEncryptedCiphertext,
    /// Symmetrically encrypted payload
    pub sym_ct: Vec<u8>,
}

/// Generate a delegation key pair for receiving re-encrypted ciphertexts
pub fn generate_delegation_keypair<R: RngCore + CryptoRng>(rng: &mut R, gp: &GlobalParams) -> DelegationKeyPair {
    let sk = Fr::random(rng);
    let pk = gp.h * sk;
    DelegationKeyPair { pk, sk }
}

/// Generate a DABE multi-hop re-encryption key for the first hop
///
/// The first hop converts from multi-authority DABE to a simpler form
/// that can be forwarded using standard DH key pairs.
///
/// # Arguments
/// * `rng` - Random number generator
/// * `gp` - Global parameters
/// * `usk` - User's aggregated secret key
/// * `target_pk` - Next recipient's public key
/// * `max_hops` - Maximum number of hops allowed
pub fn generate_first_hop_rekey<R: RngCore + CryptoRng>(
    rng: &mut R,
    gp: &GlobalParams,
    usk: &UserSecretKey,
    target_pk: &TargetPublicKey,
    max_hops: usize,
) -> Result<DabeMultiHopReEncryptionKey, AbeError> {
    if max_hops > MAX_HOPS {
        return Err(AbeError::EncryptError(format!(
            "Max hops {} exceeds limit {}", max_hops, MAX_HOPS
        )));
    }

    if usk.components.is_empty() {
        return Err(AbeError::KeygenError(
            "User key has no authority components".to_string()
        ));
    }

    let mut authority_components = HashMap::new();
    let mut combined_delta = Fr::zero();

    for (aid, uk_comp) in &usk.components {
        // Per-authority random blinding delta
        let delta_aid = Fr::random(rng);
        combined_delta = combined_delta + delta_aid;

        // RK_K = K - h^delta_aid
        let rk_k = uk_comp.k - (gp.h * delta_aid);

        let auth_rk = MultiHopAuthorityReKeyComponent {
            aid: aid.clone(),
            rk_k,
            rk_l: uk_comp.l,
            rk_x: uk_comp.kx.clone(),
            delta_aid,
        };

        authority_components.insert(aid.clone(), auth_rk);
    }

    // El-Gamal encrypt combined delta for target
    let r = Fr::random(rng);
    let u = gp.h * r;
    let target = match target_pk {
        TargetPublicKey::Simple(pk) => *pk,
        TargetPublicKey::AbeKey(l) => *l,
    };
    let h_combined_delta = gp.h * combined_delta;
    let w = h_combined_delta + (target * r);

    Ok(DabeMultiHopReEncryptionKey {
        authority_components,
        hop: DabeHopInfo { u, w, hop_index: 0 },
        max_remaining_hops: max_hops - 1,
    })
}

/// First hop re-encryption (from original DABE ciphertext)
pub fn first_hop_re_encrypt(
    _gp: &GlobalParams,
    ct: &Ciphertext,
    rk: &DabeMultiHopReEncryptionKey,
    max_hops: usize,
) -> Result<DabeMultiHopReEncryptedCiphertext, AbeError> {
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

    // Compute combined blinded contribution
    let mut c_blinded = Gt::one();

    for (aid, items) in &by_authority {
        let auth_rk = rk.authority_components.get(aid)
            .ok_or_else(|| AbeError::DecryptError(
                format!("No re-encryption key for authority {}", aid)
            ))?;

        // numerator = e(C, RK_K)
        let numerator = pairing(ct.c, auth_rk.rk_k);

        // Compute weighted sum and pairing product
        let mut prod1 = G1::zero();
        let mut prod_t = Gt::one();

        for (ct_comp, coeff) in items {
            prod1 = prod1 + ct_comp.c1 * *coeff;

            let kx = auth_rk.rk_x.get(&ct_comp.attr)
                .ok_or_else(|| AbeError::DecryptError(
                    format!("Missing re-key for attribute {}", ct_comp.attr)
                ))?;

            prod_t = prod_t * pairing(*kx * *coeff, ct_comp.d);
        }

        let pairing_prod1_l = pairing(prod1, auth_rk.rk_l);
        let denominator = prod_t * pairing_prod1_l;
        let contribution = numerator * denominator.inverse();

        c_blinded = c_blinded * contribution;
    }

    Ok(DabeMultiHopReEncryptedCiphertext {
        policy: ct.policy.clone(),
        c: ct.c,
        c_blinded,
        hops: vec![rk.hop.clone()],
        hop_count: 1,
        max_hops,
    })
}

/// First hop re-encryption for full ciphertext
pub fn first_hop_re_encrypt_full(
    gp: &GlobalParams,
    ct: &FullCiphertext,
    rk: &DabeMultiHopReEncryptionKey,
    max_hops: usize,
) -> Result<FullDabeMultiHopReEncryptedCiphertext, AbeError> {
    let pre_ct = first_hop_re_encrypt(gp, &ct.abe_ct, rk, max_hops)?;
    Ok(FullDabeMultiHopReEncryptedCiphertext {
        pre_ct,
        sym_ct: ct.sym_ct.clone(),
    })
}

/// Apply next hop re-encryption
///
/// The current recipient adds another layer of re-encryption for the next recipient.
pub fn next_hop_re_encrypt<R: RngCore + CryptoRng>(
    rng: &mut R,
    gp: &GlobalParams,
    re_ct: &DabeMultiHopReEncryptedCiphertext,
    current_secret: &TargetSecret,
    next_target_pk: &TargetPublicKey,
) -> Result<DabeMultiHopReEncryptedCiphertext, AbeError> {
    if re_ct.hop_count >= re_ct.max_hops {
        return Err(AbeError::EncryptError("Maximum hops reached".to_string()));
    }

    // Current recipient first recovers their delta
    let secret = match current_secret {
        TargetSecret::Simple(sk) => *sk,
        TargetSecret::AbeKey(t) => *t,
    };

    // Get the last hop info (for current recipient)
    let last_hop = re_ct.hops.last()
        .ok_or_else(|| AbeError::DecryptError("No hops in ciphertext".to_string()))?;

    // Recover h^delta for current hop
    let u_secret = last_hop.u * secret;
    let h_delta_current = last_hop.w - u_secret;

    // Unblind the current layer
    let delta_contribution = pairing(re_ct.c, h_delta_current);
    let unblinded = re_ct.c_blinded * delta_contribution;

    // Now add new blinding for next recipient
    let delta_new = Fr::random(rng);
    let h_delta_new = gp.h * delta_new;

    // Re-blind with new delta
    let new_blinding = pairing(re_ct.c, h_delta_new);
    let c_blinded_new = unblinded * new_blinding.inverse();

    // El-Gamal encrypt new delta for next recipient
    let r = Fr::random(rng);
    let u = gp.h * r;
    let next_target = match next_target_pk {
        TargetPublicKey::Simple(pk) => *pk,
        TargetPublicKey::AbeKey(l) => *l,
    };
    let w = h_delta_new + (next_target * r);

    // Add new hop
    let mut new_hops = re_ct.hops.clone();
    new_hops.push(DabeHopInfo { u, w, hop_index: re_ct.hop_count });

    Ok(DabeMultiHopReEncryptedCiphertext {
        policy: re_ct.policy.clone(),
        c: re_ct.c,
        c_blinded: c_blinded_new,
        hops: new_hops,
        hop_count: re_ct.hop_count + 1,
        max_hops: re_ct.max_hops,
    })
}

/// Next hop re-encryption for full ciphertext
pub fn next_hop_re_encrypt_full<R: RngCore + CryptoRng>(
    rng: &mut R,
    gp: &GlobalParams,
    re_ct: &FullDabeMultiHopReEncryptedCiphertext,
    current_secret: &TargetSecret,
    next_target_pk: &TargetPublicKey,
) -> Result<FullDabeMultiHopReEncryptedCiphertext, AbeError> {
    let pre_ct = next_hop_re_encrypt(rng, gp, &re_ct.pre_ct, current_secret, next_target_pk)?;
    Ok(FullDabeMultiHopReEncryptedCiphertext {
        pre_ct,
        sym_ct: re_ct.sym_ct.clone(),
    })
}

/// Decrypt a DABE multi-hop re-encrypted ciphertext (KEM mode)
///
/// The final recipient uses their secret to recover the symmetric key.
pub fn decrypt_multihop_kem(
    re_ct: &DabeMultiHopReEncryptedCiphertext,
    target_secret: &TargetSecret,
) -> Result<[u8; 32], AbeError> {
    let secret = match target_secret {
        TargetSecret::Simple(sk) => *sk,
        TargetSecret::AbeKey(t) => *t,
    };

    // Get the last hop (for this recipient)
    let last_hop = re_ct.hops.last()
        .ok_or_else(|| AbeError::DecryptError("No hops in ciphertext".to_string()))?;

    // Recover h^delta
    let u_secret = last_hop.u * secret;
    let h_delta = last_hop.w - u_secret;

    // Unblind: e(c, h^delta)
    let delta_contribution = pairing(re_ct.c, h_delta);
    let recovered = re_ct.c_blinded * delta_contribution;

    let sym_key = derive_key(&recovered);
    Ok(sym_key)
}

/// Decrypt a full DABE multi-hop re-encrypted ciphertext
pub fn decrypt_multihop(
    re_ct: &FullDabeMultiHopReEncryptedCiphertext,
    target_secret: &TargetSecret,
) -> Result<Vec<u8>, AbeError> {
    let sym_key = decrypt_multihop_kem(&re_ct.pre_ct, target_secret)?;
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
    fn test_dabe_multihop_single_hop() {
        let mut rng = thread_rng();

        let gp = global_setup(&mut rng);
        let (apk, ask) = authority_setup(&mut rng, &gp, "auth1");

        let uk = authority_keygen(
            &mut rng, &gp, &ask, "alice@test.com",
            &["admin".to_string()]
        ).unwrap();
        let usk_alice = aggregate_user_keys(vec![uk]).unwrap();

        let bob_keys = generate_delegation_keypair(&mut rng, &gp);

        let mut pks = HashMap::new();
        pks.insert("auth1".to_string(), apk);

        let policy = PolicyNode::Attr("auth1:admin".to_string());
        let plaintext = b"Single hop DABE secret";
        let ct = encrypt(&mut rng, &gp, &pks, &policy, plaintext).unwrap();

        // Alice → Bob
        let target_pk = TargetPublicKey::Simple(bob_keys.pk);
        let rk = generate_first_hop_rekey(&mut rng, &gp, &usk_alice, &target_pk, 3).unwrap();
        let re_ct = first_hop_re_encrypt_full(&gp, &ct, &rk, 3).unwrap();

        // Bob decrypts
        let target_secret = TargetSecret::Simple(bob_keys.sk);
        let decrypted = decrypt_multihop(&re_ct, &target_secret).unwrap();

        assert_eq!(decrypted, plaintext);
        assert_eq!(re_ct.pre_ct.hop_count, 1);
    }

    #[test]
    fn test_dabe_multihop_two_hops() {
        let mut rng = thread_rng();

        let gp = global_setup(&mut rng);
        let (apk, ask) = authority_setup(&mut rng, &gp, "auth1");

        let uk = authority_keygen(
            &mut rng, &gp, &ask, "alice@test.com",
            &["admin".to_string()]
        ).unwrap();
        let usk_alice = aggregate_user_keys(vec![uk]).unwrap();

        let bob_keys = generate_delegation_keypair(&mut rng, &gp);
        let carol_keys = generate_delegation_keypair(&mut rng, &gp);

        let mut pks = HashMap::new();
        pks.insert("auth1".to_string(), apk);

        let policy = PolicyNode::Attr("auth1:admin".to_string());
        let plaintext = b"Two hop DABE secret";
        let ct = encrypt(&mut rng, &gp, &pks, &policy, plaintext).unwrap();

        // Alice → Bob
        let rk_ab = generate_first_hop_rekey(
            &mut rng, &gp, &usk_alice,
            &TargetPublicKey::Simple(bob_keys.pk),
            3
        ).unwrap();
        let re_ct_bob = first_hop_re_encrypt_full(&gp, &ct, &rk_ab, 3).unwrap();

        // Bob → Carol
        let re_ct_carol = next_hop_re_encrypt_full(
            &mut rng, &gp, &re_ct_bob,
            &TargetSecret::Simple(bob_keys.sk),
            &TargetPublicKey::Simple(carol_keys.pk)
        ).unwrap();

        // Carol decrypts
        let decrypted = decrypt_multihop(&re_ct_carol, &TargetSecret::Simple(carol_keys.sk)).unwrap();

        assert_eq!(decrypted, plaintext);
        assert_eq!(re_ct_carol.pre_ct.hop_count, 2);
    }

    #[test]
    fn test_dabe_multihop_three_hops() {
        let mut rng = thread_rng();

        let gp = global_setup(&mut rng);
        let (apk, ask) = authority_setup(&mut rng, &gp, "auth1");

        let uk = authority_keygen(
            &mut rng, &gp, &ask, "alice",
            &["admin".to_string()]
        ).unwrap();
        let usk_alice = aggregate_user_keys(vec![uk]).unwrap();

        let bob_keys = generate_delegation_keypair(&mut rng, &gp);
        let carol_keys = generate_delegation_keypair(&mut rng, &gp);
        let dave_keys = generate_delegation_keypair(&mut rng, &gp);

        let mut pks = HashMap::new();
        pks.insert("auth1".to_string(), apk);

        let policy = PolicyNode::Attr("auth1:admin".to_string());
        let plaintext = b"Three hop DABE secret";
        let ct = encrypt(&mut rng, &gp, &pks, &policy, plaintext).unwrap();

        // Alice → Bob → Carol → Dave
        let rk_ab = generate_first_hop_rekey(
            &mut rng, &gp, &usk_alice,
            &TargetPublicKey::Simple(bob_keys.pk),
            5
        ).unwrap();
        let re_ct_bob = first_hop_re_encrypt_full(&gp, &ct, &rk_ab, 5).unwrap();

        let re_ct_carol = next_hop_re_encrypt_full(
            &mut rng, &gp, &re_ct_bob,
            &TargetSecret::Simple(bob_keys.sk),
            &TargetPublicKey::Simple(carol_keys.pk)
        ).unwrap();

        let re_ct_dave = next_hop_re_encrypt_full(
            &mut rng, &gp, &re_ct_carol,
            &TargetSecret::Simple(carol_keys.sk),
            &TargetPublicKey::Simple(dave_keys.pk)
        ).unwrap();

        // Dave decrypts
        let decrypted = decrypt_multihop(&re_ct_dave, &TargetSecret::Simple(dave_keys.sk)).unwrap();

        assert_eq!(decrypted, plaintext);
        assert_eq!(re_ct_dave.pre_ct.hop_count, 3);
    }

    #[test]
    fn test_dabe_multihop_max_hops_enforced() {
        let mut rng = thread_rng();

        let gp = global_setup(&mut rng);
        let (apk, ask) = authority_setup(&mut rng, &gp, "auth1");

        let uk = authority_keygen(
            &mut rng, &gp, &ask, "alice",
            &["admin".to_string()]
        ).unwrap();
        let usk_alice = aggregate_user_keys(vec![uk]).unwrap();

        let bob_keys = generate_delegation_keypair(&mut rng, &gp);
        let carol_keys = generate_delegation_keypair(&mut rng, &gp);

        let mut pks = HashMap::new();
        pks.insert("auth1".to_string(), apk);

        let policy = PolicyNode::Attr("auth1:admin".to_string());
        let ct = encrypt(&mut rng, &gp, &pks, &policy, b"limited hops").unwrap();

        // Create with max 1 hop
        let rk = generate_first_hop_rekey(
            &mut rng, &gp, &usk_alice,
            &TargetPublicKey::Simple(bob_keys.pk),
            1
        ).unwrap();
        let re_ct_bob = first_hop_re_encrypt_full(&gp, &ct, &rk, 1).unwrap();

        // Try second hop - should fail
        let result = next_hop_re_encrypt_full(
            &mut rng, &gp, &re_ct_bob,
            &TargetSecret::Simple(bob_keys.sk),
            &TargetPublicKey::Simple(carol_keys.pk)
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_dabe_multihop_wrong_key_fails() {
        let mut rng = thread_rng();

        let gp = global_setup(&mut rng);
        let (apk, ask) = authority_setup(&mut rng, &gp, "auth1");

        let uk = authority_keygen(
            &mut rng, &gp, &ask, "alice",
            &["admin".to_string()]
        ).unwrap();
        let usk_alice = aggregate_user_keys(vec![uk]).unwrap();

        let bob_keys = generate_delegation_keypair(&mut rng, &gp);
        let eve_keys = generate_delegation_keypair(&mut rng, &gp);

        let mut pks = HashMap::new();
        pks.insert("auth1".to_string(), apk);

        let policy = PolicyNode::Attr("auth1:admin".to_string());
        let ct = encrypt(&mut rng, &gp, &pks, &policy, b"secret for bob").unwrap();

        let rk = generate_first_hop_rekey(
            &mut rng, &gp, &usk_alice,
            &TargetPublicKey::Simple(bob_keys.pk),
            3
        ).unwrap();
        let re_ct = first_hop_re_encrypt_full(&gp, &ct, &rk, 3).unwrap();

        // Eve tries to decrypt - should fail
        let result = decrypt_multihop(&re_ct, &TargetSecret::Simple(eve_keys.sk));
        assert!(result.is_err(), "Eve should not be able to decrypt Bob's ciphertext");
    }

    #[test]
    fn test_dabe_multihop_intermediate_decrypt() {
        let mut rng = thread_rng();

        let gp = global_setup(&mut rng);
        let (apk, ask) = authority_setup(&mut rng, &gp, "auth1");

        let uk = authority_keygen(
            &mut rng, &gp, &ask, "alice",
            &["admin".to_string()]
        ).unwrap();
        let usk_alice = aggregate_user_keys(vec![uk]).unwrap();

        let bob_keys = generate_delegation_keypair(&mut rng, &gp);

        let mut pks = HashMap::new();
        pks.insert("auth1".to_string(), apk);

        let policy = PolicyNode::Attr("auth1:admin".to_string());
        let plaintext = b"bob can decrypt or forward";
        let ct = encrypt(&mut rng, &gp, &pks, &policy, plaintext).unwrap();

        let rk = generate_first_hop_rekey(
            &mut rng, &gp, &usk_alice,
            &TargetPublicKey::Simple(bob_keys.pk),
            3
        ).unwrap();
        let re_ct = first_hop_re_encrypt_full(&gp, &ct, &rk, 3).unwrap();

        // Bob can decrypt at this point
        let decrypted = decrypt_multihop(&re_ct, &TargetSecret::Simple(bob_keys.sk)).unwrap();
        assert_eq!(decrypted, plaintext);

        // Bob can also forward to Carol
        let carol_keys = generate_delegation_keypair(&mut rng, &gp);
        let re_ct_carol = next_hop_re_encrypt_full(
            &mut rng, &gp, &re_ct,
            &TargetSecret::Simple(bob_keys.sk),
            &TargetPublicKey::Simple(carol_keys.pk)
        ).unwrap();

        // Carol can decrypt
        let decrypted_carol = decrypt_multihop(&re_ct_carol, &TargetSecret::Simple(carol_keys.sk)).unwrap();
        assert_eq!(decrypted_carol, plaintext);
    }

    #[test]
    fn test_dabe_multihop_multi_authority() {
        let mut rng = thread_rng();

        let gp = global_setup(&mut rng);
        let (apk1, ask1) = authority_setup(&mut rng, &gp, "hr");
        let (apk2, ask2) = authority_setup(&mut rng, &gp, "it");

        // Alice gets keys from both authorities
        let uk1 = authority_keygen(
            &mut rng, &gp, &ask1, "alice@corp.com",
            &["manager".to_string()]
        ).unwrap();
        let uk2 = authority_keygen(
            &mut rng, &gp, &ask2, "alice@corp.com",
            &["developer".to_string()]
        ).unwrap();
        let usk_alice = aggregate_user_keys(vec![uk1, uk2]).unwrap();

        let bob_keys = generate_delegation_keypair(&mut rng, &gp);

        let mut pks = HashMap::new();
        pks.insert("hr".to_string(), apk1);
        pks.insert("it".to_string(), apk2);

        // Cross-authority policy
        let policy = PolicyNode::And(vec![
            PolicyNode::Attr("hr:manager".to_string()),
            PolicyNode::Attr("it:developer".to_string()),
        ]);

        let plaintext = b"Multi-authority multi-hop secret";
        let ct = encrypt(&mut rng, &gp, &pks, &policy, plaintext).unwrap();

        // Alice → Bob
        let rk = generate_first_hop_rekey(
            &mut rng, &gp, &usk_alice,
            &TargetPublicKey::Simple(bob_keys.pk),
            3
        ).unwrap();
        let re_ct = first_hop_re_encrypt_full(&gp, &ct, &rk, 3).unwrap();

        // Bob decrypts
        let decrypted = decrypt_multihop(&re_ct, &TargetSecret::Simple(bob_keys.sk)).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_dabe_multihop_exceeds_max_limit() {
        let mut rng = thread_rng();

        let gp = global_setup(&mut rng);
        let (apk, ask) = authority_setup(&mut rng, &gp, "auth1");

        let uk = authority_keygen(
            &mut rng, &gp, &ask, "alice",
            &["admin".to_string()]
        ).unwrap();
        let usk_alice = aggregate_user_keys(vec![uk]).unwrap();

        let bob_keys = generate_delegation_keypair(&mut rng, &gp);

        // Try to create with more than MAX_HOPS
        let result = generate_first_hop_rekey(
            &mut rng, &gp, &usk_alice,
            &TargetPublicKey::Simple(bob_keys.pk),
            MAX_HOPS + 1
        );

        assert!(result.is_err());
    }
}
