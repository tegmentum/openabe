//! Multi-Hop Proxy Re-Encryption
//!
//! This module implements multi-hop PRE where a ciphertext can be
//! re-encrypted multiple times through a chain of proxies:
//!
//! ```text
//! Alice → Bob → Carol → Dave
//! ```
//!
//! ## Design
//!
//! Each hop adds a blinding factor. The ciphertext accumulates these
//! blindings along with the El-Gamal encrypted deltas for each recipient
//! in the chain.
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
use crate::lsss::LsssMatrix;
use crate::schemes::waters::{Mpk, SecretKey, Ciphertext, FullCiphertext, CiphertextComponent, parse_policy};
use crate::schemes::waters_u2u_pre::{DelegationKeyPair, TargetPublicKey, TargetSecret};
use crate::utils::aes;
use rabe_bls12381::{Fr, G1, G2, Gt, pairing};
use rand::{RngCore, CryptoRng};
use std::collections::HashMap;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Maximum allowed hops (security limit)
pub const MAX_HOPS: usize = 10;

/// A single hop in the re-encryption chain
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct HopInfo {
    /// El-Gamal component 1: g2^r
    pub u: G2,
    /// El-Gamal component 2: g2^delta * pk_recipient^r
    pub w: G2,
    /// Hop index (0 = first re-encryption)
    pub hop_index: usize,
}

/// Multi-hop re-encryption key
///
/// This key allows re-encryption from one party to the next in the chain.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct MultiHopReEncryptionKey {
    /// Attributes this re-key is valid for
    pub source_attributes: Vec<String>,
    /// Blinded K component: K - g2^delta
    pub rk_k: G2,
    /// L component: g2^t
    pub rk_l: G2,
    /// Per-attribute components
    pub rk_x: HashMap<String, G1>,
    /// El-Gamal encrypted delta for next recipient
    pub hop: HopInfo,
    /// Maximum hops allowed after this one
    pub max_remaining_hops: usize,
}

/// Multi-hop re-encrypted ciphertext
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct MultiHopReEncryptedCiphertext {
    /// Original policy
    pub policy: String,
    /// C' = g1^s
    pub c_prime: G1,
    /// Blinded decryption result (accumulated across all hops)
    pub c_blinded: Gt,
    /// Chain of hops (each with El-Gamal encrypted delta)
    pub hops: Vec<HopInfo>,
    /// Current hop count
    pub hop_count: usize,
    /// Maximum allowed hops
    pub max_hops: usize,
}

/// Full multi-hop re-encrypted ciphertext
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct FullMultiHopReEncryptedCiphertext {
    /// ABE re-encrypted ciphertext
    pub pre_ct: MultiHopReEncryptedCiphertext,
    /// Symmetrically encrypted payload
    pub sym_ct: Vec<u8>,
}

/// Generate a delegation key pair (same as U2U PRE)
pub fn generate_delegation_keypair<R: RngCore + CryptoRng>(rng: &mut R, mpk: &Mpk) -> DelegationKeyPair {
    let sk = Fr::random(rng);
    let pk = mpk.g2 * sk;
    DelegationKeyPair { pk, sk }
}

/// Generate a multi-hop re-encryption key for the first hop
///
/// # Arguments
///
/// * `rng` - Random number generator
/// * `mpk` - Master public key
/// * `sk` - Source's secret key
/// * `target_pk` - Next recipient's public key
/// * `attrs` - Attributes to include
/// * `max_hops` - Maximum number of hops allowed
pub fn generate_first_hop_rekey<R: RngCore + CryptoRng>(
    rng: &mut R,
    mpk: &Mpk,
    sk: &SecretKey,
    target_pk: &TargetPublicKey,
    attrs: &[String],
    max_hops: usize,
) -> Result<MultiHopReEncryptionKey, AbeError> {
    if max_hops > MAX_HOPS {
        return Err(AbeError::EncryptError(format!(
            "Max hops {} exceeds limit {}", max_hops, MAX_HOPS
        )));
    }

    // Validate attributes
    for attr in attrs {
        if !sk.kx.contains_key(attr) {
            return Err(AbeError::InvalidAttribute(format!("Missing attribute: {}", attr)));
        }
    }

    // Generate random blinding factor
    let delta = Fr::random(rng);
    let g2_delta = mpk.g2 * delta;

    // Blind the K component
    let rk_k = sk.k - g2_delta;
    let rk_l = sk.l;

    // Copy attribute components
    let mut rk_x = HashMap::new();
    for attr in attrs {
        let kx = sk.kx.get(attr).unwrap();
        rk_x.insert(attr.clone(), *kx);
    }

    // El-Gamal encrypt delta for target
    let r = Fr::random(rng);
    let u = mpk.g2 * r;
    let target = match target_pk {
        TargetPublicKey::Simple(pk) => *pk,
        TargetPublicKey::AbeKey(l) => *l,
    };
    let w = g2_delta + (target * r);

    Ok(MultiHopReEncryptionKey {
        source_attributes: attrs.to_vec(),
        rk_k,
        rk_l,
        rk_x,
        hop: HopInfo { u, w, hop_index: 0 },
        max_remaining_hops: max_hops - 1,
    })
}

/// First hop re-encryption (from original ciphertext)
pub fn first_hop_re_encrypt(
    _mpk: &Mpk,
    ct: &Ciphertext,
    rk: &MultiHopReEncryptionKey,
    max_hops: usize,
) -> Result<MultiHopReEncryptedCiphertext, AbeError> {
    // Parse policy
    let policy = parse_policy(&ct.policy)
        .map_err(|e| AbeError::InvalidPolicy(e.to_string()))?;
    let lsss = LsssMatrix::from_policy(&policy)?;

    // Find satisfied rows
    let mut satisfied_attrs = Vec::new();
    let mut satisfied_components: Vec<(&String, &CiphertextComponent)> = Vec::new();

    for (attr, ct_comp) in &ct.components {
        if rk.rk_x.contains_key(attr) {
            satisfied_attrs.push(attr.clone());
            satisfied_components.push((attr, ct_comp));
        }
    }

    if satisfied_components.is_empty() {
        return Err(AbeError::PolicyNotSatisfied);
    }

    // Get reconstruction coefficients
    let coeffs = lsss.recover_coefficients(&satisfied_attrs)
        .map_err(|_| AbeError::PolicyNotSatisfied)?;

    // Compute partial decryption with blinded key
    let e_c_prime_rk_k = pairing(ct.c_prime, rk.rk_k);

    // Compute cancel term
    let mut cancel_term = Gt::one();
    for (attr, ct_comp) in &satisfied_components {
        if let Some(&omega) = coeffs.get(*attr) {
            let kx = rk.rk_x.get(*attr).unwrap();
            let p1 = pairing(ct_comp.c, rk.rk_l);
            let p2 = pairing(*kx, ct_comp.d);
            let term = (p1 * p2).pow(&omega);
            cancel_term = cancel_term * term;
        }
    }

    let c_blinded = e_c_prime_rk_k * cancel_term.inverse();

    Ok(MultiHopReEncryptedCiphertext {
        policy: ct.policy.clone(),
        c_prime: ct.c_prime,
        c_blinded,
        hops: vec![rk.hop.clone()],
        hop_count: 1,
        max_hops,
    })
}

/// First hop re-encryption for full ciphertext
pub fn first_hop_re_encrypt_full(
    mpk: &Mpk,
    ct: &FullCiphertext,
    rk: &MultiHopReEncryptionKey,
    max_hops: usize,
) -> Result<FullMultiHopReEncryptedCiphertext, AbeError> {
    // Convert raw ciphertext to typed wrapper for type-safe re-encryption
    let abe_ct: Ciphertext = ct.abe_ct.clone().into();
    let pre_ct = first_hop_re_encrypt(mpk, &abe_ct, rk, max_hops)?;
    Ok(FullMultiHopReEncryptedCiphertext {
        pre_ct,
        sym_ct: ct.sym_ct.clone(),
    })
}

/// Generate a re-encryption key for subsequent hops
///
/// The current recipient creates a new re-key to forward to the next recipient.
pub fn generate_next_hop_rekey<R: RngCore + CryptoRng>(
    rng: &mut R,
    mpk: &Mpk,
    current_secret: &TargetSecret,
    next_target_pk: &TargetPublicKey,
    current_hop_count: usize,
    max_remaining_hops: usize,
) -> Result<(G2, HopInfo), AbeError> {
    if max_remaining_hops == 0 {
        return Err(AbeError::EncryptError("Maximum hops reached".to_string()));
    }

    // Generate new delta for this hop
    let delta = Fr::random(rng);
    let g2_delta = mpk.g2 * delta;

    // El-Gamal encrypt new delta for next recipient
    let r = Fr::random(rng);
    let u = mpk.g2 * r;
    let next_target = match next_target_pk {
        TargetPublicKey::Simple(pk) => *pk,
        TargetPublicKey::AbeKey(l) => *l,
    };
    let w = g2_delta + (next_target * r);

    Ok((g2_delta, HopInfo { u, w, hop_index: current_hop_count }))
}

/// Apply next hop re-encryption
///
/// The current recipient adds another layer of re-encryption for the next recipient.
pub fn next_hop_re_encrypt<R: RngCore + CryptoRng>(
    rng: &mut R,
    mpk: &Mpk,
    re_ct: &MultiHopReEncryptedCiphertext,
    current_secret: &TargetSecret,
    next_target_pk: &TargetPublicKey,
) -> Result<MultiHopReEncryptedCiphertext, AbeError> {
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

    // Recover g2^delta for current hop
    let u_secret = last_hop.u * secret;
    let g2_delta_current = last_hop.w - u_secret;

    // Unblind the current layer
    let delta_contribution = pairing(re_ct.c_prime, g2_delta_current);
    let unblinded = re_ct.c_blinded * delta_contribution;

    // Now add new blinding for next recipient
    let delta_new = Fr::random(rng);
    let g2_delta_new = mpk.g2 * delta_new;

    // Re-blind with new delta
    let new_blinding = pairing(re_ct.c_prime, g2_delta_new);
    let c_blinded_new = unblinded * new_blinding.inverse();

    // El-Gamal encrypt new delta for next recipient
    let r = Fr::random(rng);
    let u = mpk.g2 * r;
    let next_target = match next_target_pk {
        TargetPublicKey::Simple(pk) => *pk,
        TargetPublicKey::AbeKey(l) => *l,
    };
    let w = g2_delta_new + (next_target * r);

    // Add new hop
    let mut new_hops = re_ct.hops.clone();
    new_hops.push(HopInfo { u, w, hop_index: re_ct.hop_count });

    Ok(MultiHopReEncryptedCiphertext {
        policy: re_ct.policy.clone(),
        c_prime: re_ct.c_prime,
        c_blinded: c_blinded_new,
        hops: new_hops,
        hop_count: re_ct.hop_count + 1,
        max_hops: re_ct.max_hops,
    })
}

/// Next hop re-encryption for full ciphertext
pub fn next_hop_re_encrypt_full<R: RngCore + CryptoRng>(
    rng: &mut R,
    mpk: &Mpk,
    re_ct: &FullMultiHopReEncryptedCiphertext,
    current_secret: &TargetSecret,
    next_target_pk: &TargetPublicKey,
) -> Result<FullMultiHopReEncryptedCiphertext, AbeError> {
    let pre_ct = next_hop_re_encrypt(rng, mpk, &re_ct.pre_ct, current_secret, next_target_pk)?;
    Ok(FullMultiHopReEncryptedCiphertext {
        pre_ct,
        sym_ct: re_ct.sym_ct.clone(),
    })
}

/// Decrypt a multi-hop re-encrypted ciphertext (KEM mode)
///
/// The final recipient uses their secret to recover the symmetric key.
pub fn decrypt_multihop_kem(
    re_ct: &MultiHopReEncryptedCiphertext,
    target_secret: &TargetSecret,
) -> Result<[u8; 32], AbeError> {
    let secret = match target_secret {
        TargetSecret::Simple(sk) => *sk,
        TargetSecret::AbeKey(t) => *t,
    };

    // Get the last hop (for this recipient)
    let last_hop = re_ct.hops.last()
        .ok_or_else(|| AbeError::DecryptError("No hops in ciphertext".to_string()))?;

    // Recover g2^delta
    let u_secret = last_hop.u * secret;
    let g2_delta = last_hop.w - u_secret;

    // Unblind: e(c_prime, g2_delta)
    let delta_contribution = pairing(re_ct.c_prime, g2_delta);
    let recovered = re_ct.c_blinded * delta_contribution;

    let sym_key = aes::derive_key(&recovered);
    Ok(sym_key)
}

/// Decrypt a full multi-hop re-encrypted ciphertext
pub fn decrypt_multihop(
    re_ct: &FullMultiHopReEncryptedCiphertext,
    target_secret: &TargetSecret,
) -> Result<Vec<u8>, AbeError> {
    let sym_key = decrypt_multihop_kem(&re_ct.pre_ct, target_secret)?;
    aes::decrypt(&sym_key, &re_ct.sym_ct)
        .map_err(|e| AbeError::DecryptError(e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lsss::PolicyNode;
    use crate::schemes::waters::{setup, keygen, encrypt};
    use rand::thread_rng;

    #[test]
    fn test_multihop_single_hop() {
        let mut rng = thread_rng();

        let (mpk, msk) = setup(&mut rng);
        let alice_attrs = vec!["admin".to_string()];
        let sk_alice = keygen(&mut rng, &mpk, &msk, &alice_attrs).unwrap();

        let bob_keys = generate_delegation_keypair(&mut rng, &mpk);

        let policy = PolicyNode::Attr("admin".to_string());
        let ct = encrypt(&mut rng, &mpk, &policy, b"single hop secret").unwrap();

        // Alice → Bob (1 hop)
        let target_pk = TargetPublicKey::Simple(bob_keys.pk);
        let rk = generate_first_hop_rekey(&mut rng, &mpk, &sk_alice, &target_pk, &alice_attrs, 3).unwrap();
        let re_ct = first_hop_re_encrypt_full(&mpk, &ct, &rk, 3).unwrap();

        // Bob decrypts
        let target_secret = TargetSecret::Simple(bob_keys.sk);
        let decrypted = decrypt_multihop(&re_ct, &target_secret).unwrap();

        assert_eq!(decrypted, b"single hop secret");
        assert_eq!(re_ct.pre_ct.hop_count, 1);
    }

    #[test]
    fn test_multihop_two_hops() {
        let mut rng = thread_rng();

        let (mpk, msk) = setup(&mut rng);
        let alice_attrs = vec!["admin".to_string()];
        let sk_alice = keygen(&mut rng, &mpk, &msk, &alice_attrs).unwrap();

        let bob_keys = generate_delegation_keypair(&mut rng, &mpk);
        let carol_keys = generate_delegation_keypair(&mut rng, &mpk);

        let policy = PolicyNode::Attr("admin".to_string());
        let ct = encrypt(&mut rng, &mpk, &policy, b"two hop secret").unwrap();

        // Alice → Bob
        let rk_ab = generate_first_hop_rekey(
            &mut rng, &mpk, &sk_alice,
            &TargetPublicKey::Simple(bob_keys.pk),
            &alice_attrs, 3
        ).unwrap();
        let re_ct_bob = first_hop_re_encrypt_full(&mpk, &ct, &rk_ab, 3).unwrap();

        // Bob → Carol
        let re_ct_carol = next_hop_re_encrypt_full(
            &mut rng, &mpk, &re_ct_bob,
            &TargetSecret::Simple(bob_keys.sk),
            &TargetPublicKey::Simple(carol_keys.pk)
        ).unwrap();

        // Carol decrypts
        let decrypted = decrypt_multihop(&re_ct_carol, &TargetSecret::Simple(carol_keys.sk)).unwrap();

        assert_eq!(decrypted, b"two hop secret");
        assert_eq!(re_ct_carol.pre_ct.hop_count, 2);
    }

    #[test]
    fn test_multihop_three_hops() {
        let mut rng = thread_rng();

        let (mpk, msk) = setup(&mut rng);
        let alice_attrs = vec!["admin".to_string()];
        let sk_alice = keygen(&mut rng, &mpk, &msk, &alice_attrs).unwrap();

        let bob_keys = generate_delegation_keypair(&mut rng, &mpk);
        let carol_keys = generate_delegation_keypair(&mut rng, &mpk);
        let dave_keys = generate_delegation_keypair(&mut rng, &mpk);

        let policy = PolicyNode::Attr("admin".to_string());
        let ct = encrypt(&mut rng, &mpk, &policy, b"three hop secret").unwrap();

        // Alice → Bob → Carol → Dave
        let rk_ab = generate_first_hop_rekey(
            &mut rng, &mpk, &sk_alice,
            &TargetPublicKey::Simple(bob_keys.pk),
            &alice_attrs, 5
        ).unwrap();
        let re_ct_bob = first_hop_re_encrypt_full(&mpk, &ct, &rk_ab, 5).unwrap();

        let re_ct_carol = next_hop_re_encrypt_full(
            &mut rng, &mpk, &re_ct_bob,
            &TargetSecret::Simple(bob_keys.sk),
            &TargetPublicKey::Simple(carol_keys.pk)
        ).unwrap();

        let re_ct_dave = next_hop_re_encrypt_full(
            &mut rng, &mpk, &re_ct_carol,
            &TargetSecret::Simple(carol_keys.sk),
            &TargetPublicKey::Simple(dave_keys.pk)
        ).unwrap();

        // Dave decrypts
        let decrypted = decrypt_multihop(&re_ct_dave, &TargetSecret::Simple(dave_keys.sk)).unwrap();

        assert_eq!(decrypted, b"three hop secret");
        assert_eq!(re_ct_dave.pre_ct.hop_count, 3);
    }

    #[test]
    fn test_multihop_max_hops_enforced() {
        let mut rng = thread_rng();

        let (mpk, msk) = setup(&mut rng);
        let alice_attrs = vec!["admin".to_string()];
        let sk_alice = keygen(&mut rng, &mpk, &msk, &alice_attrs).unwrap();

        let bob_keys = generate_delegation_keypair(&mut rng, &mpk);
        let carol_keys = generate_delegation_keypair(&mut rng, &mpk);

        let policy = PolicyNode::Attr("admin".to_string());
        let ct = encrypt(&mut rng, &mpk, &policy, b"limited hops").unwrap();

        // Create with max 1 hop
        let rk = generate_first_hop_rekey(
            &mut rng, &mpk, &sk_alice,
            &TargetPublicKey::Simple(bob_keys.pk),
            &alice_attrs, 1
        ).unwrap();
        let re_ct_bob = first_hop_re_encrypt_full(&mpk, &ct, &rk, 1).unwrap();

        // Try second hop - should fail
        let result = next_hop_re_encrypt_full(
            &mut rng, &mpk, &re_ct_bob,
            &TargetSecret::Simple(bob_keys.sk),
            &TargetPublicKey::Simple(carol_keys.pk)
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_multihop_wrong_key_fails() {
        let mut rng = thread_rng();

        let (mpk, msk) = setup(&mut rng);
        let alice_attrs = vec!["admin".to_string()];
        let sk_alice = keygen(&mut rng, &mpk, &msk, &alice_attrs).unwrap();

        let bob_keys = generate_delegation_keypair(&mut rng, &mpk);
        let eve_keys = generate_delegation_keypair(&mut rng, &mpk);

        let policy = PolicyNode::Attr("admin".to_string());
        let ct = encrypt(&mut rng, &mpk, &policy, b"secret for bob").unwrap();

        let rk = generate_first_hop_rekey(
            &mut rng, &mpk, &sk_alice,
            &TargetPublicKey::Simple(bob_keys.pk),
            &alice_attrs, 3
        ).unwrap();
        let re_ct = first_hop_re_encrypt_full(&mpk, &ct, &rk, 3).unwrap();

        // Eve tries to decrypt - should fail
        let result = decrypt_multihop(&re_ct, &TargetSecret::Simple(eve_keys.sk));
        assert!(result.is_err(), "Eve should not be able to decrypt Bob's ciphertext");
    }

    #[test]
    fn test_multihop_intermediate_decrypt() {
        let mut rng = thread_rng();

        let (mpk, msk) = setup(&mut rng);
        let alice_attrs = vec!["admin".to_string()];
        let sk_alice = keygen(&mut rng, &mpk, &msk, &alice_attrs).unwrap();

        let bob_keys = generate_delegation_keypair(&mut rng, &mpk);

        let policy = PolicyNode::Attr("admin".to_string());
        let ct = encrypt(&mut rng, &mpk, &policy, b"bob can decrypt or forward").unwrap();

        let rk = generate_first_hop_rekey(
            &mut rng, &mpk, &sk_alice,
            &TargetPublicKey::Simple(bob_keys.pk),
            &alice_attrs, 3
        ).unwrap();
        let re_ct = first_hop_re_encrypt_full(&mpk, &ct, &rk, 3).unwrap();

        // Bob can decrypt at this point
        let decrypted = decrypt_multihop(&re_ct, &TargetSecret::Simple(bob_keys.sk)).unwrap();
        assert_eq!(decrypted, b"bob can decrypt or forward");

        // Bob can also forward to Carol
        let carol_keys = generate_delegation_keypair(&mut rng, &mpk);
        let re_ct_carol = next_hop_re_encrypt_full(
            &mut rng, &mpk, &re_ct,
            &TargetSecret::Simple(bob_keys.sk),
            &TargetPublicKey::Simple(carol_keys.pk)
        ).unwrap();

        // Carol can decrypt
        let decrypted_carol = decrypt_multihop(&re_ct_carol, &TargetSecret::Simple(carol_keys.sk)).unwrap();
        assert_eq!(decrypted_carol, b"bob can decrypt or forward");
    }
}
