//! AC17 Multi-Hop Proxy Re-Encryption
//!
//! This module implements multi-hop PRE for AC17 CP-ABE where a ciphertext
//! can be re-encrypted multiple times through a chain of proxies:
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
use crate::schemes::ac17::{Mpk, SecretKey, Ciphertext, FullCiphertext, CiphertextComponent};
use crate::schemes::waters::parse_policy;
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
pub struct Ac17HopInfo {
    /// El-Gamal component 1: h^r
    pub u: G2,
    /// El-Gamal component 2: h^delta * pk_recipient^r
    pub w: G2,
    /// Hop index (0 = first re-encryption)
    pub hop_index: usize,
}

/// AC17 Multi-hop re-encryption key
///
/// This key allows re-encryption from one party to the next in the chain.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Ac17MultiHopReEncryptionKey {
    /// Attributes this re-key is valid for
    pub source_attributes: Vec<String>,
    /// Blinded K component: K - h^delta
    pub rk_k: G2,
    /// L component: h^r
    pub rk_l: G2,
    /// Per-attribute components
    pub rk_attrs: HashMap<String, G1>,
    /// El-Gamal encrypted delta for next recipient
    pub hop: Ac17HopInfo,
    /// Maximum hops allowed after this one
    pub max_remaining_hops: usize,
}

/// AC17 Multi-hop re-encrypted ciphertext
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Ac17MultiHopReEncryptedCiphertext {
    /// Original policy
    pub policy: String,
    /// C = g^s
    pub c: G1,
    /// Blinded decryption result (accumulated across all hops)
    pub c_blinded: Gt,
    /// Chain of hops (each with El-Gamal encrypted delta)
    pub hops: Vec<Ac17HopInfo>,
    /// Current hop count
    pub hop_count: usize,
    /// Maximum allowed hops
    pub max_hops: usize,
}

/// Full AC17 multi-hop re-encrypted ciphertext
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct FullAc17MultiHopReEncryptedCiphertext {
    /// ABE re-encrypted ciphertext
    pub pre_ct: Ac17MultiHopReEncryptedCiphertext,
    /// Symmetrically encrypted payload
    pub sym_ct: Vec<u8>,
}

/// Generate a delegation key pair for AC17 multi-hop PRE
pub fn generate_delegation_keypair<R: RngCore + CryptoRng>(rng: &mut R, mpk: &Mpk) -> DelegationKeyPair {
    let sk = Fr::random(rng);
    let pk = mpk.h * sk;
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
) -> Result<Ac17MultiHopReEncryptionKey, AbeError> {
    if max_hops > MAX_HOPS {
        return Err(AbeError::EncryptError(format!(
            "Max hops {} exceeds limit {}", max_hops, MAX_HOPS
        )));
    }

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

    // El-Gamal encrypt delta for target
    let r = Fr::random(rng);
    let u = mpk.h * r;
    let target = match target_pk {
        TargetPublicKey::Simple(pk) => *pk,
        TargetPublicKey::AbeKey(l) => *l,
    };
    let w = h_delta + (target * r);

    Ok(Ac17MultiHopReEncryptionKey {
        source_attributes: attrs.to_vec(),
        rk_k,
        rk_l,
        rk_attrs,
        hop: Ac17HopInfo { u, w, hop_index: 0 },
        max_remaining_hops: max_hops - 1,
    })
}

/// First hop re-encryption (from original AC17 ciphertext)
pub fn first_hop_re_encrypt(
    _mpk: &Mpk,
    ct: &Ciphertext,
    rk: &Ac17MultiHopReEncryptionKey,
    max_hops: usize,
) -> Result<Ac17MultiHopReEncryptedCiphertext, AbeError> {
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

    Ok(Ac17MultiHopReEncryptedCiphertext {
        policy: ct.policy.clone(),
        c: ct.c,
        c_blinded,
        hops: vec![rk.hop.clone()],
        hop_count: 1,
        max_hops,
    })
}

/// First hop re-encryption for full AC17 ciphertext
pub fn first_hop_re_encrypt_full(
    mpk: &Mpk,
    ct: &FullCiphertext,
    rk: &Ac17MultiHopReEncryptionKey,
    max_hops: usize,
) -> Result<FullAc17MultiHopReEncryptedCiphertext, AbeError> {
    let pre_ct = first_hop_re_encrypt(mpk, &ct.abe_ct, rk, max_hops)?;
    Ok(FullAc17MultiHopReEncryptedCiphertext {
        pre_ct,
        sym_ct: ct.sym_ct.clone(),
    })
}

/// Apply next hop re-encryption for AC17
///
/// The current recipient adds another layer of re-encryption for the next recipient.
pub fn next_hop_re_encrypt<R: RngCore + CryptoRng>(
    rng: &mut R,
    mpk: &Mpk,
    re_ct: &Ac17MultiHopReEncryptedCiphertext,
    current_secret: &TargetSecret,
    next_target_pk: &TargetPublicKey,
) -> Result<Ac17MultiHopReEncryptedCiphertext, AbeError> {
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
    let h_delta_new = mpk.h * delta_new;

    // Re-blind with new delta
    let new_blinding = pairing(re_ct.c, h_delta_new);
    let c_blinded_new = unblinded * new_blinding.inverse();

    // El-Gamal encrypt new delta for next recipient
    let r = Fr::random(rng);
    let u = mpk.h * r;
    let next_target = match next_target_pk {
        TargetPublicKey::Simple(pk) => *pk,
        TargetPublicKey::AbeKey(l) => *l,
    };
    let w = h_delta_new + (next_target * r);

    // Add new hop
    let mut new_hops = re_ct.hops.clone();
    new_hops.push(Ac17HopInfo { u, w, hop_index: re_ct.hop_count });

    Ok(Ac17MultiHopReEncryptedCiphertext {
        policy: re_ct.policy.clone(),
        c: re_ct.c,
        c_blinded: c_blinded_new,
        hops: new_hops,
        hop_count: re_ct.hop_count + 1,
        max_hops: re_ct.max_hops,
    })
}

/// Next hop re-encryption for full AC17 ciphertext
pub fn next_hop_re_encrypt_full<R: RngCore + CryptoRng>(
    rng: &mut R,
    mpk: &Mpk,
    re_ct: &FullAc17MultiHopReEncryptedCiphertext,
    current_secret: &TargetSecret,
    next_target_pk: &TargetPublicKey,
) -> Result<FullAc17MultiHopReEncryptedCiphertext, AbeError> {
    let pre_ct = next_hop_re_encrypt(rng, mpk, &re_ct.pre_ct, current_secret, next_target_pk)?;
    Ok(FullAc17MultiHopReEncryptedCiphertext {
        pre_ct,
        sym_ct: re_ct.sym_ct.clone(),
    })
}

/// Decrypt an AC17 multi-hop re-encrypted ciphertext (KEM mode)
///
/// The final recipient uses their secret to recover the symmetric key.
pub fn decrypt_multihop_kem(
    re_ct: &Ac17MultiHopReEncryptedCiphertext,
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

    // Unblind: e(c, h_delta)
    let delta_contribution = pairing(re_ct.c, h_delta);
    let recovered = re_ct.c_blinded * delta_contribution;

    let sym_key = derive_key(&recovered);
    Ok(sym_key)
}

/// Decrypt a full AC17 multi-hop re-encrypted ciphertext
pub fn decrypt_multihop(
    re_ct: &FullAc17MultiHopReEncryptedCiphertext,
    target_secret: &TargetSecret,
) -> Result<Vec<u8>, AbeError> {
    let sym_key = decrypt_multihop_kem(&re_ct.pre_ct, target_secret)?;
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
    fn test_ac17_multihop_single_hop() {
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
    fn test_ac17_multihop_two_hops() {
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
    fn test_ac17_multihop_three_hops() {
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
    fn test_ac17_multihop_max_hops_enforced() {
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
    fn test_ac17_multihop_wrong_key_fails() {
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
    fn test_ac17_multihop_intermediate_decrypt() {
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
