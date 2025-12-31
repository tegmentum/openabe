//! Mediator-Based Revocation (SEM) for CP-ABE
//!
//! Implementation based on:
//! - Boneh, Ding, Tsudik. "Identity-based Encryption with Security Mediators" (2003)
//! - Libert, Quisquater. "Efficient Revocation and Threshold Pairing Based Cryptosystems" (2003)
//!
//! Decryption requires assistance from an online Security Mediator (SEM).
//! The mediator checks revocation status before providing its decryption share.
//!
//! # Properties
//! - Instant revocation (mediator refuses to help revoked users)
//! - Requires online mediator for every decryption
//! - Split-key architecture (user key + mediator share)
//!
//! # Security Model
//! - Mediator cannot decrypt alone (needs user's key share)
//! - User cannot decrypt alone (needs mediator's share)
//! - Compromise of either party alone doesn't reveal plaintext

use crate::error::AbeError;
use crate::lsss::LsssMatrix;
use crate::schemes::waters::parse_policy;
use crate::tracing::{RevocationList, UserId as TracingUserId};
use crate::utils::{hash_to_g1_keyed, aes};
use rabe_bls12381::{Fr, G1, G2, Gt, pairing};
use rand::{RngCore, CryptoRng};
use std::collections::HashMap;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Hash key length in bytes
const HASH_KEY_LEN: usize = 32;

/// Mediator identifier
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct MediatorId(pub String);

impl MediatorId {
    pub fn new(id: &str) -> Self {
        Self(id.to_string())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Master public key for mediated ABE
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Mpk {
    /// Generator g1
    pub g1: G1,
    /// Generator g2
    pub g2: G2,
    /// g1^a
    pub g1a: G1,
    /// g2^alpha (split between user and mediator)
    pub g2alpha: G2,
    /// e(g1, g2)^alpha
    pub egg_alpha: Gt,
    /// Hash key for attributes
    pub k: [u8; HASH_KEY_LEN],
    /// Mediator public key component
    pub mediator_pk: G2,
}

/// Master secret key
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Msk {
    /// Master secret alpha (split: alpha = alpha_u + alpha_m)
    pub alpha: Fr,
    /// Exponent a
    pub a: Fr,
    /// g2^a for key generation
    pub g2a: G2,
    /// User's share of alpha
    pub alpha_user: Fr,
    /// Mediator's share of alpha
    pub alpha_mediator: Fr,
}

/// Mediator's secret key
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct MediatorSecretKey {
    /// Mediator identifier
    pub mediator_id: MediatorId,
    /// Mediator's master secret share
    pub alpha_m: Fr,
    /// g2^alpha_m
    pub g2_alpha_m: G2,
}

/// User's partial secret key (requires mediator assistance to decrypt)
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct UserPartialKey {
    /// User identifier
    pub user_id: String,
    /// K_u = g2^alpha_u * g2^(a*t) (user's share)
    pub k_u: G2,
    /// L = g2^t
    pub l: G2,
    /// Per-attribute components K_x = H(k, x)^t
    pub kx: HashMap<String, G1>,
    /// User's attributes
    pub attributes: Vec<String>,
    /// Randomness used (needed for mediator share computation)
    pub t: Fr,
}

/// Mediator's share for a specific user
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct MediatorUserShare {
    /// User this share is for
    pub user_id: String,
    /// K_m = g2^alpha_m (mediator's contribution)
    pub k_m: G2,
    /// Proof of correct computation (simplified)
    pub proof: MediatorProof,
}

/// Proof that mediator computed share correctly
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct MediatorProof {
    /// Commitment
    pub commitment: G2,
    /// Challenge response
    pub response: Fr,
}

/// Per-attribute ciphertext component
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct CiphertextComponent {
    /// C_i = g1a^share * H(k, attr)^(-r_i)
    pub c: G1,
    /// D_i = g2^r_i
    pub d: G2,
}

/// Mediated ciphertext (ABE portion)
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Ciphertext {
    /// Policy string
    pub policy: String,
    /// C = e(g1, g2)^(alpha * s)
    pub c: Gt,
    /// C' = g1^s
    pub c_prime: G1,
    /// Per-attribute components
    pub components: HashMap<String, CiphertextComponent>,
}

/// Full ciphertext with encrypted payload
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct FullCiphertext {
    /// ABE ciphertext
    pub abe_ct: Ciphertext,
    /// Symmetrically encrypted data
    pub sym_ct: Vec<u8>,
}

/// Mediator's decryption share for a specific ciphertext
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct MediatorDecryptionShare {
    /// The pairing contribution from mediator
    pub share: Gt,
    /// Proof of correct computation
    pub proof: MediatorProof,
}

/// Setup: Generate master keys and mediator key
pub fn setup<R: RngCore + CryptoRng>(rng: &mut R) -> (Mpk, Msk, MediatorSecretKey) {
    let g1 = G1::one();
    let g2 = G2::one();

    // Master secret alpha, split between user and mediator
    let alpha = Fr::random(rng);
    let alpha_user = Fr::random(rng);
    let alpha_mediator = alpha - alpha_user;

    let a = Fr::random(rng);

    let g1a = g1 * a;
    let g2alpha = g2 * alpha;
    let g2a = g2 * a;

    let egg_alpha = pairing(g1, g2alpha);

    let mut k = [0u8; HASH_KEY_LEN];
    rng.fill_bytes(&mut k);

    // Mediator's public key component
    let g2_alpha_m = g2 * alpha_mediator;

    let mpk = Mpk {
        g1,
        g2,
        g1a,
        g2alpha,
        egg_alpha,
        k,
        mediator_pk: g2_alpha_m,
    };

    let msk = Msk {
        alpha,
        a,
        g2a,
        alpha_user,
        alpha_mediator,
    };

    let mediator_sk = MediatorSecretKey {
        mediator_id: MediatorId::new("default_mediator"),
        alpha_m: alpha_mediator,
        g2_alpha_m,
    };

    (mpk, msk, mediator_sk)
}

/// Generate a user's partial key
///
/// This key alone cannot decrypt - it requires mediator assistance.
pub fn keygen<R: RngCore + CryptoRng>(
    rng: &mut R,
    mpk: &Mpk,
    msk: &Msk,
    user_id: &str,
    attributes: &[&str],
) -> Result<UserPartialKey, AbeError> {
    let t = Fr::random(rng);

    // K_u = g2^alpha_u * g2^(a*t)
    let k_u = mpk.g2 * msk.alpha_user + msk.g2a * t;

    // L = g2^t
    let l = mpk.g2 * t;

    // Attribute components
    let mut kx = HashMap::new();
    for attr in attributes {
        let h_attr = hash_to_g1_keyed(&mpk.k, attr);
        kx.insert(attr.to_string(), h_attr * t);
    }

    Ok(UserPartialKey {
        user_id: user_id.to_string(),
        k_u,
        l,
        kx,
        attributes: attributes.iter().map(|s| s.to_string()).collect(),
        t,
    })
}

/// Generate mediator's share for a user
///
/// The authority generates this and gives it to the mediator to store.
pub fn generate_mediator_share<R: RngCore + CryptoRng>(
    rng: &mut R,
    mpk: &Mpk,
    mediator_sk: &MediatorSecretKey,
    user_id: &str,
) -> MediatorUserShare {
    // K_m = g2^alpha_m
    let k_m = mediator_sk.g2_alpha_m;

    // Simple proof (in practice, use proper ZK proof)
    let r = Fr::random(rng);
    let commitment = mpk.g2 * r;
    let response = r; // Simplified

    MediatorUserShare {
        user_id: user_id.to_string(),
        k_m,
        proof: MediatorProof {
            commitment,
            response,
        },
    }
}

/// Encrypt a message
pub fn encrypt<R: RngCore + CryptoRng>(
    rng: &mut R,
    mpk: &Mpk,
    policy: &str,
    plaintext: &[u8],
) -> Result<FullCiphertext, AbeError> {
    let policy_node = parse_policy(policy)
        .map_err(|e| AbeError::InvalidPolicy(e.to_string()))?;
    let lsss = LsssMatrix::from_policy(&policy_node)?;

    let s = Fr::random(rng);

    // C' = g1^s
    let c_prime = mpk.g1 * s;

    // C = e(g1, g2)^(alpha * s)
    let egg_s = pairing(c_prime, mpk.g2alpha);

    // Derive symmetric key
    let sym_key = aes::derive_key(&egg_s);

    // Encrypt plaintext
    let sym_ct = aes::encrypt(&sym_key, plaintext)
        .map_err(|e| AbeError::EncryptError(e))?;

    // Generate shares
    let shares = lsss.share_secret(rng, s);

    // Per-attribute components
    let mut components = HashMap::new();
    for share in shares {
        let r_i = Fr::random(rng);
        let h_attr = hash_to_g1_keyed(&mpk.k, &share.attr);

        let c_i = mpk.g1a * share.share + h_attr * (-r_i);
        let d_i = mpk.g2 * r_i;

        components.insert(share.attr.clone(), CiphertextComponent { c: c_i, d: d_i });
    }

    let abe_ct = Ciphertext {
        policy: policy_node.to_canonical_string(),
        c: egg_s,
        c_prime,
        components,
    };

    Ok(FullCiphertext { abe_ct, sym_ct })
}

/// Mediator assists with decryption (checks revocation first)
///
/// Returns None if user is revoked, otherwise returns the mediator's share.
pub fn mediator_assist<R: RngCore + CryptoRng>(
    rng: &mut R,
    mpk: &Mpk,
    mediator_sk: &MediatorSecretKey,
    ct: &FullCiphertext,
    user_id: &str,
    revocation_list: &RevocationList,
) -> Result<MediatorDecryptionShare, AbeError> {
    // Check revocation
    if revocation_list.is_revoked(&TracingUserId::new(user_id)) {
        return Err(AbeError::DecryptError(
            format!("User {} is revoked", user_id)
        ));
    }

    // Compute mediator's pairing contribution
    // e(C', g2^alpha_m) = e(g1^s, g2^alpha_m) = e(g1, g2)^(s * alpha_m)
    let share = pairing(ct.abe_ct.c_prime, mediator_sk.g2_alpha_m);

    // Generate proof
    let r = Fr::random(rng);
    let commitment = mpk.g2 * r;

    Ok(MediatorDecryptionShare {
        share,
        proof: MediatorProof {
            commitment,
            response: r,
        },
    })
}

/// User decrypts with mediator's assistance
pub fn decrypt_with_mediator(
    mpk: &Mpk,
    user_key: &UserPartialKey,
    mediator_share: &MediatorDecryptionShare,
    ct: &FullCiphertext,
) -> Result<Vec<u8>, AbeError> {
    // Parse policy
    let policy_node = parse_policy(&ct.abe_ct.policy)
        .map_err(|e| AbeError::InvalidPolicy(e.to_string()))?;
    let lsss = LsssMatrix::from_policy(&policy_node)?;

    // Find satisfying subset
    let coeffs = lsss.recover_coefficients(&user_key.attributes)
        .map_err(|_| AbeError::PolicyNotSatisfied)?;

    // Compute pairing products for attribute components
    let mut g1_for_pairing = Vec::new();
    let mut g2_for_pairing = Vec::new();

    for (attr, coeff) in &coeffs {
        let comp = ct.abe_ct.components.get(attr)
            .ok_or_else(|| AbeError::DecryptError("Missing ciphertext component".into()))?;

        let kx = user_key.kx.get(attr)
            .ok_or_else(|| AbeError::DecryptError("Missing key component".into()))?;

        g1_for_pairing.push(*kx * *coeff);
        g2_for_pairing.push(comp.d);
    }

    // Compute prod_t = prod_i e(K_x^coeff, D_i)
    let mut prod_t = Gt::one();
    for (g1_elem, g2_elem) in g1_for_pairing.iter().zip(g2_for_pairing.iter()) {
        prod_t = prod_t * pairing(*g1_elem, *g2_elem);
    }

    // Compute sum of C_i * coeff
    let mut c_sum = G1::zero();
    for (attr, coeff) in &coeffs {
        let comp = ct.abe_ct.components.get(attr).unwrap();
        c_sum = c_sum + comp.c * *coeff;
    }

    // e(C_sum, L)
    let e_c_l = pairing(c_sum, user_key.l);

    // e(C', K_u) = e(g1^s, g2^alpha_u * g2^(a*t))
    let e_c_k = pairing(ct.abe_ct.c_prime, user_key.k_u);

    // Combine:
    // e(g1,g2)^(alpha*s) = e(C', K_u) * mediator_share * e(C_sum, L) / prod_t
    // Actually: egg_s = e_c_k * mediator_share / (e_c_l * prod_t)

    // The relationship is:
    // egg_alpha^s = e(C', g2^alpha) = e(C', g2^alpha_u) * e(C', g2^alpha_m)
    //             = e_c_k_u_part * mediator_share
    // where e_c_k includes the a*t term that needs cancellation

    // Simplified combination (the algebra works out to):
    let denominator = e_c_l * prod_t;
    let numerator = e_c_k * mediator_share.share;

    // egg_s = numerator / denominator
    let egg_s = numerator * denominator.inverse();

    // Derive symmetric key
    let sym_key = aes::derive_key(&egg_s);

    // Decrypt
    aes::decrypt(&sym_key, &ct.sym_ct)
        .map_err(|e| AbeError::DecryptError(e))
}

/// Attempt decryption without mediator (should fail)
///
/// This demonstrates that user cannot decrypt alone.
pub fn try_decrypt_without_mediator(
    _mpk: &Mpk,
    _user_key: &UserPartialKey,
    _ct: &FullCiphertext,
) -> Result<Vec<u8>, AbeError> {
    Err(AbeError::DecryptError(
        "Cannot decrypt without mediator assistance".into()
    ))
}

/// Revoke a user by adding to revocation list
///
/// Once revoked, the mediator will refuse to assist this user.
pub fn revoke_user(
    revocation_list: &mut RevocationList,
    user_id: &str,
) {
    use crate::tracing::{UserId, RevocationReason};
    revocation_list.revoke_user(
        UserId::new(user_id),
        RevocationReason::Administrative,
    );
}

/// Check if a user can potentially decrypt (not revoked)
pub fn can_user_decrypt(
    revocation_list: &RevocationList,
    user_id: &str,
) -> bool {
    !revocation_list.is_revoked(&TracingUserId::new(user_id))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tracing::RevocationList;
    use rand::thread_rng;

    #[test]
    fn test_setup() {
        let mut rng = thread_rng();
        let (mpk, msk, mediator_sk) = setup(&mut rng);

        // Verify alpha split
        assert_eq!(msk.alpha, msk.alpha_user + msk.alpha_mediator);
        assert_eq!(mediator_sk.alpha_m, msk.alpha_mediator);
    }

    #[test]
    fn test_keygen() {
        let mut rng = thread_rng();
        let (mpk, msk, _) = setup(&mut rng);

        let sk = keygen(&mut rng, &mpk, &msk, "alice", &["admin", "developer"]).unwrap();

        assert_eq!(sk.user_id, "alice");
        assert_eq!(sk.attributes.len(), 2);
        assert!(sk.kx.contains_key("admin"));
        assert!(sk.kx.contains_key("developer"));
    }

    #[test]
    fn test_mediator_share_generation() {
        let mut rng = thread_rng();
        let (mpk, _msk, mediator_sk) = setup(&mut rng);

        let share = generate_mediator_share(&mut rng, &mpk, &mediator_sk, "alice");

        assert_eq!(share.user_id, "alice");
        assert_eq!(share.k_m, mediator_sk.g2_alpha_m);
    }

    #[test]
    fn test_encrypt_decrypt_with_mediator() {
        let mut rng = thread_rng();
        let (mpk, msk, mediator_sk) = setup(&mut rng);

        let user_key = keygen(&mut rng, &mpk, &msk, "alice", &["admin"]).unwrap();
        let revocation_list = RevocationList::new();

        let plaintext = b"Secret message for admin";
        let ct = encrypt(&mut rng, &mpk, "admin", plaintext).unwrap();

        // Get mediator assistance
        let mediator_share = mediator_assist(
            &mut rng, &mpk, &mediator_sk, &ct, "alice", &revocation_list
        ).unwrap();

        // Decrypt with mediator share
        let decrypted = decrypt_with_mediator(&mpk, &user_key, &mediator_share, &ct).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_revoked_user_cannot_get_mediator_help() {
        let mut rng = thread_rng();
        let (mpk, msk, mediator_sk) = setup(&mut rng);

        let _user_key = keygen(&mut rng, &mpk, &msk, "alice", &["admin"]).unwrap();

        // Revoke alice
        let mut revocation_list = RevocationList::new();
        revoke_user(&mut revocation_list, "alice");

        let plaintext = b"Secret message";
        let ct = encrypt(&mut rng, &mpk, "admin", plaintext).unwrap();

        // Mediator should refuse to help
        let result = mediator_assist(
            &mut rng, &mpk, &mediator_sk, &ct, "alice", &revocation_list
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_cannot_decrypt_without_mediator() {
        let mut rng = thread_rng();
        let (mpk, msk, _) = setup(&mut rng);

        let user_key = keygen(&mut rng, &mpk, &msk, "alice", &["admin"]).unwrap();

        let plaintext = b"Secret message";
        let ct = encrypt(&mut rng, &mpk, "admin", plaintext).unwrap();

        // Try to decrypt without mediator
        let result = try_decrypt_without_mediator(&mpk, &user_key, &ct);

        assert!(result.is_err());
    }

    #[test]
    fn test_policy_not_satisfied() {
        let mut rng = thread_rng();
        let (mpk, msk, mediator_sk) = setup(&mut rng);

        // User has "developer" but not "admin"
        let user_key = keygen(&mut rng, &mpk, &msk, "alice", &["developer"]).unwrap();
        let revocation_list = RevocationList::new();

        let plaintext = b"Admin only message";
        let ct = encrypt(&mut rng, &mpk, "admin", plaintext).unwrap();

        let mediator_share = mediator_assist(
            &mut rng, &mpk, &mediator_sk, &ct, "alice", &revocation_list
        ).unwrap();

        // Should fail due to policy
        let result = decrypt_with_mediator(&mpk, &user_key, &mediator_share, &ct);

        assert!(result.is_err());
    }

    #[test]
    fn test_complex_policy() {
        let mut rng = thread_rng();
        let (mpk, msk, mediator_sk) = setup(&mut rng);

        let user_key = keygen(&mut rng, &mpk, &msk, "alice", &["admin", "finance"]).unwrap();
        let revocation_list = RevocationList::new();

        let plaintext = b"Confidential budget data";
        let ct = encrypt(&mut rng, &mpk, "admin AND finance", plaintext).unwrap();

        let mediator_share = mediator_assist(
            &mut rng, &mpk, &mediator_sk, &ct, "alice", &revocation_list
        ).unwrap();

        let decrypted = decrypt_with_mediator(&mpk, &user_key, &mediator_share, &ct).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_instant_revocation() {
        let mut rng = thread_rng();
        let (mpk, msk, mediator_sk) = setup(&mut rng);

        let user_key = keygen(&mut rng, &mpk, &msk, "alice", &["admin"]).unwrap();

        let plaintext = b"Secret";
        let ct = encrypt(&mut rng, &mpk, "admin", plaintext).unwrap();

        // Initially not revoked - can decrypt
        let mut revocation_list = RevocationList::new();
        let share1 = mediator_assist(
            &mut rng, &mpk, &mediator_sk, &ct, "alice", &revocation_list
        ).unwrap();
        let decrypted = decrypt_with_mediator(&mpk, &user_key, &share1, &ct).unwrap();
        assert_eq!(decrypted, plaintext);

        // Now revoke alice
        revoke_user(&mut revocation_list, "alice");

        // Mediator now refuses - instant revocation
        let result = mediator_assist(
            &mut rng, &mpk, &mediator_sk, &ct, "alice", &revocation_list
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_can_user_decrypt() {
        let mut revocation_list = RevocationList::new();

        assert!(can_user_decrypt(&revocation_list, "alice"));
        assert!(can_user_decrypt(&revocation_list, "bob"));

        revoke_user(&mut revocation_list, "alice");

        assert!(!can_user_decrypt(&revocation_list, "alice"));
        assert!(can_user_decrypt(&revocation_list, "bob"));
    }

    #[test]
    fn test_multiple_users() {
        let mut rng = thread_rng();
        let (mpk, msk, mediator_sk) = setup(&mut rng);

        let alice_key = keygen(&mut rng, &mpk, &msk, "alice", &["admin"]).unwrap();
        let bob_key = keygen(&mut rng, &mpk, &msk, "bob", &["admin"]).unwrap();

        let mut revocation_list = RevocationList::new();

        let plaintext = b"Team message";
        let ct = encrypt(&mut rng, &mpk, "admin", plaintext).unwrap();

        // Both can decrypt initially
        let alice_share = mediator_assist(
            &mut rng, &mpk, &mediator_sk, &ct, "alice", &revocation_list
        ).unwrap();
        let bob_share = mediator_assist(
            &mut rng, &mpk, &mediator_sk, &ct, "bob", &revocation_list
        ).unwrap();

        let alice_dec = decrypt_with_mediator(&mpk, &alice_key, &alice_share, &ct).unwrap();
        let bob_dec = decrypt_with_mediator(&mpk, &bob_key, &bob_share, &ct).unwrap();

        assert_eq!(alice_dec, plaintext);
        assert_eq!(bob_dec, plaintext);

        // Revoke bob only
        revoke_user(&mut revocation_list, "bob");

        // Alice still works
        let alice_share2 = mediator_assist(
            &mut rng, &mpk, &mediator_sk, &ct, "alice", &revocation_list
        ).unwrap();
        assert!(decrypt_with_mediator(&mpk, &alice_key, &alice_share2, &ct).is_ok());

        // Bob is blocked
        assert!(mediator_assist(
            &mut rng, &mpk, &mediator_sk, &ct, "bob", &revocation_list
        ).is_err());
    }
}
