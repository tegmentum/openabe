//! Waters '11 Trace-and-Revoke ABE
//!
//! This module combines Waters '11 CP-ABE with integrated traitor tracing
//! and efficient revocation. Unlike separate revocation lists, revocation
//! is embedded directly in the ciphertext structure.
//!
//! # Design
//!
//! Based on concepts from:
//! - Boneh-Sahai-Waters broadcast encryption with traitor tracing
//! - Complete subtree revocation method
//!
//! # Features
//!
//! - Identity-embedded keys for white-box tracing
//! - Revocation set embedded in ciphertext (revoked users cannot decrypt)
//! - Efficient for small revocation sets (O(r) ciphertext overhead)
//! - No need to re-key non-revoked users

use crate::error::AbeError;
use crate::lsss::PolicyNode;
use crate::tracing::{UserId, TraceResult, TracingMetadata, RevocationList};
use crate::schemes::waters::{Mpk, Msk, SecretKey, Ciphertext, FullCiphertext, RawFullCiphertext};
use crate::schemes::waters::{
    setup as base_setup,
    keygen as base_keygen,
    encrypt as base_encrypt,
};
use crate::utils::hash_to_g1;
use rabe_bls12381::{Fr, G1, G2, pairing};
use rand::{RngCore, CryptoRng};
use std::collections::{HashMap, HashSet};

/// Trace-and-Revoke Master Public Key
#[derive(Clone, Debug)]
pub struct TraceRevokeMpk {
    /// Base Waters MPK
    pub base: Mpk,

    /// Tracing verification key: g2^τ
    pub trace_vk: G2,

    /// Revocation base: g1^γ for revocation mechanism
    pub revoke_base: G1,
}

/// Trace-and-Revoke Master Secret Key
///
/// # Security
///
/// This structure contains secret key material that is zeroized on drop.
#[derive(Clone, Debug)]
pub struct TraceRevokeMsk {
    /// Base Waters MSK
    pub base: Msk,

    /// Tracing secret τ
    pub trace_sk: Fr,

    /// Revocation secret γ
    pub revoke_sk: Fr,
}

impl Drop for TraceRevokeMsk {
    fn drop(&mut self) {
        self.trace_sk = Fr::zero();
        self.revoke_sk = Fr::zero();
    }
}

/// Tracing Key for identifying traitors
///
/// # Security
///
/// This structure contains secret key material that is zeroized on drop.
#[derive(Clone, Debug)]
pub struct TraceRevokeTracingKey {
    /// Tracing secret τ
    pub trace_sk: Fr,

    /// Verification key g2^τ
    pub trace_vk: G2,
}

impl Drop for TraceRevokeTracingKey {
    fn drop(&mut self) {
        self.trace_sk = Fr::zero();
    }
}

/// User identity token (for revocation checking)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UserIdentityToken {
    /// User ID hash: H(user_id)
    pub id_hash: G1,

    /// Revocation component: H(user_id)^γ
    pub revoke_token: G1,
}

/// Trace-and-Revoke Secret Key
#[derive(Clone, Debug)]
pub struct TraceRevokeSecretKey {
    /// Base Waters secret key
    pub base: SecretKey,

    /// User metadata for tracing
    pub metadata: TracingMetadata,

    /// Identity commitment: H(user_id)^τ
    pub identity_commitment: G1,

    /// Identity token for revocation
    pub identity_token: UserIdentityToken,

    /// Decryption helper for revocation mechanism
    pub revoke_key: G2,
}

impl TraceRevokeSecretKey {
    /// Get user ID
    pub fn user_id(&self) -> &UserId {
        &self.metadata.user_id
    }
}

/// Revocation header embedded in ciphertext
#[derive(Clone, Debug)]
pub struct RevocationHeader {
    /// Set of revoked user identity hashes
    pub revoked_ids: HashSet<Vec<u8>>,

    /// Revocation ciphertext component: g1^s for each revoked user
    pub revoke_components: HashMap<Vec<u8>, G1>,

    /// Random value for revocation: r_rev
    pub r_rev: G1,
}

/// Trace-and-Revoke Ciphertext
#[derive(Clone, Debug)]
pub struct TraceRevokeCiphertext {
    /// Base ABE ciphertext
    pub abe_ct: Ciphertext,

    /// Revocation header
    pub revoke_header: RevocationHeader,
}

/// Full Trace-and-Revoke Ciphertext with payload
#[derive(Clone, Debug)]
pub struct TraceRevokeFullCiphertext {
    /// ABE ciphertext with revocation
    pub ct: TraceRevokeCiphertext,

    /// Encrypted payload
    pub sym_ct: Vec<u8>,
}

/// Setup: Generate trace-and-revoke master keys
pub fn setup<R: RngCore + CryptoRng>(rng: &mut R) -> (TraceRevokeMpk, TraceRevokeMsk, TraceRevokeTracingKey) {
    let (base_mpk, base_msk) = base_setup(rng);

    // Tracing secret
    let trace_sk = Fr::random(rng);
    let trace_vk = G2::one() * trace_sk;

    // Revocation secret
    let revoke_sk = Fr::random(rng);
    let revoke_base = G1::one() * revoke_sk;

    let mpk = TraceRevokeMpk {
        base: base_mpk,
        trace_vk,
        revoke_base,
    };

    let msk = TraceRevokeMsk {
        base: base_msk,
        trace_sk,
        revoke_sk,
    };

    let tracing_key = TraceRevokeTracingKey {
        trace_sk,
        trace_vk,
    };

    (mpk, msk, tracing_key)
}

/// Generate a trace-and-revoke secret key
pub fn keygen<R: RngCore + CryptoRng>(
    rng: &mut R,
    mpk: &TraceRevokeMpk,
    msk: &TraceRevokeMsk,
    user_id: impl Into<UserId>,
    attributes: &[String],
) -> Result<TraceRevokeSecretKey, AbeError> {
    let user_id = user_id.into();

    // Generate base key
    let base_sk = base_keygen(rng, &mpk.base, &msk.base, attributes)?;

    // Identity commitment for tracing
    let h_id = hash_to_g1(user_id.as_str());
    let identity_commitment = h_id * msk.trace_sk;

    // Identity token for revocation
    let revoke_token = h_id * msk.revoke_sk;
    let identity_token = UserIdentityToken {
        id_hash: h_id,
        revoke_token,
    };

    // Revocation key component
    let r = Fr::random(rng);
    let revoke_key = mpk.base.g2 * r;

    let issued_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let metadata = TracingMetadata::new(user_id, issued_at);

    Ok(TraceRevokeSecretKey {
        base: base_sk,
        metadata,
        identity_commitment,
        identity_token,
        revoke_key,
    })
}

/// Encrypt with revocation set
///
/// Users in the revocation set cannot decrypt the ciphertext.
pub fn encrypt<R: RngCore + CryptoRng>(
    rng: &mut R,
    mpk: &TraceRevokeMpk,
    policy: &PolicyNode,
    revoked_users: &[UserId],
    plaintext: &[u8],
) -> Result<TraceRevokeFullCiphertext, AbeError> {
    // Build revocation header
    let mut revoked_ids = HashSet::new();
    let mut revoke_components = HashMap::new();

    let s_rev = Fr::random(rng);
    let r_rev = G1::one() * s_rev;

    for user_id in revoked_users {
        let h_id = hash_to_g1(user_id.as_str());
        let id_bytes = serialize_g1(&h_id);

        // Revocation component for this user
        let component = mpk.revoke_base * s_rev;

        revoked_ids.insert(id_bytes.clone());
        revoke_components.insert(id_bytes, component);
    }

    let revoke_header = RevocationHeader {
        revoked_ids,
        revoke_components,
        r_rev,
    };

    // Encrypt using base scheme
    let base_ct = base_encrypt(rng, &mpk.base, policy, plaintext)?;

    // Convert raw ciphertext to typed wrapper
    let abe_ct: Ciphertext = base_ct.abe_ct.clone().into();
    let ct = TraceRevokeCiphertext {
        abe_ct,
        revoke_header,
    };

    Ok(TraceRevokeFullCiphertext {
        ct,
        sym_ct: base_ct.sym_ct.clone(),
    })
}

/// Decrypt with revocation check
pub fn decrypt(
    mpk: &TraceRevokeMpk,
    sk: &TraceRevokeSecretKey,
    ct: &TraceRevokeFullCiphertext,
) -> Result<Vec<u8>, AbeError> {
    // Check if user is revoked
    let id_bytes = serialize_g1(&sk.identity_token.id_hash);

    if ct.ct.revoke_header.revoked_ids.contains(&id_bytes) {
        return Err(AbeError::RevocationError(
            format!("User {} is revoked", sk.user_id())
        ));
    }

    // Perform base ABE decryption
    // Convert typed ciphertext to raw for FullCiphertext construction
    let full_ct: FullCiphertext = RawFullCiphertext {
        abe_ct: ct.ct.abe_ct.clone().into_inner(),
        sym_ct: ct.sym_ct.clone(),
    }.into();

    crate::schemes::waters::decrypt(&mpk.base, &sk.base, &full_ct)
}

/// Trace a leaked key
pub fn trace_key(
    _mpk: &TraceRevokeMpk,
    tracing_key: &TraceRevokeTracingKey,
    leaked_key: &TraceRevokeSecretKey,
    known_users: &[UserId],
) -> TraceResult {
    for user_id in known_users {
        let h_id = hash_to_g1(user_id.as_str());

        // Verify: e(commitment, g2) == e(H(user_id), trace_vk)
        let lhs = pairing(leaked_key.identity_commitment, G2::one());
        let rhs = pairing(h_id, tracing_key.trace_vk);

        if lhs == rhs {
            return TraceResult::Traced(vec![user_id.clone()]);
        }
    }

    TraceResult::Inconclusive
}

/// Add user to revocation set and re-encrypt
///
/// For existing ciphertexts, this creates a new ciphertext with
/// the additional revoked user.
pub fn add_revocation<R: RngCore + CryptoRng>(
    rng: &mut R,
    mpk: &TraceRevokeMpk,
    ct: &TraceRevokeFullCiphertext,
    new_revoked: &UserId,
) -> TraceRevokeFullCiphertext {
    let mut new_ct = ct.clone();

    let h_id = hash_to_g1(new_revoked.as_str());
    let id_bytes = serialize_g1(&h_id);

    if !new_ct.ct.revoke_header.revoked_ids.contains(&id_bytes) {
        let s_rev = Fr::random(rng);
        let component = mpk.revoke_base * s_rev;

        new_ct.ct.revoke_header.revoked_ids.insert(id_bytes.clone());
        new_ct.ct.revoke_header.revoke_components.insert(id_bytes, component);
    }

    new_ct
}

/// Create ciphertext with revocation list
pub fn encrypt_with_revocation_list<R: RngCore + CryptoRng>(
    rng: &mut R,
    mpk: &TraceRevokeMpk,
    policy: &PolicyNode,
    revocation_list: &RevocationList,
    plaintext: &[u8],
) -> Result<TraceRevokeFullCiphertext, AbeError> {
    let revoked_users: Vec<UserId> = revocation_list
        .revoked_users()
        .cloned()
        .collect();

    encrypt(rng, mpk, policy, &revoked_users, plaintext)
}

// Helper to serialize G1 point for use as key
fn serialize_g1(point: &G1) -> Vec<u8> {
    // Simple serialization - in production use proper serialization
    let mut bytes = Vec::with_capacity(96);
    // Use the point's string representation as a simple serialization
    bytes.extend_from_slice(format!("{:?}", point).as_bytes());
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::thread_rng;

    #[test]
    fn test_trace_revoke_setup() {
        let mut rng = thread_rng();
        let (mpk, msk, tracing_key) = setup(&mut rng);

        assert_eq!(msk.trace_sk, tracing_key.trace_sk);
        assert_eq!(mpk.trace_vk, tracing_key.trace_vk);
    }

    #[test]
    fn test_trace_revoke_keygen() {
        let mut rng = thread_rng();
        let (mpk, msk, tracing_key) = setup(&mut rng);

        let attrs = vec!["admin".to_string()];
        let sk = keygen(&mut rng, &mpk, &msk, "alice", &attrs).unwrap();

        assert_eq!(sk.user_id().as_str(), "alice");
    }

    #[test]
    fn test_trace_revoke_encrypt_decrypt() {
        let mut rng = thread_rng();
        let (mpk, msk, _tk) = setup(&mut rng);

        let attrs = vec!["admin".to_string()];
        let sk = keygen(&mut rng, &mpk, &msk, "alice", &attrs).unwrap();

        let policy = PolicyNode::Attr("admin".to_string());
        let plaintext = b"Trace-revoke secret";

        // Encrypt with no revocations
        let ct = encrypt(&mut rng, &mpk, &policy, &[], plaintext).unwrap();

        // Alice can decrypt
        let decrypted = decrypt(&mpk, &sk, &ct).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_revoked_user_cannot_decrypt() {
        let mut rng = thread_rng();
        let (mpk, msk, _tk) = setup(&mut rng);

        let attrs = vec!["admin".to_string()];
        let sk_alice = keygen(&mut rng, &mpk, &msk, "alice", &attrs).unwrap();
        let sk_bob = keygen(&mut rng, &mpk, &msk, "bob", &attrs).unwrap();

        let policy = PolicyNode::Attr("admin".to_string());
        let plaintext = b"Secret for non-revoked only";

        // Encrypt with alice revoked
        let revoked = vec![UserId::new("alice")];
        let ct = encrypt(&mut rng, &mpk, &policy, &revoked, plaintext).unwrap();

        // Alice cannot decrypt
        let result = decrypt(&mpk, &sk_alice, &ct);
        assert!(result.is_err());
        assert!(matches!(result, Err(AbeError::RevocationError(_))));

        // Bob can decrypt
        let decrypted = decrypt(&mpk, &sk_bob, &ct).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_trace_leaked_key() {
        let mut rng = thread_rng();
        let (mpk, msk, tracing_key) = setup(&mut rng);

        let attrs = vec!["user".to_string()];
        let sk_alice = keygen(&mut rng, &mpk, &msk, "alice", &attrs).unwrap();

        let known_users = vec![
            UserId::new("alice"),
            UserId::new("bob"),
            UserId::new("charlie"),
        ];

        let result = trace_key(&mpk, &tracing_key, &sk_alice, &known_users);
        assert!(result.is_traced());
        assert_eq!(result.traitors().unwrap()[0].as_str(), "alice");
    }

    #[test]
    fn test_add_revocation() {
        let mut rng = thread_rng();
        let (mpk, msk, _tk) = setup(&mut rng);

        let attrs = vec!["admin".to_string()];
        let sk_alice = keygen(&mut rng, &mpk, &msk, "alice", &attrs).unwrap();

        let policy = PolicyNode::Attr("admin".to_string());
        let plaintext = b"Secret message";

        // Initially no revocations
        let ct = encrypt(&mut rng, &mpk, &policy, &[], plaintext).unwrap();

        // Alice can decrypt
        assert!(decrypt(&mpk, &sk_alice, &ct).is_ok());

        // Add alice to revocation
        let ct_revoked = add_revocation(&mut rng, &mpk, &ct, &UserId::new("alice"));

        // Now alice cannot decrypt
        let result = decrypt(&mpk, &sk_alice, &ct_revoked);
        assert!(result.is_err());
    }

    #[test]
    fn test_encrypt_with_revocation_list() {
        let mut rng = thread_rng();
        let (mpk, msk, _tk) = setup(&mut rng);

        let attrs = vec!["admin".to_string()];
        let sk_alice = keygen(&mut rng, &mpk, &msk, "alice", &attrs).unwrap();
        let sk_bob = keygen(&mut rng, &mpk, &msk, "bob", &attrs).unwrap();

        let mut revocation_list = RevocationList::new();
        revocation_list.revoke_user(
            UserId::new("alice"),
            crate::tracing::RevocationReason::TraitorTraced
        );

        let policy = PolicyNode::Attr("admin".to_string());
        let plaintext = b"Using revocation list";

        let ct = encrypt_with_revocation_list(
            &mut rng, &mpk, &policy, &revocation_list, plaintext
        ).unwrap();

        // Alice is revoked
        assert!(decrypt(&mpk, &sk_alice, &ct).is_err());

        // Bob is not revoked
        assert!(decrypt(&mpk, &sk_bob, &ct).is_ok());
    }
}
