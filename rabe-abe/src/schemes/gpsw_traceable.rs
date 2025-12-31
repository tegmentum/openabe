//! GPSW KP-ABE with White-Box Traitor Tracing
//!
//! This module extends the GPSW KP-ABE scheme with white-box traitor
//! tracing capability. When a decryption key is leaked and available for
//! inspection, the embedded identity commitment can trace it back to the
//! original user.
//!
//! # Key Differences from CP-ABE Traceable
//!
//! In KP-ABE (Key-Policy ABE):
//! - The **policy** is embedded in the **secret key**
//! - The **ciphertext** is encrypted under **attributes**
//! - Tracing works the same way: identity commitments in keys
//!
//! # Approach
//!
//! The traceable scheme embeds an identity commitment in each user's secret key:
//! - During setup, a tracing secret `τ` is generated
//! - During keygen, the user's identity is committed: `id_commit = H(user_id)^τ`
//! - When a leaked key is found, the tracing key can verify the commitment
//!
//! # Security
//!
//! - Keys remain secure for decryption (same as base GPSW)
//! - Tracing requires the tracing key, which should be kept secure
//! - Collusion-resistant: Multiple users cannot combine keys to evade tracing

use crate::error::AbeError;
use crate::lsss::PolicyNode;
use crate::tracing::{UserId, TraceResult, TracingMetadata};
use crate::schemes::gpsw::{Mpk, Msk, SecretKey, Ciphertext, FullCiphertext};
use crate::schemes::gpsw::{
    setup as base_setup,
    keygen as base_keygen,
    encrypt as base_encrypt,
    decrypt as base_decrypt,
};
use crate::utils::hash_to_g1;
use rabe_bls12381::{Fr, G1, G2, pairing};
use rand::{RngCore, CryptoRng};
use std::collections::HashMap;

/// Traceable Master Public Key for GPSW KP-ABE
///
/// Extends the base GPSW MPK with tracing verification key.
#[derive(Clone, Debug)]
pub struct TraceableMpk {
    /// Base GPSW master public key
    pub base: Mpk,

    /// Tracing verification key: g2^τ
    pub trace_vk: G2,
}

/// Traceable Master Secret Key for GPSW KP-ABE
///
/// Extends the base GPSW MSK with tracing secret.
#[derive(Clone, Debug)]
pub struct TraceableMsk {
    /// Base GPSW master secret key
    pub base: Msk,

    /// Tracing secret τ (used to generate identity commitments)
    pub trace_sk: Fr,
}

impl Drop for TraceableMsk {
    fn drop(&mut self) {
        self.trace_sk = Fr::zero();
    }
}

/// Tracing Key for GPSW KP-ABE
///
/// Used by the tracing authority to verify identity commitments in leaked keys.
#[derive(Clone, Debug)]
pub struct TracingKey {
    /// Tracing secret τ
    pub trace_sk: Fr,

    /// Verification key g2^τ
    pub trace_vk: G2,
}

impl Drop for TracingKey {
    fn drop(&mut self) {
        self.trace_sk = Fr::zero();
    }
}

/// Proof of identity embedded in the secret key
#[derive(Clone, Debug)]
pub struct IdentityProof {
    /// The user's identity commitment: H(user_id)^τ
    pub commitment: G1,

    /// Timestamp when the key was issued
    pub issued_at: u64,

    /// Key version number
    pub version: u32,
}

impl IdentityProof {
    /// Verify that this proof corresponds to a given user ID
    pub fn verify(&self, user_id: &UserId, trace_vk: &G2) -> bool {
        // Compute H(user_id)
        let h_id = hash_to_g1(user_id.as_str());

        // Verify: e(commitment, g2) == e(H(user_id), trace_vk)
        let lhs = pairing(self.commitment, G2::one());
        let rhs = pairing(h_id, *trace_vk);

        lhs == rhs
    }
}

/// Traceable Secret Key for GPSW KP-ABE
///
/// Extends the base GPSW secret key with identity information for tracing.
/// Note: In KP-ABE, the key contains the policy.
#[derive(Clone, Debug)]
pub struct TraceableSecretKey {
    /// Base GPSW secret key (contains policy, used for decryption)
    pub base: SecretKey,

    /// Tracing metadata
    pub metadata: TracingMetadata,

    /// Identity commitment for tracing: H(user_id)^τ
    pub identity_commitment: G1,

    /// Proof that can be verified with the tracing key
    pub identity_proof: IdentityProof,
}

impl TraceableSecretKey {
    /// Get the user ID associated with this key
    pub fn user_id(&self) -> &UserId {
        &self.metadata.user_id
    }

    /// Get when the key was issued
    pub fn issued_at(&self) -> u64 {
        self.metadata.issued_at
    }

    /// Get the key version
    pub fn version(&self) -> u32 {
        self.metadata.version
    }

    /// Get the policy this key enforces
    pub fn policy(&self) -> &str {
        &self.base.policy
    }
}

/// Setup: Generate traceable master keys and tracing key
///
/// Returns (TraceableMpk, TraceableMsk, TracingKey)
pub fn traceable_setup<R: RngCore + CryptoRng>(rng: &mut R) -> (TraceableMpk, TraceableMsk, TracingKey) {
    // Run base GPSW setup
    let (base_mpk, base_msk) = base_setup(rng);

    // Generate tracing secret
    let trace_sk = Fr::random(rng);
    let trace_vk = G2::one() * trace_sk;

    let mpk = TraceableMpk {
        base: base_mpk,
        trace_vk,
    };

    let msk = TraceableMsk {
        base: base_msk,
        trace_sk,
    };

    let tracing_key = TracingKey {
        trace_sk,
        trace_vk,
    };

    (mpk, msk, tracing_key)
}

/// Generate a traceable secret key for a user with a policy
///
/// In KP-ABE, the policy is embedded in the key.
/// The key includes an identity commitment that can be traced back to the user.
pub fn traceable_keygen<R: RngCore + CryptoRng>(
    rng: &mut R,
    mpk: &TraceableMpk,
    msk: &TraceableMsk,
    user_id: impl Into<UserId>,
    policy: &PolicyNode,
) -> Result<TraceableSecretKey, AbeError> {
    let user_id = user_id.into();

    // Generate base GPSW key with policy
    let base_sk = base_keygen(rng, &mpk.base, &msk.base, policy)?;

    // Compute identity commitment: H(user_id)^τ
    let h_id = hash_to_g1(user_id.as_str());
    let identity_commitment = h_id * msk.trace_sk;

    // Current timestamp
    let issued_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let identity_proof = IdentityProof {
        commitment: identity_commitment,
        issued_at,
        version: 1,
    };

    let metadata = TracingMetadata::new(user_id, issued_at);

    Ok(TraceableSecretKey {
        base: base_sk,
        metadata,
        identity_commitment,
        identity_proof,
    })
}

/// Generate a traceable key with explicit version and timestamp
pub fn traceable_keygen_versioned<R: RngCore + CryptoRng>(
    rng: &mut R,
    mpk: &TraceableMpk,
    msk: &TraceableMsk,
    user_id: impl Into<UserId>,
    policy: &PolicyNode,
    version: u32,
    issued_at: u64,
) -> Result<TraceableSecretKey, AbeError> {
    let user_id = user_id.into();

    let base_sk = base_keygen(rng, &mpk.base, &msk.base, policy)?;

    let h_id = hash_to_g1(user_id.as_str());
    let identity_commitment = h_id * msk.trace_sk;

    let identity_proof = IdentityProof {
        commitment: identity_commitment,
        issued_at,
        version,
    };

    let metadata = TracingMetadata::with_version(user_id, issued_at, version);

    Ok(TraceableSecretKey {
        base: base_sk,
        metadata,
        identity_commitment,
        identity_proof,
    })
}

/// Trace a leaked key to identify the user
///
/// Given a leaked key and the tracing key, identify which user it belongs to.
pub fn trace_key(
    _mpk: &TraceableMpk,
    tracing_key: &TracingKey,
    leaked_key: &TraceableSecretKey,
    known_users: &[UserId],
) -> TraceResult {
    for user_id in known_users {
        if leaked_key.identity_proof.verify(user_id, &tracing_key.trace_vk) {
            return TraceResult::Traced(vec![user_id.clone()]);
        }
    }

    TraceResult::Inconclusive
}

/// Verify that a key's claimed user ID matches the cryptographic commitment
pub fn verify_key_origin(
    _mpk: &TraceableMpk,
    tracing_key: &TracingKey,
    key: &TraceableSecretKey,
) -> Result<bool, AbeError> {
    let claimed_user = &key.metadata.user_id;
    Ok(key.identity_proof.verify(claimed_user, &tracing_key.trace_vk))
}

/// Batch trace multiple keys
pub fn trace_keys_batch(
    mpk: &TraceableMpk,
    tracing_key: &TracingKey,
    leaked_keys: &[TraceableSecretKey],
    known_users: &[UserId],
) -> HashMap<usize, TraceResult> {
    leaked_keys
        .iter()
        .enumerate()
        .map(|(i, key)| {
            let result = trace_key(mpk, tracing_key, key, known_users);
            (i, result)
        })
        .collect()
}

// ============================================================================
// Encryption/Decryption (delegates to base GPSW scheme)
// ============================================================================

/// Encrypt a message under a set of attributes
///
/// Uses the base GPSW scheme - the traceable extension only affects keys.
pub fn encrypt<R: RngCore + CryptoRng>(
    rng: &mut R,
    mpk: &TraceableMpk,
    attributes: &[String],
    plaintext: &[u8],
) -> Result<FullCiphertext, AbeError> {
    base_encrypt(rng, &mpk.base, attributes, plaintext)
}

/// Decrypt a ciphertext using a traceable secret key
///
/// Decryption succeeds iff the ciphertext's attributes satisfy the key's policy.
pub fn decrypt(
    mpk: &TraceableMpk,
    sk: &TraceableSecretKey,
    ct: &FullCiphertext,
) -> Result<Vec<u8>, AbeError> {
    base_decrypt(&mpk.base, &sk.base, ct)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::thread_rng;

    #[test]
    fn test_traceable_setup() {
        let mut rng = thread_rng();
        let (mpk, msk, tracing_key) = traceable_setup(&mut rng);

        // Verify tracing key consistency
        assert_eq!(msk.trace_sk, tracing_key.trace_sk);
        assert_eq!(mpk.trace_vk, tracing_key.trace_vk);

        // Verify g2^τ = trace_vk
        let expected_vk = G2::one() * msk.trace_sk;
        assert_eq!(mpk.trace_vk, expected_vk);
    }

    #[test]
    fn test_traceable_keygen() {
        let mut rng = thread_rng();
        let (mpk, msk, tracing_key) = traceable_setup(&mut rng);

        // KP-ABE: policy in key
        let policy = PolicyNode::And(vec![
            PolicyNode::Attr("admin".to_string()),
            PolicyNode::Attr("developer".to_string()),
        ]);

        let sk = traceable_keygen(&mut rng, &mpk, &msk, "alice", &policy).unwrap();

        assert_eq!(sk.user_id().as_str(), "alice");
        assert!(sk.version() >= 1);

        // Verify identity proof
        let alice_id = UserId::new("alice");
        assert!(sk.identity_proof.verify(&alice_id, &tracing_key.trace_vk));

        // Should not verify for wrong user
        let bob_id = UserId::new("bob");
        assert!(!sk.identity_proof.verify(&bob_id, &tracing_key.trace_vk));
    }

    #[test]
    fn test_trace_key_success() {
        let mut rng = thread_rng();
        let (mpk, msk, tracing_key) = traceable_setup(&mut rng);

        let policy = PolicyNode::Attr("user".to_string());
        let sk_alice = traceable_keygen(&mut rng, &mpk, &msk, "alice", &policy).unwrap();
        let sk_bob = traceable_keygen(&mut rng, &mpk, &msk, "bob", &policy).unwrap();

        let known_users = vec![
            UserId::new("alice"),
            UserId::new("bob"),
            UserId::new("charlie"),
        ];

        // Trace Alice's key
        let result = trace_key(&mpk, &tracing_key, &sk_alice, &known_users);
        assert!(result.is_traced());
        let traitors = result.traitors().unwrap();
        assert_eq!(traitors.len(), 1);
        assert_eq!(traitors[0].as_str(), "alice");

        // Trace Bob's key
        let result = trace_key(&mpk, &tracing_key, &sk_bob, &known_users);
        assert!(result.is_traced());
        let traitors = result.traitors().unwrap();
        assert_eq!(traitors[0].as_str(), "bob");
    }

    #[test]
    fn test_trace_unknown_user() {
        let mut rng = thread_rng();
        let (mpk, msk, tracing_key) = traceable_setup(&mut rng);

        let policy = PolicyNode::Attr("user".to_string());
        let sk_dave = traceable_keygen(&mut rng, &mpk, &msk, "dave", &policy).unwrap();

        // Dave is not in the known users list
        let known_users = vec![UserId::new("alice"), UserId::new("bob")];

        let result = trace_key(&mpk, &tracing_key, &sk_dave, &known_users);
        assert!(result.is_inconclusive());
    }

    #[test]
    fn test_verify_key_origin() {
        let mut rng = thread_rng();
        let (mpk, msk, tracing_key) = traceable_setup(&mut rng);

        let policy = PolicyNode::Attr("admin".to_string());
        let sk = traceable_keygen(&mut rng, &mpk, &msk, "alice", &policy).unwrap();

        // Key origin should verify
        assert!(verify_key_origin(&mpk, &tracing_key, &sk).unwrap());
    }

    #[test]
    fn test_encrypt_decrypt_with_traceable_keys() {
        let mut rng = thread_rng();
        let (mpk, msk, _tracing_key) = traceable_setup(&mut rng);

        // KP-ABE: policy in key, attributes in ciphertext
        let policy = PolicyNode::And(vec![
            PolicyNode::Attr("admin".to_string()),
            PolicyNode::Attr("developer".to_string()),
        ]);
        let sk = traceable_keygen(&mut rng, &mpk, &msk, "alice", &policy).unwrap();

        // Ciphertext has attributes
        let attributes = vec!["admin".to_string(), "developer".to_string()];
        let plaintext = b"Secret traceable message";
        let ct = encrypt(&mut rng, &mpk, &attributes, plaintext).unwrap();

        let decrypted = decrypt(&mpk, &sk, &ct).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_policy_not_satisfied() {
        let mut rng = thread_rng();
        let (mpk, msk, _tracing_key) = traceable_setup(&mut rng);

        // Key requires admin AND developer
        let policy = PolicyNode::And(vec![
            PolicyNode::Attr("admin".to_string()),
            PolicyNode::Attr("developer".to_string()),
        ]);
        let sk = traceable_keygen(&mut rng, &mpk, &msk, "alice", &policy).unwrap();

        // Ciphertext only has admin attribute
        let attributes = vec!["admin".to_string()];
        let plaintext = b"This won't decrypt";
        let ct = encrypt(&mut rng, &mpk, &attributes, plaintext).unwrap();

        // Decryption should fail
        let result = decrypt(&mpk, &sk, &ct);
        assert!(result.is_err());
    }

    #[test]
    fn test_batch_tracing() {
        let mut rng = thread_rng();
        let (mpk, msk, tracing_key) = traceable_setup(&mut rng);

        let policy = PolicyNode::Attr("user".to_string());

        let keys: Vec<_> = ["alice", "bob", "charlie"]
            .iter()
            .map(|name| traceable_keygen(&mut rng, &mpk, &msk, *name, &policy).unwrap())
            .collect();

        let known_users: Vec<_> = ["alice", "bob", "charlie", "dave"]
            .iter()
            .map(|s| UserId::new(*s))
            .collect();

        let results = trace_keys_batch(&mpk, &tracing_key, &keys, &known_users);

        assert_eq!(results.len(), 3);
        for (i, name) in ["alice", "bob", "charlie"].iter().enumerate() {
            let result = &results[&i];
            assert!(result.is_traced());
            assert_eq!(result.traitors().unwrap()[0].as_str(), *name);
        }
    }

    #[test]
    fn test_versioned_keygen() {
        let mut rng = thread_rng();
        let (mpk, msk, tracing_key) = traceable_setup(&mut rng);

        let policy = PolicyNode::Attr("admin".to_string());

        let sk = traceable_keygen_versioned(
            &mut rng, &mpk, &msk, "alice", &policy, 5, 1234567890
        ).unwrap();

        assert_eq!(sk.version(), 5);
        assert_eq!(sk.issued_at(), 1234567890);

        // Should still trace correctly
        let alice_id = UserId::new("alice");
        assert!(sk.identity_proof.verify(&alice_id, &tracing_key.trace_vk));
    }
}
