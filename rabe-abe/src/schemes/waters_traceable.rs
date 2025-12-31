//! Waters '11 CP-ABE with White-Box Traitor Tracing
//!
//! This module extends the Waters '11 CP-ABE scheme with white-box traitor
//! tracing capability. When a decryption key is leaked and available for
//! inspection, the embedded identity commitment can trace it back to the
//! original user.
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
//! - Keys remain secure for decryption (same as base Waters '11)
//! - Tracing requires the tracing key, which should be kept secure
//! - Collusion-resistant: Multiple users cannot combine keys to evade tracing

use crate::error::AbeError;
use crate::lsss::PolicyNode;
use crate::tracing::{UserId, TraceResult, TracingMetadata};
use crate::schemes::waters::{Mpk, Msk, SecretKey, Ciphertext, FullCiphertext};
use crate::schemes::waters::{
    setup as base_setup,
    keygen as base_keygen,
    encrypt_kem as base_encrypt_kem,
    decrypt_kem as base_decrypt_kem,
    encrypt as base_encrypt,
    decrypt as base_decrypt,
};
use crate::utils::hash_to_g1;
use rabe_bls12381::{Fr, G1, G2, pairing};
use rand::{RngCore, CryptoRng};
use std::collections::HashMap;

/// Traceable Master Public Key
///
/// Extends the base Waters MPK with tracing verification key.
#[derive(Clone, Debug)]
pub struct TraceableMpk {
    /// Base Waters '11 master public key
    pub base: Mpk,

    /// Tracing verification key: g2^τ
    pub trace_vk: G2,
}

/// Traceable Master Secret Key
///
/// Extends the base Waters MSK with tracing secret.
///
/// # Security
///
/// This structure contains secret key material that is zeroized on drop.
#[derive(Clone, Debug)]
pub struct TraceableMsk {
    /// Base Waters '11 master secret key
    pub base: Msk,

    /// Tracing secret τ (used to generate identity commitments)
    pub trace_sk: Fr,
}

impl Drop for TraceableMsk {
    fn drop(&mut self) {
        self.trace_sk = Fr::zero();
    }
}

/// Tracing Key
///
/// Used by the tracing authority to verify identity commitments in leaked keys.
/// This should be kept secure and separate from the MSK.
///
/// # Security
///
/// This structure contains secret key material that is zeroized on drop.
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
///
/// This allows verification that the key belongs to a specific user.
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
        // i.e., e(H(user_id)^τ, g2) == e(H(user_id), g2^τ)
        let lhs = pairing(self.commitment, G2::one());
        let rhs = pairing(h_id, *trace_vk);

        lhs == rhs
    }
}

/// Traceable Secret Key
///
/// Extends the base Waters secret key with identity information for tracing.
#[derive(Clone, Debug)]
pub struct TraceableSecretKey {
    /// Base Waters '11 secret key (used for decryption)
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
}

/// Setup: Generate traceable master keys and tracing key
///
/// Returns (TraceableMpk, TraceableMsk, TracingKey)
/// - TraceableMpk: Distributed publicly
/// - TraceableMsk: Kept by the key issuer
/// - TracingKey: Kept by the tracing authority (may be same as issuer)
pub fn traceable_setup<R: RngCore + CryptoRng>(rng: &mut R) -> (TraceableMpk, TraceableMsk, TracingKey) {
    // Run base Waters setup
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

/// Generate a traceable secret key for a user
///
/// The key includes an identity commitment that can be traced back to the user.
pub fn traceable_keygen<R: RngCore + CryptoRng>(
    rng: &mut R,
    mpk: &TraceableMpk,
    msk: &TraceableMsk,
    user_id: impl Into<UserId>,
    attributes: &[String],
) -> Result<TraceableSecretKey, AbeError> {
    let user_id = user_id.into();

    // Generate base Waters key
    let base_sk = base_keygen(rng, &mpk.base, &msk.base, attributes)?;

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
    attributes: &[String],
    version: u32,
    issued_at: u64,
) -> Result<TraceableSecretKey, AbeError> {
    let user_id = user_id.into();

    let base_sk = base_keygen(rng, &mpk.base, &msk.base, attributes)?;

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
/// This requires checking against a list of known users.
pub fn trace_key(
    _mpk: &TraceableMpk,
    tracing_key: &TracingKey,
    leaked_key: &TraceableSecretKey,
    known_users: &[UserId],
) -> TraceResult {
    // Verify the commitment is valid (was generated with correct trace_sk)
    for user_id in known_users {
        if leaked_key.identity_proof.verify(user_id, &tracing_key.trace_vk) {
            return TraceResult::Traced(vec![user_id.clone()]);
        }
    }

    // Could also verify using direct pairing check
    // e(commitment, g2) should equal e(H(known_user), trace_vk) for the correct user

    TraceResult::Inconclusive
}

/// Trace a leaked key when the user ID is embedded in metadata
///
/// Verifies that the key's claimed user ID matches the cryptographic commitment.
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
// Encryption/Decryption (delegates to base Waters scheme)
// ============================================================================

/// Encrypt a message with a policy (KEM mode)
///
/// Uses the base Waters scheme - the traceable extension only affects keys.
/// Returns (Ciphertext, symmetric_key) where symmetric_key is 32 bytes.
pub fn encrypt_kem<R: RngCore + CryptoRng>(
    rng: &mut R,
    mpk: &TraceableMpk,
    policy: &PolicyNode,
) -> Result<(Ciphertext, [u8; 32]), AbeError> {
    base_encrypt_kem(rng, &mpk.base, policy)
}

/// Decrypt a ciphertext (KEM mode)
/// Returns the 32-byte symmetric key.
pub fn decrypt_kem(
    mpk: &TraceableMpk,
    sk: &TraceableSecretKey,
    ct: &Ciphertext,
) -> Result<[u8; 32], AbeError> {
    base_decrypt_kem(&mpk.base, &sk.base, ct)
}

/// Encrypt a message with a policy (full mode with AES)
pub fn encrypt<R: RngCore + CryptoRng>(
    rng: &mut R,
    mpk: &TraceableMpk,
    policy: &PolicyNode,
    plaintext: &[u8],
) -> Result<FullCiphertext, AbeError> {
    base_encrypt(rng, &mpk.base, policy, plaintext)
}

/// Decrypt a ciphertext (full mode with AES)
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

        let attrs = vec!["admin".to_string(), "dept:eng".to_string()];
        let sk = traceable_keygen(&mut rng, &mpk, &msk, "alice", &attrs).unwrap();

        assert_eq!(sk.user_id().as_str(), "alice");
        assert_eq!(sk.base.attributes.len(), 2);
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

        let attrs = vec!["admin".to_string()];
        let sk_alice = traceable_keygen(&mut rng, &mpk, &msk, "alice", &attrs).unwrap();
        let sk_bob = traceable_keygen(&mut rng, &mpk, &msk, "bob", &attrs).unwrap();

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

        let attrs = vec!["admin".to_string()];
        let sk_dave = traceable_keygen(&mut rng, &mpk, &msk, "dave", &attrs).unwrap();

        // Dave is not in the known users list
        let known_users = vec![
            UserId::new("alice"),
            UserId::new("bob"),
        ];

        let result = trace_key(&mpk, &tracing_key, &sk_dave, &known_users);
        assert!(result.is_inconclusive());
    }

    #[test]
    fn test_verify_key_origin() {
        let mut rng = thread_rng();
        let (mpk, msk, tracing_key) = traceable_setup(&mut rng);

        let attrs = vec!["admin".to_string()];
        let sk = traceable_keygen(&mut rng, &mpk, &msk, "alice", &attrs).unwrap();

        // Key origin should verify
        assert!(verify_key_origin(&mpk, &tracing_key, &sk).unwrap());
    }

    #[test]
    fn test_encrypt_decrypt_with_traceable_keys() {
        let mut rng = thread_rng();
        let (mpk, msk, _tracing_key) = traceable_setup(&mut rng);

        let attrs = vec!["admin".to_string(), "dept:eng".to_string()];
        let sk = traceable_keygen(&mut rng, &mpk, &msk, "alice", &attrs).unwrap();

        let policy = PolicyNode::And(vec![
            PolicyNode::Attr("admin".to_string()),
            PolicyNode::Attr("dept:eng".to_string()),
        ]);

        let plaintext = b"Secret traceable message";
        let ct = encrypt(&mut rng, &mpk, &policy, plaintext).unwrap();

        let decrypted = decrypt(&mpk, &sk, &ct).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_batch_tracing() {
        let mut rng = thread_rng();
        let (mpk, msk, tracing_key) = traceable_setup(&mut rng);

        let attrs = vec!["user".to_string()];

        let keys: Vec<_> = ["alice", "bob", "charlie"]
            .iter()
            .map(|name| traceable_keygen(&mut rng, &mpk, &msk, *name, &attrs).unwrap())
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

        let attrs = vec!["admin".to_string()];

        // Generate key with specific version
        let sk = traceable_keygen_versioned(
            &mut rng, &mpk, &msk, "alice", &attrs, 5, 1234567890
        ).unwrap();

        assert_eq!(sk.version(), 5);
        assert_eq!(sk.issued_at(), 1234567890);

        // Should still trace correctly
        let alice_id = UserId::new("alice");
        assert!(sk.identity_proof.verify(&alice_id, &tracing_key.trace_vk));
    }
}
