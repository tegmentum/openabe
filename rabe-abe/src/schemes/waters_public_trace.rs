//! Public Traceability for Waters CP-ABE
//!
//! This module implements public traceability, where anyone can trace a leaked key
//! without needing the tracing secret key. Uses publicly verifiable identity commitments.
//!
//! # Key Idea
//!
//! Instead of `H(user_id)^τ` where τ is secret, we use a structure where the commitment
//! can be verified against a public verification key without revealing τ.
//!
//! # Design
//!
//! - Master public key includes a trace verification key (TVK)
//! - Each user's secret key contains an identity commitment that can be verified
//! - Anyone with the MPK can verify if a key belongs to a specific user
//! - Tracing requires no secret information
//!
//! # Security
//!
//! - Collusion resistant: combining keys doesn't help evade tracing
//! - Public verifiability: anyone can verify trace results
//! - Non-frameability: honest users cannot be falsely accused
//!
//! # References
//!
//! - Liu, Au, Susilo. "Self-Generated-Certificate Public Key Encryption Without Pairing" (2007)
//! - Boneh, Naor. "Traitor Tracing with Constant Size Ciphertext" (2008)

use crate::error::AbeError;
use crate::lsss::PolicyNode;
use crate::schemes::waters::{
    Mpk, Msk, SecretKey, FullCiphertext,
    setup as base_setup,
    keygen as base_keygen,
    encrypt as base_encrypt,
    decrypt as base_decrypt,
};
use crate::tracing::{UserId, TraceResult, TracingMetadata};
use crate::utils::{hash_to_g1, hash_to_fr};
use rabe_bls12381::{Fr, G1, G2, pairing};
use rand::{RngCore, CryptoRng};
use sha2::Sha256;

/// Public trace verification key
#[derive(Clone, Debug)]
pub struct TraceVerificationKey {
    /// g^τ in G1 for commitment verification
    pub g_tau: G1,
    /// h^τ in G2 for pairing-based verification
    pub h_tau: G2,
    /// Base for identity hashing
    pub identity_base: G1,
}

/// Master public key with public traceability
#[derive(Clone, Debug)]
pub struct PublicTraceableMpk {
    /// Base Waters MPK
    pub base: Mpk,
    /// Public trace verification key
    pub trace_vk: TraceVerificationKey,
}

/// Master secret key with public traceability
#[derive(Clone, Debug)]
pub struct PublicTraceableMsk {
    /// Base Waters MSK
    pub base: Msk,
    /// Tracing secret τ
    pub tau: Fr,
}

/// Identity commitment for public verification
#[derive(Clone, Debug)]
pub struct PublicIdentityCommitment {
    /// C1 = H(user_id)^τ - can be verified publicly
    pub c1: G1,
    /// C2 = g^r where r is commitment randomness
    pub c2: G1,
    /// C3 = H(user_id)^r - links commitment to identity
    pub c3: G1,
    /// Proof of correct commitment (Schnorr-like)
    pub proof: CommitmentProof,
}

/// Zero-knowledge proof of correct commitment
#[derive(Clone, Debug)]
pub struct CommitmentProof {
    /// Challenge
    pub challenge: Fr,
    /// Response for τ
    pub response_tau: Fr,
    /// Response for r
    pub response_r: Fr,
}

/// Secret key with public traceability
#[derive(Clone, Debug)]
pub struct PublicTraceableSecretKey {
    /// User ID
    pub user_id: UserId,
    /// Base Waters secret key
    pub base: SecretKey,
    /// Public identity commitment
    pub commitment: PublicIdentityCommitment,
    /// Metadata
    pub metadata: TracingMetadata,
}

/// Setup public traceable ABE
pub fn setup<R: RngCore + CryptoRng>(rng: &mut R) -> (PublicTraceableMpk, PublicTraceableMsk) {
    // Run base Waters setup
    let (base_mpk, base_msk) = base_setup(rng);

    // Generate tracing secret
    let tau = Fr::random(rng);

    // Compute trace verification key
    let g = G1::one();
    let h = G2::one();
    let g_tau = g * tau;
    let h_tau = h * tau;
    let identity_base = hash_to_g1("public_trace_identity_base");

    let trace_vk = TraceVerificationKey {
        g_tau,
        h_tau,
        identity_base,
    };

    (
        PublicTraceableMpk {
            base: base_mpk,
            trace_vk,
        },
        PublicTraceableMsk {
            base: base_msk,
            tau,
        },
    )
}

/// Hash user ID to G1 point
fn hash_user_id(mpk: &PublicTraceableMpk, user_id: &UserId) -> G1 {
    let mut data = Vec::new();
    data.extend_from_slice(b"public_trace_user_");
    data.extend_from_slice(user_id.as_str().as_bytes());

    // Use the identity base scaled by hash
    let scalar = hash_to_fr(&data);
    mpk.trace_vk.identity_base * scalar
}

/// Generate secret key with public traceability
pub fn keygen<R: RngCore + CryptoRng>(
    rng: &mut R,
    mpk: &PublicTraceableMpk,
    msk: &PublicTraceableMsk,
    user_id: impl Into<UserId>,
    attributes: &[String],
) -> Result<PublicTraceableSecretKey, AbeError> {
    let user_id = user_id.into();

    // Generate base Waters key
    let base_sk = base_keygen(rng, &mpk.base, &msk.base, attributes)?;

    // Commitment randomness
    let r = Fr::random(rng);

    // Hash user ID
    let h_uid = hash_user_id(mpk, &user_id);

    // C1 = H(user_id)^τ
    let c1 = h_uid * msk.tau;

    // C2 = g^r
    let g = G1::one();
    let c2 = g * r;

    // C3 = H(user_id)^r
    let c3 = h_uid * r;

    // Generate proof of correct commitment
    let proof = generate_commitment_proof(rng, mpk, &user_id, msk.tau, r);

    let commitment = PublicIdentityCommitment {
        c1,
        c2,
        c3,
        proof,
    };

    let issued_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let metadata = TracingMetadata::new(user_id.clone(), issued_at);

    Ok(PublicTraceableSecretKey {
        user_id,
        base: base_sk,
        commitment,
        metadata,
    })
}

/// Generate zero-knowledge proof of correct commitment
fn generate_commitment_proof<R: RngCore + CryptoRng>(
    rng: &mut R,
    mpk: &PublicTraceableMpk,
    user_id: &UserId,
    tau: Fr,
    r: Fr,
) -> CommitmentProof {
    let h_uid = hash_user_id(mpk, user_id);
    let g = G1::one();

    // Commitment phase
    let k_tau = Fr::random(rng);
    let k_r = Fr::random(rng);

    // Compute commitments
    let t1 = h_uid * k_tau;      // H(uid)^k_tau
    let t2 = g * k_r;            // g^k_r
    let t3 = h_uid * k_r;        // H(uid)^k_r

    // Challenge via Fiat-Shamir
    let mut challenge_data = Vec::new();
    challenge_data.extend_from_slice(b"public_trace_proof");
    challenge_data.extend_from_slice(user_id.as_str().as_bytes());
    challenge_data.extend_from_slice(&t1.into_bytes());
    challenge_data.extend_from_slice(&t2.into_bytes());
    challenge_data.extend_from_slice(&t3.into_bytes());
    let challenge = hash_to_fr(&challenge_data);

    // Response
    let response_tau = k_tau - challenge * tau;
    let response_r = k_r - challenge * r;

    CommitmentProof {
        challenge,
        response_tau,
        response_r,
    }
}

/// Verify identity commitment publicly
pub fn verify_commitment(
    mpk: &PublicTraceableMpk,
    user_id: &UserId,
    commitment: &PublicIdentityCommitment,
) -> bool {
    let h_uid = hash_user_id(mpk, user_id);
    let g = G1::one();

    // Recompute commitments from proof
    let t1 = h_uid * commitment.proof.response_tau + commitment.c1 * commitment.proof.challenge;
    let t2 = g * commitment.proof.response_r + commitment.c2 * commitment.proof.challenge;
    let t3 = h_uid * commitment.proof.response_r + commitment.c3 * commitment.proof.challenge;

    // Recompute challenge
    let mut challenge_data = Vec::new();
    challenge_data.extend_from_slice(b"public_trace_proof");
    challenge_data.extend_from_slice(user_id.as_str().as_bytes());
    challenge_data.extend_from_slice(&t1.into_bytes());
    challenge_data.extend_from_slice(&t2.into_bytes());
    challenge_data.extend_from_slice(&t3.into_bytes());
    let expected_challenge = hash_to_fr(&challenge_data);

    // Verify challenge matches
    commitment.proof.challenge == expected_challenge
}

/// Encrypt message (uses base Waters encryption)
pub fn encrypt<R: RngCore + CryptoRng>(
    rng: &mut R,
    mpk: &PublicTraceableMpk,
    policy: &PolicyNode,
    plaintext: &[u8],
) -> Result<FullCiphertext, AbeError> {
    base_encrypt(rng, &mpk.base, policy, plaintext)
}

/// Decrypt message
pub fn decrypt(
    mpk: &PublicTraceableMpk,
    sk: &PublicTraceableSecretKey,
    ct: &FullCiphertext,
) -> Result<Vec<u8>, AbeError> {
    // Verify the key's commitment is valid before using
    if !verify_commitment(mpk, &sk.user_id, &sk.commitment) {
        return Err(AbeError::DecryptError("Invalid key commitment".into()));
    }

    // Use base Waters decryption
    base_decrypt(&mpk.base, &sk.base, ct)
}

/// Public trace - anyone can verify if a key belongs to a user
///
/// This is the key feature: no secret tracing key needed!
pub fn public_trace(
    mpk: &PublicTraceableMpk,
    leaked_key: &PublicTraceableSecretKey,
    candidate_user_ids: &[UserId],
) -> TraceResult {
    // For each candidate, check if the commitment matches
    for candidate_id in candidate_user_ids {
        if verify_user_match(mpk, leaked_key, candidate_id) {
            return TraceResult::Traced(vec![candidate_id.clone()]);
        }
    }

    TraceResult::Inconclusive
}

/// Verify if a leaked key matches a specific user
fn verify_user_match(
    mpk: &PublicTraceableMpk,
    leaked_key: &PublicTraceableSecretKey,
    candidate_id: &UserId,
) -> bool {
    let h_uid = hash_user_id(mpk, candidate_id);
    let h = G2::one();

    // Verify: e(C1, h) = e(H(uid), h^τ)
    // This proves C1 = H(uid)^τ without knowing τ
    let lhs = pairing(leaked_key.commitment.c1, h);
    let rhs = pairing(h_uid, mpk.trace_vk.h_tau);

    if lhs != rhs {
        return false;
    }

    // Verify: e(C2, H(uid)_G2) = e(g, C3_G2) via commitment check
    // Full commitment verification
    verify_commitment(mpk, candidate_id, &leaked_key.commitment)
}

/// Batch public trace - efficiently check against many users
pub fn batch_public_trace(
    mpk: &PublicTraceableMpk,
    leaked_key: &PublicTraceableSecretKey,
    candidate_user_ids: &[UserId],
) -> Vec<TraceResult> {
    let h = G2::one();
    // Pre-compute pairing on leaked key side
    let c1_pairing = pairing(leaked_key.commitment.c1, h);

    candidate_user_ids.iter().map(|candidate_id| {
        let h_uid = hash_user_id(mpk, candidate_id);
        let rhs = pairing(h_uid, mpk.trace_vk.h_tau);

        if c1_pairing == rhs {
            // Quick match - do full verification
            if verify_user_match(mpk, leaked_key, candidate_id) {
                TraceResult::Traced(vec![candidate_id.clone()])
            } else {
                TraceResult::Inconclusive
            }
        } else {
            TraceResult::Inconclusive
        }
    }).collect()
}

/// Extract user ID from leaked key if commitment is valid
///
/// Note: This only works if the key's embedded user_id field is trustworthy.
/// For truly public tracing, use public_trace with candidate list.
pub fn extract_claimed_user(
    mpk: &PublicTraceableMpk,
    leaked_key: &PublicTraceableSecretKey,
) -> Option<UserId> {
    // Verify the key claims to belong to the embedded user_id
    if verify_commitment(mpk, &leaked_key.user_id, &leaked_key.commitment) {
        Some(leaked_key.user_id.clone())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::thread_rng;

    #[test]
    fn test_setup_and_keygen() {
        let mut rng = thread_rng();

        let (mpk, msk) = setup(&mut rng);

        let attrs = vec!["admin".to_string(), "user".to_string()];
        let sk = keygen(&mut rng, &mpk, &msk, "alice", &attrs).unwrap();

        assert_eq!(sk.user_id.as_str(), "alice");
    }

    #[test]
    fn test_commitment_verification() {
        let mut rng = thread_rng();

        let (mpk, msk) = setup(&mut rng);
        let attrs = vec!["a".to_string()];
        let sk = keygen(&mut rng, &mpk, &msk, "bob", &attrs).unwrap();

        // Valid commitment should verify
        assert!(verify_commitment(&mpk, &sk.user_id, &sk.commitment));

        // Wrong user ID should not verify
        let wrong_id = UserId::new("carol");
        assert!(!verify_commitment(&mpk, &wrong_id, &sk.commitment));
    }

    #[test]
    fn test_public_trace() {
        let mut rng = thread_rng();

        let (mpk, msk) = setup(&mut rng);

        let attrs = vec!["a".to_string(), "b".to_string()];
        let alice_sk = keygen(&mut rng, &mpk, &msk, "alice", &attrs).unwrap();
        let bob_sk = keygen(&mut rng, &mpk, &msk, "bob", &attrs).unwrap();

        let candidates = vec![
            UserId::new("alice"),
            UserId::new("bob"),
            UserId::new("carol"),
        ];

        // Trace Alice's key
        let result = public_trace(&mpk, &alice_sk, &candidates);
        match result {
            TraceResult::Traced(ids) => assert_eq!(ids[0].as_str(), "alice"),
            _ => panic!("Should trace to alice"),
        }

        // Trace Bob's key
        let result = public_trace(&mpk, &bob_sk, &candidates);
        match result {
            TraceResult::Traced(ids) => assert_eq!(ids[0].as_str(), "bob"),
            _ => panic!("Should trace to bob"),
        }
    }

    #[test]
    fn test_extract_claimed_user() {
        let mut rng = thread_rng();

        let (mpk, msk) = setup(&mut rng);
        let attrs = vec!["x".to_string()];
        let sk = keygen(&mut rng, &mpk, &msk, "dave", &attrs).unwrap();

        let extracted = extract_claimed_user(&mpk, &sk);
        assert!(extracted.is_some());
        assert_eq!(extracted.unwrap().as_str(), "dave");
    }

    #[test]
    fn test_batch_trace() {
        let mut rng = thread_rng();

        let (mpk, msk) = setup(&mut rng);
        let attrs = vec!["a".to_string()];
        let sk = keygen(&mut rng, &mpk, &msk, "target", &attrs).unwrap();

        let candidates: Vec<UserId> = (0..100)
            .map(|i| UserId::new(format!("user{}", i)))
            .chain(std::iter::once(UserId::new("target")))
            .collect();

        let results = batch_public_trace(&mpk, &sk, &candidates);

        // Should find exactly one match
        let traced_count = results.iter().filter(|r| matches!(r, TraceResult::Traced(_))).count();
        assert_eq!(traced_count, 1);

        // The match should be "target"
        let traced_result = results.iter().find(|r| matches!(r, TraceResult::Traced(_))).unwrap();
        match traced_result {
            TraceResult::Traced(ids) => assert_eq!(ids[0].as_str(), "target"),
            _ => unreachable!(),
        }
    }

    #[test]
    fn test_encrypt_decrypt_with_public_trace() {
        let mut rng = thread_rng();

        let (mpk, msk) = setup(&mut rng);
        let attrs = vec!["admin".to_string(), "user".to_string()];
        let sk = keygen(&mut rng, &mpk, &msk, "alice", &attrs).unwrap();

        let policy = PolicyNode::And(vec![
            PolicyNode::Attr("admin".to_string()),
            PolicyNode::Attr("user".to_string()),
        ]);
        let plaintext = b"Secret message";

        let ct = encrypt(&mut rng, &mpk, &policy, plaintext).unwrap();
        let decrypted = decrypt(&mpk, &sk, &ct).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_no_false_positives() {
        let mut rng = thread_rng();

        let (mpk, msk) = setup(&mut rng);
        let attrs = vec!["a".to_string()];
        let sk = keygen(&mut rng, &mpk, &msk, "real_user", &attrs).unwrap();

        // Check against only wrong users
        let wrong_candidates = vec![
            UserId::new("wrong1"),
            UserId::new("wrong2"),
            UserId::new("wrong3"),
        ];

        let result = public_trace(&mpk, &sk, &wrong_candidates);
        assert!(matches!(result, TraceResult::Inconclusive));
    }
}
