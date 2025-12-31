//! Accountable ABE with Non-Repudiation
//!
//! This module implements Accountable ABE where key tracing produces
//! cryptographic evidence that the traced user cannot deny. This is
//! achieved through:
//!
//! 1. User-signed key requests (user acknowledges receiving the key)
//! 2. Authority-signed key issuance (authority confirms issuing to user)
//! 3. Verifiable identity commitments in the key
//!
//! # Non-Repudiation Property
//!
//! When a key is traced to a user:
//! - The authority can prove they issued the key to that user
//! - The user cannot deny having received the key
//! - Third parties can verify the evidence independently
//!
//! # Design
//!
//! Based on concepts from:
//! - "Accountable Attribute-based Encryption with Public Traceability"
//! - Digital signature schemes for key acknowledgment

use crate::error::AbeError;
use crate::lsss::PolicyNode;
use crate::tracing::{UserId, TraceResult, TracingMetadata};
use crate::schemes::waters::{Mpk, Msk, SecretKey, FullCiphertext};
use crate::schemes::waters::{
    setup as base_setup,
    keygen as base_keygen,
    encrypt as base_encrypt,
    decrypt as base_decrypt,
};
use crate::utils::hash_to_g1;
use rabe_bls12381::{Fr, G1, G2, pairing};
use rand::{RngCore, CryptoRng};
use sha2::{Sha256, Digest};
use std::collections::HashMap;

/// User's signature keypair for accountability
#[derive(Clone, Debug)]
pub struct UserSigningKey {
    /// User ID
    pub user_id: UserId,

    /// Private signing key (scalar)
    pub sk: Fr,

    /// Public verification key: g2^sk
    pub vk: G2,
}

/// User's public verification key (registered with authority)
#[derive(Clone, Debug)]
pub struct UserVerificationKey {
    /// User ID
    pub user_id: UserId,

    /// Public verification key: g2^sk
    pub vk: G2,
}

/// Key request signed by user
#[derive(Clone, Debug)]
pub struct SignedKeyRequest {
    /// User ID
    pub user_id: UserId,

    /// Requested attributes
    pub attributes: Vec<String>,

    /// Timestamp
    pub timestamp: u64,

    /// Nonce for freshness
    pub nonce: Vec<u8>,

    /// User's signature: H(request)^sk
    pub signature: G1,

    /// User's verification key
    pub user_vk: G2,
}

/// Authority's issuance certificate
#[derive(Clone, Debug)]
pub struct IssuanceCertificate {
    /// User ID
    pub user_id: UserId,

    /// Issued attributes
    pub attributes: Vec<String>,

    /// Timestamp
    pub issued_at: u64,

    /// Key fingerprint (hash of identity commitment)
    pub key_fingerprint: Vec<u8>,

    /// Authority signature: H(certificate)^authority_sk
    pub authority_signature: G1,
}

/// Accountable Master Public Key
#[derive(Clone, Debug)]
pub struct AccountableMpk {
    /// Base Waters MPK
    pub base: Mpk,

    /// Tracing verification key: g2^τ
    pub trace_vk: G2,

    /// Authority verification key for issuance: g2^authority_sk
    pub authority_vk: G2,
}

/// Accountable Master Secret Key
#[derive(Clone, Debug)]
pub struct AccountableMsk {
    /// Base Waters MSK
    pub base: Msk,

    /// Tracing secret τ
    pub trace_sk: Fr,

    /// Authority signing key for issuance
    pub authority_sk: Fr,
}

/// Tracing Key for identifying traitors
#[derive(Clone, Debug)]
pub struct AccountableTracingKey {
    /// Tracing secret τ
    pub trace_sk: Fr,

    /// Verification key g2^τ
    pub trace_vk: G2,
}

/// Accountable Secret Key with audit trail
#[derive(Clone, Debug)]
pub struct AccountableSecretKey {
    /// Base Waters secret key
    pub base: SecretKey,

    /// User metadata for tracing
    pub metadata: TracingMetadata,

    /// Identity commitment: H(user_id)^τ
    pub identity_commitment: G1,

    /// Issuance certificate from authority
    pub issuance_cert: IssuanceCertificate,

    /// User's signed request
    pub key_request: SignedKeyRequest,
}

impl AccountableSecretKey {
    /// Get user ID
    pub fn user_id(&self) -> &UserId {
        &self.metadata.user_id
    }
}

/// Evidence of key tracing (non-repudiable)
#[derive(Clone, Debug)]
pub struct TraceEvidence {
    /// Traced user ID
    pub user_id: UserId,

    /// Identity commitment from leaked key
    pub identity_commitment: G1,

    /// User's signed key request
    pub key_request: SignedKeyRequest,

    /// Authority's issuance certificate
    pub issuance_cert: IssuanceCertificate,
}

impl TraceEvidence {
    /// Verify the evidence is valid and non-repudiable
    pub fn verify(&self, mpk: &AccountableMpk) -> bool {
        // 1. Verify user's signature on key request
        let request_hash = hash_key_request(&self.key_request);
        let user_sig_valid = pairing(self.key_request.signature, G2::one())
            == pairing(request_hash, self.key_request.user_vk);

        // 2. Verify authority's signature on certificate
        let cert_hash = hash_certificate(&self.issuance_cert);
        let auth_sig_valid = pairing(self.issuance_cert.authority_signature, G2::one())
            == pairing(cert_hash, mpk.authority_vk);

        // 3. Verify identity commitment matches
        let h_id = hash_to_g1(self.user_id.as_str());
        let commitment_valid = pairing(self.identity_commitment, G2::one())
            == pairing(h_id, mpk.trace_vk);

        user_sig_valid && auth_sig_valid && commitment_valid
    }
}

/// Registry of user verification keys
#[derive(Clone, Debug, Default)]
pub struct UserRegistry {
    /// Map of user ID to verification key
    pub users: HashMap<String, UserVerificationKey>,
}

impl UserRegistry {
    /// Create a new registry
    pub fn new() -> Self {
        Self { users: HashMap::new() }
    }

    /// Register a user
    pub fn register(&mut self, user_id: UserId, vk: G2) {
        self.users.insert(
            user_id.as_str().to_string(),
            UserVerificationKey { user_id, vk },
        );
    }

    /// Get a user's verification key
    pub fn get(&self, user_id: &str) -> Option<&UserVerificationKey> {
        self.users.get(user_id)
    }
}

/// Setup: Generate accountable master keys
pub fn setup<R: RngCore + CryptoRng>(rng: &mut R) -> (AccountableMpk, AccountableMsk, AccountableTracingKey) {
    let (base_mpk, base_msk) = base_setup(rng);

    // Tracing secret
    let trace_sk = Fr::random(rng);
    let trace_vk = G2::one() * trace_sk;

    // Authority signing key
    let authority_sk = Fr::random(rng);
    let authority_vk = G2::one() * authority_sk;

    let mpk = AccountableMpk {
        base: base_mpk,
        trace_vk,
        authority_vk,
    };

    let msk = AccountableMsk {
        base: base_msk,
        trace_sk,
        authority_sk,
    };

    let tracing_key = AccountableTracingKey {
        trace_sk,
        trace_vk,
    };

    (mpk, msk, tracing_key)
}

/// Generate a user signing key
pub fn generate_user_signing_key<R: RngCore + CryptoRng>(rng: &mut R, user_id: impl Into<UserId>) -> UserSigningKey {
    let user_id = user_id.into();
    let sk = Fr::random(rng);
    let vk = G2::one() * sk;

    UserSigningKey { user_id, sk, vk }
}

/// Create a signed key request
pub fn create_key_request<R: RngCore + CryptoRng>(
    rng: &mut R,
    signing_key: &UserSigningKey,
    attributes: &[String],
) -> SignedKeyRequest {
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let mut nonce = vec![0u8; 16];
    rng.fill_bytes(&mut nonce);

    // Create unsigned request for hashing
    let unsigned = SignedKeyRequest {
        user_id: signing_key.user_id.clone(),
        attributes: attributes.to_vec(),
        timestamp,
        nonce: nonce.clone(),
        signature: G1::one(), // Placeholder
        user_vk: signing_key.vk,
    };

    // Sign the request
    let hash = hash_key_request(&unsigned);
    let signature = hash * signing_key.sk;

    SignedKeyRequest {
        user_id: signing_key.user_id.clone(),
        attributes: attributes.to_vec(),
        timestamp,
        nonce,
        signature,
        user_vk: signing_key.vk,
    }
}

/// Verify a key request signature
pub fn verify_key_request(request: &SignedKeyRequest) -> bool {
    let hash = hash_key_request(request);
    pairing(request.signature, G2::one()) == pairing(hash, request.user_vk)
}

/// Generate an accountable secret key
pub fn keygen<R: RngCore + CryptoRng>(
    rng: &mut R,
    mpk: &AccountableMpk,
    msk: &AccountableMsk,
    request: &SignedKeyRequest,
) -> Result<AccountableSecretKey, AbeError> {
    // Verify user's signature on request
    if !verify_key_request(request) {
        return Err(AbeError::TracingError("Invalid key request signature".into()));
    }

    let user_id = request.user_id.clone();
    let attributes = &request.attributes;

    // Generate base key
    let base_sk = base_keygen(rng, &mpk.base, &msk.base, attributes)?;

    // Identity commitment for tracing
    let h_id = hash_to_g1(user_id.as_str());
    let identity_commitment = h_id * msk.trace_sk;

    // Create key fingerprint
    let key_fingerprint = {
        let mut hasher = Sha256::new();
        hasher.update(format!("{:?}", identity_commitment).as_bytes());
        hasher.finalize().to_vec()
    };

    let issued_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    // Create and sign issuance certificate
    let unsigned_cert = IssuanceCertificate {
        user_id: user_id.clone(),
        attributes: attributes.clone(),
        issued_at,
        key_fingerprint: key_fingerprint.clone(),
        authority_signature: G1::one(), // Placeholder
    };

    let cert_hash = hash_certificate(&unsigned_cert);
    let authority_signature = cert_hash * msk.authority_sk;

    let issuance_cert = IssuanceCertificate {
        user_id: user_id.clone(),
        attributes: attributes.clone(),
        issued_at,
        key_fingerprint,
        authority_signature,
    };

    let metadata = TracingMetadata::new(user_id, issued_at);

    Ok(AccountableSecretKey {
        base: base_sk,
        metadata,
        identity_commitment,
        issuance_cert,
        key_request: request.clone(),
    })
}

/// Encrypt using the base scheme
pub fn encrypt<R: RngCore + CryptoRng>(
    rng: &mut R,
    mpk: &AccountableMpk,
    policy: &PolicyNode,
    plaintext: &[u8],
) -> Result<FullCiphertext, AbeError> {
    base_encrypt(rng, &mpk.base, policy, plaintext)
}

/// Decrypt using the base scheme
pub fn decrypt(
    mpk: &AccountableMpk,
    sk: &AccountableSecretKey,
    ct: &FullCiphertext,
) -> Result<Vec<u8>, AbeError> {
    base_decrypt(&mpk.base, &sk.base, ct)
}

/// Trace a leaked key with non-repudiable evidence
pub fn trace_key(
    mpk: &AccountableMpk,
    tracing_key: &AccountableTracingKey,
    leaked_key: &AccountableSecretKey,
    known_users: &[UserId],
) -> (TraceResult, Option<TraceEvidence>) {
    for user_id in known_users {
        let h_id = hash_to_g1(user_id.as_str());

        // Verify: e(commitment, g2) == e(H(user_id), trace_vk)
        let lhs = pairing(leaked_key.identity_commitment, G2::one());
        let rhs = pairing(h_id, tracing_key.trace_vk);

        if lhs == rhs {
            // Build non-repudiable evidence
            let evidence = TraceEvidence {
                user_id: user_id.clone(),
                identity_commitment: leaked_key.identity_commitment,
                key_request: leaked_key.key_request.clone(),
                issuance_cert: leaked_key.issuance_cert.clone(),
            };

            // Verify the evidence is valid
            if evidence.verify(mpk) {
                return (TraceResult::Traced(vec![user_id.clone()]), Some(evidence));
            }
        }
    }

    (TraceResult::Inconclusive, None)
}

/// Verify trace evidence independently
pub fn verify_trace_evidence(mpk: &AccountableMpk, evidence: &TraceEvidence) -> bool {
    evidence.verify(mpk)
}

// Helper to hash a key request for signing
fn hash_key_request(request: &SignedKeyRequest) -> G1 {
    let mut hasher = Sha256::new();
    hasher.update(request.user_id.as_str().as_bytes());
    for attr in &request.attributes {
        hasher.update(attr.as_bytes());
    }
    hasher.update(request.timestamp.to_le_bytes());
    hasher.update(&request.nonce);
    let hash = hasher.finalize();

    hash_to_g1(&format!("key_request:{}", hex::encode(&hash)))
}

// Helper to hash an issuance certificate for signing
fn hash_certificate(cert: &IssuanceCertificate) -> G1 {
    let mut hasher = Sha256::new();
    hasher.update(cert.user_id.as_str().as_bytes());
    for attr in &cert.attributes {
        hasher.update(attr.as_bytes());
    }
    hasher.update(cert.issued_at.to_le_bytes());
    hasher.update(&cert.key_fingerprint);
    let hash = hasher.finalize();

    hash_to_g1(&format!("issuance_cert:{}", hex::encode(&hash)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::thread_rng;

    #[test]
    fn test_accountable_setup() {
        let mut rng = thread_rng();
        let (mpk, msk, tracing_key) = setup(&mut rng);

        assert_eq!(msk.trace_sk, tracing_key.trace_sk);
        assert_eq!(mpk.trace_vk, tracing_key.trace_vk);
    }

    #[test]
    fn test_user_signing_key() {
        let mut rng = thread_rng();
        let signing_key = generate_user_signing_key(&mut rng, "alice");

        assert_eq!(signing_key.user_id.as_str(), "alice");
    }

    #[test]
    fn test_key_request_signature() {
        let mut rng = thread_rng();
        let signing_key = generate_user_signing_key(&mut rng, "alice");

        let attrs = vec!["admin".to_string()];
        let request = create_key_request(&mut rng, &signing_key, &attrs);

        assert!(verify_key_request(&request));
    }

    #[test]
    fn test_accountable_keygen() {
        let mut rng = thread_rng();
        let (mpk, msk, _tk) = setup(&mut rng);

        let signing_key = generate_user_signing_key(&mut rng, "alice");
        let attrs = vec!["admin".to_string()];
        let request = create_key_request(&mut rng, &signing_key, &attrs);

        let sk = keygen(&mut rng, &mpk, &msk, &request).unwrap();
        assert_eq!(sk.user_id().as_str(), "alice");
    }

    #[test]
    fn test_accountable_encrypt_decrypt() {
        let mut rng = thread_rng();
        let (mpk, msk, _tk) = setup(&mut rng);

        let signing_key = generate_user_signing_key(&mut rng, "alice");
        let attrs = vec!["admin".to_string()];
        let request = create_key_request(&mut rng, &signing_key, &attrs);
        let sk = keygen(&mut rng, &mpk, &msk, &request).unwrap();

        let policy = PolicyNode::Attr("admin".to_string());
        let plaintext = b"Accountable secret";

        let ct = encrypt(&mut rng, &mpk, &policy, plaintext).unwrap();
        let decrypted = decrypt(&mpk, &sk, &ct).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_trace_with_evidence() {
        let mut rng = thread_rng();
        let (mpk, msk, tracing_key) = setup(&mut rng);

        let signing_key = generate_user_signing_key(&mut rng, "alice");
        let attrs = vec!["admin".to_string()];
        let request = create_key_request(&mut rng, &signing_key, &attrs);
        let sk = keygen(&mut rng, &mpk, &msk, &request).unwrap();

        let known_users = vec![
            UserId::new("alice"),
            UserId::new("bob"),
            UserId::new("charlie"),
        ];

        let (result, evidence) = trace_key(&mpk, &tracing_key, &sk, &known_users);

        assert!(result.is_traced());
        assert_eq!(result.traitors().unwrap()[0].as_str(), "alice");

        // Verify non-repudiable evidence
        let evidence = evidence.unwrap();
        assert!(verify_trace_evidence(&mpk, &evidence));
        assert_eq!(evidence.user_id.as_str(), "alice");
    }

    #[test]
    fn test_evidence_verification() {
        let mut rng = thread_rng();
        let (mpk, msk, tracing_key) = setup(&mut rng);

        let signing_key = generate_user_signing_key(&mut rng, "alice");
        let attrs = vec!["admin".to_string()];
        let request = create_key_request(&mut rng, &signing_key, &attrs);
        let sk = keygen(&mut rng, &mpk, &msk, &request).unwrap();

        let known_users = vec![UserId::new("alice")];
        let (_, evidence) = trace_key(&mpk, &tracing_key, &sk, &known_users);

        let evidence = evidence.unwrap();

        // Third party can verify the evidence independently
        assert!(verify_trace_evidence(&mpk, &evidence));

        // Evidence contains:
        // 1. User's signed key request (user cannot deny)
        // 2. Authority's issuance certificate (authority confirms)
        // 3. Identity commitment matching the user
        assert_eq!(evidence.user_id.as_str(), "alice");
        assert!(verify_key_request(&evidence.key_request));
    }

    #[test]
    fn test_invalid_request_rejected() {
        let mut rng = thread_rng();
        let (mpk, msk, _tk) = setup(&mut rng);

        // Create a forged request with wrong signature
        let attrs = vec!["admin".to_string()];
        let forged_request = SignedKeyRequest {
            user_id: UserId::new("alice"),
            attributes: attrs,
            timestamp: 12345,
            nonce: vec![0u8; 16],
            signature: G1::one(), // Invalid signature
            user_vk: G2::one(),
        };

        // Should fail verification
        assert!(!verify_key_request(&forged_request));

        // Keygen should reject invalid request
        let result = keygen(&mut rng, &mpk, &msk, &forged_request);
        assert!(result.is_err());
    }

    #[test]
    fn test_user_registry() {
        let mut rng = thread_rng();
        let mut registry = UserRegistry::new();

        let alice_key = generate_user_signing_key(&mut rng, "alice");
        let bob_key = generate_user_signing_key(&mut rng, "bob");

        registry.register(UserId::new("alice"), alice_key.vk);
        registry.register(UserId::new("bob"), bob_key.vk);

        assert!(registry.get("alice").is_some());
        assert!(registry.get("bob").is_some());
        assert!(registry.get("charlie").is_none());
    }
}
