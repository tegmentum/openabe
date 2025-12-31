//! DABE Trace-and-Revoke ABE
//!
//! This module combines Decentralized Multi-Authority ABE (DABE) with integrated
//! traitor tracing and efficient revocation.
//!
//! # Design
//!
//! Unlike single-authority schemes, DABE trace-and-revoke uses a central
//! tracing authority that embeds user identity into keys issued by any
//! participating authority.
//!
//! # Features
//!
//! - Identity-embedded keys for white-box tracing (global across authorities)
//! - Revocation set embedded in ciphertext (revoked users cannot decrypt)
//! - Multi-authority compatible
//! - Efficient for small revocation sets

use crate::error::AbeError;
use crate::lsss::PolicyNode;
use crate::tracing::{UserId, TraceResult, TracingMetadata, RevocationList};
use crate::schemes::dabe::{
    GlobalParams, AuthorityPk, AuthoritySk, UserSecretKey,
    Ciphertext, FullCiphertext,
    global_setup as base_global_setup,
    authority_keygen as base_authority_keygen,
    encrypt as base_encrypt,
};
use crate::utils::hash_to_g1;
use rabe_bls12381::{Fr, G1, G2, pairing};
use rand::{RngCore, CryptoRng};
use std::collections::{HashMap, HashSet};

/// DABE Trace-and-Revoke Master Public Key (Global)
#[derive(Clone, Debug)]
pub struct DabeTraceRevokeMpk {
    /// Base DABE global params
    pub gp: GlobalParams,

    /// Tracing verification key: g2^τ (global for all authorities)
    pub trace_vk: G2,

    /// Revocation base: g1^γ for revocation mechanism
    pub revoke_base: G1,
}

/// DABE Trace-and-Revoke Master Secret Key (Global)
#[derive(Clone, Debug)]
pub struct DabeTraceRevokeMsk {
    /// Tracing secret τ (global)
    pub trace_sk: Fr,

    /// Revocation secret γ
    pub revoke_sk: Fr,
}

/// Tracing Key for identifying traitors
#[derive(Clone, Debug)]
pub struct DabeTraceRevokeTracingKey {
    /// Tracing secret τ
    pub trace_sk: Fr,

    /// Verification key g2^τ
    pub trace_vk: G2,
}

/// User identity token (for revocation checking)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DabeUserIdentityToken {
    /// User ID hash: H(user_id)
    pub id_hash: G1,

    /// Revocation component: H(user_id)^γ
    pub revoke_token: G1,
}

/// DABE Trace-and-Revoke Secret Key
#[derive(Clone, Debug)]
pub struct DabeTraceRevokeSecretKey {
    /// Base DABE secret key
    pub base: UserSecretKey,

    /// User metadata for tracing
    pub metadata: TracingMetadata,

    /// Identity commitment: H(user_id)^τ
    pub identity_commitment: G1,

    /// Identity token for revocation
    pub identity_token: DabeUserIdentityToken,
}

impl DabeTraceRevokeSecretKey {
    /// Get user ID
    pub fn user_id(&self) -> &UserId {
        &self.metadata.user_id
    }
}

/// Revocation header embedded in ciphertext
#[derive(Clone, Debug)]
pub struct DabeRevocationHeader {
    /// Set of revoked user identity hashes
    pub revoked_ids: HashSet<Vec<u8>>,

    /// Revocation ciphertext component: g1^s for each revoked user
    pub revoke_components: HashMap<Vec<u8>, G1>,

    /// Random value for revocation: r_rev
    pub r_rev: G1,
}

/// DABE Trace-and-Revoke Ciphertext
#[derive(Clone, Debug)]
pub struct DabeTraceRevokeCiphertext {
    /// Base ABE ciphertext
    pub abe_ct: Ciphertext,

    /// Revocation header
    pub revoke_header: DabeRevocationHeader,
}

/// Full DABE Trace-and-Revoke Ciphertext with payload
#[derive(Clone, Debug)]
pub struct DabeTraceRevokeFullCiphertext {
    /// ABE ciphertext with revocation
    pub ct: DabeTraceRevokeCiphertext,

    /// Encrypted payload
    pub sym_ct: Vec<u8>,
}

/// Setup: Generate trace-and-revoke global params and master keys
pub fn setup<R: RngCore + CryptoRng>(rng: &mut R) -> (DabeTraceRevokeMpk, DabeTraceRevokeMsk, DabeTraceRevokeTracingKey) {
    let gp = base_global_setup(rng);

    // Tracing secret (global)
    let trace_sk = Fr::random(rng);
    let trace_vk = G2::one() * trace_sk;

    // Revocation secret
    let revoke_sk = Fr::random(rng);
    let revoke_base = G1::one() * revoke_sk;

    let mpk = DabeTraceRevokeMpk {
        gp,
        trace_vk,
        revoke_base,
    };

    let msk = DabeTraceRevokeMsk {
        trace_sk,
        revoke_sk,
    };

    let tracing_key = DabeTraceRevokeTracingKey {
        trace_sk,
        trace_vk,
    };

    (mpk, msk, tracing_key)
}

/// Generate a trace-and-revoke secret key from multiple authorities
///
/// This combines key components from multiple authorities while embedding
/// the user's identity for tracing.
pub fn keygen<R: RngCore + CryptoRng>(
    rng: &mut R,
    mpk: &DabeTraceRevokeMpk,
    msk: &DabeTraceRevokeMsk,
    authority_keys: &[(&AuthoritySk, &[String])], // (authority_sk, attributes)
    user_id: impl Into<UserId>,
) -> Result<DabeTraceRevokeSecretKey, AbeError> {
    let user_id = user_id.into();

    // Generate key components from each authority
    let mut components = HashMap::new();
    for (ask, attrs) in authority_keys {
        let component = base_authority_keygen(
            rng,
            &mpk.gp,
            ask,
            user_id.as_str(),
            attrs,
        )?;
        components.insert(ask.aid.clone(), component);
    }

    let base_sk = UserSecretKey { components };

    // Identity commitment for tracing
    let h_id = hash_to_g1(user_id.as_str());
    let identity_commitment = h_id * msk.trace_sk;

    // Identity token for revocation
    let revoke_token = h_id * msk.revoke_sk;
    let identity_token = DabeUserIdentityToken {
        id_hash: h_id,
        revoke_token,
    };

    let issued_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let metadata = TracingMetadata::new(user_id, issued_at);

    Ok(DabeTraceRevokeSecretKey {
        base: base_sk,
        metadata,
        identity_commitment,
        identity_token,
    })
}

/// Encrypt with revocation set
///
/// Users in the revocation set cannot decrypt the ciphertext.
pub fn encrypt<R: RngCore + CryptoRng>(
    rng: &mut R,
    mpk: &DabeTraceRevokeMpk,
    authority_pks: &HashMap<String, AuthorityPk>,
    policy: &PolicyNode,
    revoked_users: &[UserId],
    plaintext: &[u8],
) -> Result<DabeTraceRevokeFullCiphertext, AbeError> {
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

    let revoke_header = DabeRevocationHeader {
        revoked_ids,
        revoke_components,
        r_rev,
    };

    // Encrypt using base scheme
    let base_ct = base_encrypt(rng, &mpk.gp, authority_pks, policy, plaintext)?;

    let ct = DabeTraceRevokeCiphertext {
        abe_ct: base_ct.abe_ct,
        revoke_header,
    };

    Ok(DabeTraceRevokeFullCiphertext {
        ct,
        sym_ct: base_ct.sym_ct,
    })
}

/// Decrypt with revocation check
pub fn decrypt(
    mpk: &DabeTraceRevokeMpk,
    sk: &DabeTraceRevokeSecretKey,
    ct: &DabeTraceRevokeFullCiphertext,
) -> Result<Vec<u8>, AbeError> {
    // Check if user is revoked
    let id_bytes = serialize_g1(&sk.identity_token.id_hash);

    if ct.ct.revoke_header.revoked_ids.contains(&id_bytes) {
        return Err(AbeError::RevocationError(
            format!("User {} is revoked", sk.user_id())
        ));
    }

    // Perform base ABE decryption
    let full_ct = FullCiphertext {
        abe_ct: ct.ct.abe_ct.clone(),
        sym_ct: ct.sym_ct.clone(),
    };

    crate::schemes::dabe::decrypt(&mpk.gp, &sk.base, &full_ct)
}

/// Trace a leaked key
pub fn trace_key(
    _mpk: &DabeTraceRevokeMpk,
    tracing_key: &DabeTraceRevokeTracingKey,
    leaked_key: &DabeTraceRevokeSecretKey,
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
    mpk: &DabeTraceRevokeMpk,
    ct: &DabeTraceRevokeFullCiphertext,
    new_revoked: &UserId,
) -> DabeTraceRevokeFullCiphertext {
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
    mpk: &DabeTraceRevokeMpk,
    authority_pks: &HashMap<String, AuthorityPk>,
    policy: &PolicyNode,
    revocation_list: &RevocationList,
    plaintext: &[u8],
) -> Result<DabeTraceRevokeFullCiphertext, AbeError> {
    let revoked_users: Vec<UserId> = revocation_list
        .revoked_users()
        .cloned()
        .collect();

    encrypt(rng, mpk, authority_pks, policy, &revoked_users, plaintext)
}

// Helper to serialize G1 point for use as key
fn serialize_g1(point: &G1) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(96);
    bytes.extend_from_slice(format!("{:?}", point).as_bytes());
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schemes::dabe::authority_setup;
    use rand::thread_rng;

    #[test]
    fn test_dabe_trace_revoke_setup() {
        let mut rng = thread_rng();
        let (mpk, msk, tracing_key) = setup(&mut rng);

        assert_eq!(msk.trace_sk, tracing_key.trace_sk);
        assert_eq!(mpk.trace_vk, tracing_key.trace_vk);
    }

    #[test]
    fn test_dabe_trace_revoke_keygen() {
        let mut rng = thread_rng();
        let (mpk, msk, _tracing_key) = setup(&mut rng);

        // Setup authority
        let (apk, ask) = authority_setup(&mut rng, &mpk.gp, "auth1");
        let attrs = vec!["admin".to_string()];

        let sk = keygen(&mut rng, &mpk, &msk, &[(&ask, &attrs)], "alice").unwrap();

        assert_eq!(sk.user_id().as_str(), "alice");
    }

    #[test]
    fn test_dabe_trace_revoke_encrypt_decrypt() {
        let mut rng = thread_rng();
        let (mpk, msk, _tk) = setup(&mut rng);

        // Setup authority
        let (apk, ask) = authority_setup(&mut rng, &mpk.gp, "auth1");
        let attrs = vec!["admin".to_string()];

        let sk = keygen(&mut rng, &mpk, &msk, &[(&ask, &attrs)], "alice").unwrap();

        let mut authority_pks = HashMap::new();
        authority_pks.insert("auth1".to_string(), apk);

        let policy = PolicyNode::Attr("auth1:admin".to_string());
        let plaintext = b"DABE Trace-revoke secret";

        // Encrypt with no revocations
        let ct = encrypt(&mut rng, &mpk, &authority_pks, &policy, &[], plaintext).unwrap();

        // Alice can decrypt
        let decrypted = decrypt(&mpk, &sk, &ct).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_dabe_revoked_user_cannot_decrypt() {
        let mut rng = thread_rng();
        let (mpk, msk, _tk) = setup(&mut rng);

        // Setup authority
        let (apk, ask) = authority_setup(&mut rng, &mpk.gp, "auth1");
        let attrs = vec!["admin".to_string()];

        let sk_alice = keygen(&mut rng, &mpk, &msk, &[(&ask, &attrs)], "alice").unwrap();
        let sk_bob = keygen(&mut rng, &mpk, &msk, &[(&ask, &attrs)], "bob").unwrap();

        let mut authority_pks = HashMap::new();
        authority_pks.insert("auth1".to_string(), apk);

        let policy = PolicyNode::Attr("auth1:admin".to_string());
        let plaintext = b"Secret for non-revoked only";

        // Encrypt with alice revoked
        let revoked = vec![UserId::new("alice")];
        let ct = encrypt(&mut rng, &mpk, &authority_pks, &policy, &revoked, plaintext).unwrap();

        // Alice cannot decrypt
        let result = decrypt(&mpk, &sk_alice, &ct);
        assert!(result.is_err());
        assert!(matches!(result, Err(AbeError::RevocationError(_))));

        // Bob can decrypt
        let decrypted = decrypt(&mpk, &sk_bob, &ct).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_dabe_trace_leaked_key() {
        let mut rng = thread_rng();
        let (mpk, msk, tracing_key) = setup(&mut rng);

        // Setup authority
        let (_apk, ask) = authority_setup(&mut rng, &mpk.gp, "auth1");
        let attrs = vec!["user".to_string()];

        let sk_alice = keygen(&mut rng, &mpk, &msk, &[(&ask, &attrs)], "alice").unwrap();

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
    fn test_dabe_add_revocation() {
        let mut rng = thread_rng();
        let (mpk, msk, _tk) = setup(&mut rng);

        // Setup authority
        let (apk, ask) = authority_setup(&mut rng, &mpk.gp, "auth1");
        let attrs = vec!["admin".to_string()];

        let sk_alice = keygen(&mut rng, &mpk, &msk, &[(&ask, &attrs)], "alice").unwrap();

        let mut authority_pks = HashMap::new();
        authority_pks.insert("auth1".to_string(), apk);

        let policy = PolicyNode::Attr("auth1:admin".to_string());
        let plaintext = b"Secret message";

        // Initially no revocations
        let ct = encrypt(&mut rng, &mpk, &authority_pks, &policy, &[], plaintext).unwrap();

        // Alice can decrypt
        assert!(decrypt(&mpk, &sk_alice, &ct).is_ok());

        // Add alice to revocation
        let ct_revoked = add_revocation(&mut rng, &mpk, &ct, &UserId::new("alice"));

        // Now alice cannot decrypt
        let result = decrypt(&mpk, &sk_alice, &ct_revoked);
        assert!(result.is_err());
    }

    #[test]
    fn test_dabe_multi_authority_trace_revoke() {
        let mut rng = thread_rng();
        let (mpk, msk, tracing_key) = setup(&mut rng);

        // Setup two authorities
        let (apk1, ask1) = authority_setup(&mut rng, &mpk.gp, "auth1");
        let (apk2, ask2) = authority_setup(&mut rng, &mpk.gp, "auth2");

        let attrs1 = vec!["admin".to_string()];
        let attrs2 = vec!["finance".to_string()];

        // Alice gets keys from both authorities
        let sk_alice = keygen(
            &mut rng, &mpk, &msk,
            &[(&ask1, &attrs1), (&ask2, &attrs2)],
            "alice"
        ).unwrap();

        let mut authority_pks = HashMap::new();
        authority_pks.insert("auth1".to_string(), apk1);
        authority_pks.insert("auth2".to_string(), apk2);

        // Policy requiring both authorities
        let policy = PolicyNode::And(vec![
            PolicyNode::Attr("auth1:admin".to_string()),
            PolicyNode::Attr("auth2:finance".to_string()),
        ]);
        let plaintext = b"Multi-authority secret";

        // Encrypt and decrypt
        let ct = encrypt(&mut rng, &mpk, &authority_pks, &policy, &[], plaintext).unwrap();
        let decrypted = decrypt(&mpk, &sk_alice, &ct).unwrap();
        assert_eq!(decrypted, plaintext);

        // Trace the key
        let known_users = vec![
            UserId::new("alice"),
            UserId::new("bob"),
        ];
        let result = trace_key(&mpk, &tracing_key, &sk_alice, &known_users);
        assert!(result.is_traced());
        assert_eq!(result.traitors().unwrap()[0].as_str(), "alice");
    }
}
