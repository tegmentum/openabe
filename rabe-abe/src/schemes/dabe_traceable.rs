//! DABE (Decentralized Multi-Authority ABE) with White-Box Traitor Tracing
//!
//! This module extends DABE with white-box traitor tracing capability.
//! In the multi-authority setting, each authority embeds its own identity
//! commitment when issuing keys, allowing tracing of leaked keys back to
//! the user across any authority.
//!
//! # Multi-Authority Tracing
//!
//! - Each authority has its own tracing key (τ_aid)
//! - When issuing key components, authorities embed H(user_id)^τ_aid
//! - Any authority can verify its own key components independently
//! - A central tracing authority can aggregate proofs if needed
//!
//! # Design
//!
//! The tracing overhead is minimal: one G1 element per authority key component.

use crate::error::AbeError;
use crate::lsss::PolicyNode;
use crate::tracing::{UserId, TraceResult, TracingMetadata};
use crate::schemes::dabe::{
    GlobalParams, AuthorityPk, AuthoritySk, UserKeyComponent, UserSecretKey,
    FullCiphertext,
    global_setup as base_global_setup,
    authority_setup as base_authority_setup,
    authority_keygen as base_authority_keygen,
    encrypt as base_encrypt,
    decrypt as base_decrypt,
};
use crate::utils::hash_to_g1;
use rabe_bls12381::{Fr, G1, G2, pairing};
use rand::{RngCore, CryptoRng};
use std::collections::HashMap;

/// Traceable Authority Secret Key
///
/// Extends the base DABE authority SK with tracing capability.
#[derive(Clone, Debug)]
pub struct DabeTraceableAuthoritySk {
    /// Base authority secret key
    pub base: AuthoritySk,

    /// Tracing secret for this authority: τ_aid
    pub trace_sk: Fr,

    /// Tracing verification key: g2^τ_aid
    pub trace_vk: G2,
}

/// Tracing Key for a DABE Authority
#[derive(Clone, Debug)]
pub struct DabeAuthorityTracingKey {
    /// Authority identifier
    pub aid: String,

    /// Tracing secret τ_aid
    pub trace_sk: Fr,

    /// Verification key g2^τ_aid
    pub trace_vk: G2,
}

/// Identity proof for a key component from one authority
#[derive(Clone, Debug)]
pub struct DabeIdentityProof {
    /// Authority that issued this proof
    pub aid: String,

    /// Identity commitment: H(user_id)^τ_aid
    pub commitment: G1,

    /// Timestamp when issued
    pub issued_at: u64,

    /// Key version
    pub version: u32,
}

impl DabeIdentityProof {
    /// Verify this proof corresponds to a given user ID
    pub fn verify(&self, user_id: &UserId, trace_vk: &G2) -> bool {
        let h_id = hash_to_g1(user_id.as_str());
        let lhs = pairing(self.commitment, G2::one());
        let rhs = pairing(h_id, *trace_vk);
        lhs == rhs
    }
}

/// Traceable User Key Component from a single authority
#[derive(Clone, Debug)]
pub struct DabeTraceableKeyComponent {
    /// Base key component
    pub base: UserKeyComponent,

    /// Identity proof from this authority
    pub identity_proof: DabeIdentityProof,
}

/// Traceable User Secret Key (aggregated from multiple authorities)
#[derive(Clone, Debug)]
pub struct DabeTraceableUserSecretKey {
    /// Traceable components from each authority (keyed by authority ID)
    pub components: HashMap<String, DabeTraceableKeyComponent>,

    /// User metadata
    pub metadata: TracingMetadata,
}

impl DabeTraceableUserSecretKey {
    /// Get the user ID
    pub fn user_id(&self) -> &UserId {
        &self.metadata.user_id
    }

    /// Get all authority IDs that contributed to this key
    pub fn authorities(&self) -> impl Iterator<Item = &str> {
        self.components.keys().map(|s| s.as_str())
    }

    /// Get the base (non-traceable) user secret key
    pub fn base_key(&self) -> UserSecretKey {
        UserSecretKey {
            components: self.components
                .iter()
                .map(|(aid, comp)| (aid.clone(), comp.base.clone()))
                .collect(),
        }
    }
}

/// Setup: Generate global parameters (same as base DABE)
pub fn global_setup<R: RngCore + CryptoRng>(rng: &mut R) -> GlobalParams {
    base_global_setup(rng)
}

/// Setup: Generate traceable authority keys
///
/// Returns (AuthorityPk, DabeTraceableAuthoritySk, DabeAuthorityTracingKey)
pub fn traceable_authority_setup<R: RngCore + CryptoRng>(
    rng: &mut R,
    gp: &GlobalParams,
    authority_id: &str,
) -> (AuthorityPk, DabeTraceableAuthoritySk, DabeAuthorityTracingKey) {
    // Base authority setup
    let (apk, ask) = base_authority_setup(rng, gp, authority_id);

    // Generate tracing key for this authority
    let trace_sk = Fr::random(rng);
    let trace_vk = G2::one() * trace_sk;

    let traceable_ask = DabeTraceableAuthoritySk {
        base: ask,
        trace_sk,
        trace_vk,
    };

    let tracing_key = DabeAuthorityTracingKey {
        aid: authority_id.to_string(),
        trace_sk,
        trace_vk,
    };

    (apk, traceable_ask, tracing_key)
}

/// Generate a traceable key component from an authority
pub fn traceable_authority_keygen<R: RngCore + CryptoRng>(
    rng: &mut R,
    gp: &GlobalParams,
    ask: &DabeTraceableAuthoritySk,
    user_id: impl Into<UserId>,
    attributes: &[String],
) -> Result<DabeTraceableKeyComponent, AbeError> {
    let user_id = user_id.into();

    // Generate base key component
    let base_comp = base_authority_keygen(rng, gp, &ask.base, user_id.as_str(), attributes)?;

    // Compute identity commitment
    let h_id = hash_to_g1(user_id.as_str());
    let commitment = h_id * ask.trace_sk;

    let issued_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let identity_proof = DabeIdentityProof {
        aid: ask.base.aid.clone(),
        commitment,
        issued_at,
        version: 1,
    };

    Ok(DabeTraceableKeyComponent {
        base: base_comp,
        identity_proof,
    })
}

/// Generate a traceable key component with explicit version and timestamp
pub fn traceable_authority_keygen_versioned<R: RngCore + CryptoRng>(
    rng: &mut R,
    gp: &GlobalParams,
    ask: &DabeTraceableAuthoritySk,
    user_id: impl Into<UserId>,
    attributes: &[String],
    version: u32,
    issued_at: u64,
) -> Result<DabeTraceableKeyComponent, AbeError> {
    let user_id = user_id.into();

    let base_comp = base_authority_keygen(rng, gp, &ask.base, user_id.as_str(), attributes)?;

    let h_id = hash_to_g1(user_id.as_str());
    let commitment = h_id * ask.trace_sk;

    let identity_proof = DabeIdentityProof {
        aid: ask.base.aid.clone(),
        commitment,
        issued_at,
        version,
    };

    Ok(DabeTraceableKeyComponent {
        base: base_comp,
        identity_proof,
    })
}

/// Aggregate traceable key components into a complete user key
pub fn aggregate_traceable_keys(
    user_id: impl Into<UserId>,
    components: Vec<DabeTraceableKeyComponent>,
) -> Result<DabeTraceableUserSecretKey, AbeError> {
    let user_id = user_id.into();

    if components.is_empty() {
        return Err(AbeError::KeygenError("No key components provided".to_string()));
    }

    let issued_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let comp_map: HashMap<String, DabeTraceableKeyComponent> = components
        .into_iter()
        .map(|c| (c.base.aid.clone(), c))
        .collect();

    let metadata = TracingMetadata::new(user_id, issued_at);

    Ok(DabeTraceableUserSecretKey {
        components: comp_map,
        metadata,
    })
}

/// Trace a leaked key component to identify the user
///
/// Uses a specific authority's tracing key to verify the component it issued.
pub fn trace_key_component(
    tracing_key: &DabeAuthorityTracingKey,
    component: &DabeTraceableKeyComponent,
    known_users: &[UserId],
) -> TraceResult {
    // Only verify components from the matching authority
    if component.base.aid != tracing_key.aid {
        return TraceResult::Failed(format!(
            "Component is from authority {} but tracing key is for {}",
            component.base.aid, tracing_key.aid
        ));
    }

    for user_id in known_users {
        if component.identity_proof.verify(user_id, &tracing_key.trace_vk) {
            return TraceResult::Traced(vec![user_id.clone()]);
        }
    }

    TraceResult::Inconclusive
}

/// Trace a complete leaked key using all available authority tracing keys
pub fn trace_key(
    tracing_keys: &HashMap<String, DabeAuthorityTracingKey>,
    leaked_key: &DabeTraceableUserSecretKey,
    known_users: &[UserId],
) -> TraceResult {
    // Try each authority's component
    for (aid, component) in &leaked_key.components {
        if let Some(tracing_key) = tracing_keys.get(aid) {
            let result = trace_key_component(tracing_key, component, known_users);
            if result.is_traced() {
                return result;
            }
        }
    }

    TraceResult::Inconclusive
}

/// Verify that a key's claimed user ID matches all cryptographic commitments
pub fn verify_key_origin(
    tracing_keys: &HashMap<String, DabeAuthorityTracingKey>,
    key: &DabeTraceableUserSecretKey,
) -> Result<bool, AbeError> {
    let claimed_user = &key.metadata.user_id;

    for (aid, component) in &key.components {
        if let Some(tracing_key) = tracing_keys.get(aid) {
            if !component.identity_proof.verify(claimed_user, &tracing_key.trace_vk) {
                return Ok(false);
            }
        }
    }

    Ok(true)
}

/// Verify a single authority's component against claimed user
pub fn verify_component_origin(
    tracing_key: &DabeAuthorityTracingKey,
    component: &DabeTraceableKeyComponent,
    claimed_user: &UserId,
) -> bool {
    component.identity_proof.verify(claimed_user, &tracing_key.trace_vk)
}

// ============================================================================
// Encryption/Decryption (delegates to base DABE scheme)
// ============================================================================

/// Encrypt a message (delegates to base DABE)
pub fn encrypt<R: RngCore + CryptoRng>(
    rng: &mut R,
    gp: &GlobalParams,
    authority_pks: &HashMap<String, AuthorityPk>,
    policy: &PolicyNode,
    plaintext: &[u8],
) -> Result<FullCiphertext, AbeError> {
    base_encrypt(rng, gp, authority_pks, policy, plaintext)
}

/// Decrypt a ciphertext with a traceable key
pub fn decrypt(
    gp: &GlobalParams,
    sk: &DabeTraceableUserSecretKey,
    ct: &FullCiphertext,
) -> Result<Vec<u8>, AbeError> {
    let base_sk = sk.base_key();
    base_decrypt(gp, &base_sk, ct)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::thread_rng;

    fn setup_two_authorities(rng: &mut (impl RngCore + CryptoRng)) -> (
        GlobalParams,
        HashMap<String, AuthorityPk>,
        HashMap<String, DabeTraceableAuthoritySk>,
        HashMap<String, DabeAuthorityTracingKey>,
    ) {
        let gp = global_setup(rng);

        let mut pks = HashMap::new();
        let mut sks = HashMap::new();
        let mut trace_keys = HashMap::new();

        for aid in &["auth1", "auth2"] {
            let (pk, sk, tk) = traceable_authority_setup(rng, &gp, aid);
            pks.insert(aid.to_string(), pk);
            sks.insert(aid.to_string(), sk);
            trace_keys.insert(aid.to_string(), tk);
        }

        (gp, pks, sks, trace_keys)
    }

    #[test]
    fn test_dabe_traceable_authority_setup() {
        let mut rng = thread_rng();
        let gp = global_setup(&mut rng);
        let (pk, sk, tk) = traceable_authority_setup(&mut rng, &gp, "auth1");

        assert_eq!(pk.aid, "auth1");
        assert_eq!(sk.base.aid, "auth1");
        assert_eq!(tk.aid, "auth1");
        assert_eq!(sk.trace_sk, tk.trace_sk);
        assert_eq!(sk.trace_vk, tk.trace_vk);
    }

    #[test]
    fn test_dabe_traceable_keygen() {
        let mut rng = thread_rng();
        let (gp, _pks, sks, trace_keys) = setup_two_authorities(&mut rng);

        let ask1 = sks.get("auth1").unwrap();
        let tk1 = trace_keys.get("auth1").unwrap();

        let attrs = vec!["auth1:admin".to_string()];
        let comp = traceable_authority_keygen(&mut rng, &gp, ask1, "alice", &attrs).unwrap();

        assert_eq!(comp.base.aid, "auth1");

        // Verify identity proof
        let alice_id = UserId::new("alice");
        assert!(comp.identity_proof.verify(&alice_id, &tk1.trace_vk));

        let bob_id = UserId::new("bob");
        assert!(!comp.identity_proof.verify(&bob_id, &tk1.trace_vk));
    }

    #[test]
    fn test_dabe_aggregate_traceable_keys() {
        let mut rng = thread_rng();
        let (gp, _pks, sks, _trace_keys) = setup_two_authorities(&mut rng);

        let ask1 = sks.get("auth1").unwrap();
        let ask2 = sks.get("auth2").unwrap();

        let comp1 = traceable_authority_keygen(
            &mut rng, &gp, ask1, "alice", &["auth1:admin".to_string()]
        ).unwrap();

        let comp2 = traceable_authority_keygen(
            &mut rng, &gp, ask2, "alice", &["auth2:dept:eng".to_string()]
        ).unwrap();

        let sk = aggregate_traceable_keys("alice", vec![comp1, comp2]).unwrap();

        assert_eq!(sk.user_id().as_str(), "alice");
        assert_eq!(sk.components.len(), 2);
    }

    #[test]
    fn test_dabe_trace_key_component() {
        let mut rng = thread_rng();
        let (gp, _pks, sks, trace_keys) = setup_two_authorities(&mut rng);

        let ask1 = sks.get("auth1").unwrap();
        let tk1 = trace_keys.get("auth1").unwrap();

        let comp_alice = traceable_authority_keygen(
            &mut rng, &gp, ask1, "alice", &["auth1:admin".to_string()]
        ).unwrap();

        let known_users = vec![
            UserId::new("alice"),
            UserId::new("bob"),
        ];

        let result = trace_key_component(tk1, &comp_alice, &known_users);
        assert!(result.is_traced());
        assert_eq!(result.traitors().unwrap()[0].as_str(), "alice");
    }

    #[test]
    fn test_dabe_trace_complete_key() {
        let mut rng = thread_rng();
        let (gp, _pks, sks, trace_keys) = setup_two_authorities(&mut rng);

        let ask1 = sks.get("auth1").unwrap();
        let ask2 = sks.get("auth2").unwrap();

        let comp1 = traceable_authority_keygen(
            &mut rng, &gp, ask1, "alice", &["auth1:admin".to_string()]
        ).unwrap();

        let comp2 = traceable_authority_keygen(
            &mut rng, &gp, ask2, "alice", &["auth2:level:5".to_string()]
        ).unwrap();

        let sk = aggregate_traceable_keys("alice", vec![comp1, comp2]).unwrap();

        let known_users = vec![
            UserId::new("alice"),
            UserId::new("bob"),
        ];

        let result = trace_key(&trace_keys, &sk, &known_users);
        assert!(result.is_traced());
        assert_eq!(result.traitors().unwrap()[0].as_str(), "alice");
    }

    #[test]
    fn test_dabe_verify_key_origin() {
        let mut rng = thread_rng();
        let (gp, _pks, sks, trace_keys) = setup_two_authorities(&mut rng);

        let ask1 = sks.get("auth1").unwrap();
        let ask2 = sks.get("auth2").unwrap();

        let comp1 = traceable_authority_keygen(
            &mut rng, &gp, ask1, "alice", &["auth1:admin".to_string()]
        ).unwrap();

        let comp2 = traceable_authority_keygen(
            &mut rng, &gp, ask2, "alice", &["auth2:user".to_string()]
        ).unwrap();

        let sk = aggregate_traceable_keys("alice", vec![comp1, comp2]).unwrap();

        assert!(verify_key_origin(&trace_keys, &sk).unwrap());
    }

    #[test]
    fn test_dabe_encrypt_decrypt_traceable() {
        let mut rng = thread_rng();
        let (gp, pks, sks, _trace_keys) = setup_two_authorities(&mut rng);

        let ask1 = sks.get("auth1").unwrap();

        // Attributes passed to keygen are local names without authority prefix
        let comp = traceable_authority_keygen(
            &mut rng, &gp, ask1, "alice", &["admin".to_string()]
        ).unwrap();

        let sk = aggregate_traceable_keys("alice", vec![comp]).unwrap();

        // Policy uses full authority:attribute format
        let policy = PolicyNode::Attr("auth1:admin".to_string());

        let plaintext = b"DABE traceable secret";
        let ct = encrypt(&mut rng, &gp, &pks, &policy, plaintext).unwrap();

        let decrypted = decrypt(&gp, &sk, &ct).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_dabe_cross_authority_tracing() {
        let mut rng = thread_rng();
        let (gp, pks, sks, trace_keys) = setup_two_authorities(&mut rng);

        let ask1 = sks.get("auth1").unwrap();
        let ask2 = sks.get("auth2").unwrap();

        // Alice gets keys from both authorities
        // Attributes are local names without authority prefix
        let comp1 = traceable_authority_keygen(
            &mut rng, &gp, ask1, "alice", &["admin".to_string()]
        ).unwrap();

        let comp2 = traceable_authority_keygen(
            &mut rng, &gp, ask2, "alice", &["developer".to_string()]
        ).unwrap();

        let sk = aggregate_traceable_keys("alice", vec![comp1, comp2]).unwrap();

        // Cross-authority policy uses full authority:attribute format
        let policy = PolicyNode::And(vec![
            PolicyNode::Attr("auth1:admin".to_string()),
            PolicyNode::Attr("auth2:developer".to_string()),
        ]);

        let plaintext = b"Cross-authority secret";
        let ct = encrypt(&mut rng, &gp, &pks, &policy, plaintext).unwrap();

        let decrypted = decrypt(&gp, &sk, &ct).unwrap();
        assert_eq!(decrypted, plaintext);

        // Trace the key - should identify alice
        let known_users = vec![UserId::new("alice"), UserId::new("bob")];
        let result = trace_key(&trace_keys, &sk, &known_users);
        assert!(result.is_traced());
        assert_eq!(result.traitors().unwrap()[0].as_str(), "alice");
    }
}
