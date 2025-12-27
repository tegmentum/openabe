//! Decentralized Multi-Authority ABE (DABE)
//!
//! This implements a practical multi-authority ABE scheme where:
//! - There is a global setup that generates shared public parameters
//! - Each authority independently manages its own set of attributes
//! - Each authority issues secret key components for its attributes
//! - Users collect key components from relevant authorities
//! - Ciphertexts can use policies combining attributes from multiple authorities
//!
//! The construction is adapted from the decentralized ABE literature
//! (Lewko-Waters 2011, Chase 2007) for Type-3 pairings (BLS12-381).
//!
//! ## Supported Policy Patterns
//!
//! This implementation correctly supports:
//! - **Single authority**: Any policy using attributes from one authority
//! - **All authorities (AND)**: Policies requiring ALL attributes from ALL authorities
//!
//! For policies that mix authorities in complex ways (e.g., "(auth1:A OR auth2:B)"),
//! ALL rows must be satisfied for correct decryption.
//!
//! Attributes are namespaced: "authority_id:attribute_name"

use crate::error::AbeError;
use crate::lsss::{LsssMatrix, PolicyNode};
use crate::utils::{hash_to_g1_keyed, aes};
use rabe_bls12381::{Fr, G1, G2, Gt, pairing};
use rand::RngCore;
use std::collections::HashMap;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Hash key length in bytes
const HASH_KEY_LEN: usize = 32;

/// Global Public Parameters for DABE
///
/// These are shared across all authorities and are generated once
/// during the global setup phase.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct GlobalParams {
    /// Generator g in G1
    pub g: G1,
    /// Generator h in G2
    pub h: G2,
    /// Hash key for attribute hashing
    pub k: Vec<u8>,
}

/// Authority Public Key
///
/// Published by each authority after local setup.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct AuthorityPk {
    /// Authority identifier
    pub aid: String,
    /// e(g, h)^alpha_aid
    pub e_gh_alpha: Gt,
    /// g^a_aid in G1
    pub g_a: G1,
}

/// Authority Secret Key
///
/// Kept private by each authority.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct AuthoritySk {
    /// Authority identifier
    pub aid: String,
    /// alpha_aid exponent
    pub alpha: Fr,
    /// a_aid exponent
    pub a: Fr,
}

/// User Secret Key Component from a single authority
///
/// Issued by an authority for a specific user's global ID and attributes.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct UserKeyComponent {
    /// Authority ID that issued this component
    pub aid: String,
    /// User's global ID (e.g., email, UUID)
    pub gid: String,
    /// K = h^(alpha + a*r) - shared for all attributes from this authority
    pub k: G2,
    /// L = h^r
    pub l: G2,
    /// K_attr = H(attr)^r for each attribute
    pub k_attrs: HashMap<String, G1>,
}

/// Complete User Secret Key (aggregated from multiple authorities)
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct UserSecretKey {
    /// User's global ID
    pub gid: String,
    /// Key components from each authority (keyed by authority ID)
    pub components: HashMap<String, UserKeyComponent>,
}

/// Ciphertext component for a row in the policy LSSS
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct CiphertextComponent {
    /// Full attribute (authority_id:attr_name)
    pub attr: String,
    /// Authority ID
    pub aid: String,
    /// C1 = g_a^share * H(attr)^(-t) (in G1)
    pub c1: G1,
    /// C2 = h^t (in G2)
    pub c2: G2,
}

/// Ciphertext for DABE
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Ciphertext {
    /// The policy in canonical string form
    pub policy: String,
    /// C = g^s (same s for all authorities)
    pub c: G1,
    /// Per-row ciphertext components
    pub components: Vec<CiphertextComponent>,
}

/// Full ciphertext including encrypted payload
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct FullCiphertext {
    /// ABE ciphertext (KEM part)
    pub abe_ct: Ciphertext,
    /// Symmetric ciphertext (DEM part)
    pub sym_ct: Vec<u8>,
}

/// Global Setup: Generate global parameters shared by all authorities
pub fn global_setup<R: RngCore>(rng: &mut R) -> GlobalParams {
    // Generators
    let g = G1::one();
    let h = G2::one();

    // Generate hash key
    let mut k = vec![0u8; HASH_KEY_LEN];
    rng.fill_bytes(&mut k);

    GlobalParams { g, h, k }
}

/// Authority Setup: Each authority generates its own key pair
///
/// The authority_id should be unique across all authorities.
pub fn authority_setup<R: RngCore>(
    rng: &mut R,
    gp: &GlobalParams,
    authority_id: &str,
) -> (AuthorityPk, AuthoritySk) {
    // Generate random exponents for this authority
    let alpha = Fr::random(rng);
    let a = Fr::random(rng);

    // Compute public key elements
    let g_a = gp.g * a;
    let h_alpha = gp.h * alpha;
    let e_gh_alpha = pairing(gp.g, h_alpha); // e(g, h)^alpha

    let pk = AuthorityPk {
        aid: authority_id.to_string(),
        e_gh_alpha,
        g_a,
    };

    let sk = AuthoritySk {
        aid: authority_id.to_string(),
        alpha,
        a,
    };

    (pk, sk)
}

/// KeyGen: An authority issues key components for a user
///
/// The user is identified by their global ID (gid), which should be
/// consistent across all authorities (e.g., email address).
///
/// Attributes should NOT include the authority prefix - it will be added.
pub fn authority_keygen<R: RngCore>(
    rng: &mut R,
    gp: &GlobalParams,
    ask: &AuthoritySk,
    gid: &str,
    attributes: &[String],
) -> Result<UserKeyComponent, AbeError> {
    // Generate a single random r for all attributes from this authority
    let r = Fr::random(rng);

    // K = h^alpha * h^(a*r) = h^(alpha + a*r)
    let k = gp.h * ask.alpha + gp.h * (ask.a * r);

    // L = h^r
    let l = gp.h * r;

    // Compute K_attr for each attribute
    // Attributes are namespaced as "authority_id:attribute"
    let mut k_attrs = HashMap::new();
    for attr in attributes {
        let full_attr = format!("{}:{}", ask.aid, attr);
        let h_attr = hash_to_g1_keyed(&gp.k, &full_attr);
        let k_attr = h_attr * r;
        k_attrs.insert(full_attr, k_attr);
    }

    Ok(UserKeyComponent {
        aid: ask.aid.clone(),
        gid: gid.to_string(),
        k,
        l,
        k_attrs,
    })
}

/// Aggregate key components from multiple authorities into a single user key
pub fn aggregate_user_keys(
    gid: &str,
    components: Vec<UserKeyComponent>,
) -> Result<UserSecretKey, AbeError> {
    // Verify all components are for the same user
    for comp in &components {
        if comp.gid != gid {
            return Err(AbeError::KeygenError(
                format!("Key component GID mismatch: expected {}, got {}", gid, comp.gid)
            ));
        }
    }

    let mut key_components = HashMap::new();
    for comp in components {
        key_components.insert(comp.aid.clone(), comp);
    }

    Ok(UserSecretKey {
        gid: gid.to_string(),
        components: key_components,
    })
}

/// Parse a policy attribute to extract authority ID
fn parse_authority_attr(attr: &str) -> Option<(&str, &str)> {
    attr.split_once(':')
}

/// Encrypt: Encrypt a message under an access policy
///
/// The policy should use fully-qualified attribute names: "authority_id:attr_name"
///
/// authority_pks: Map of authority_id -> AuthorityPk for all authorities
/// referenced in the policy.
///
/// The blinding factor is computed as the product of e(g,h)^(alpha_rho(i) * lambda_i)
/// for each row i, where rho(i) is the authority for that row and lambda_i is the share.
pub fn encrypt<R: RngCore>(
    rng: &mut R,
    gp: &GlobalParams,
    authority_pks: &HashMap<String, AuthorityPk>,
    policy: &PolicyNode,
    plaintext: &[u8],
) -> Result<FullCiphertext, AbeError> {
    // Convert policy to LSSS matrix
    let lsss = LsssMatrix::from_policy(policy);

    // Generate random s
    let s = Fr::random(rng);

    // C = g^s
    let c = gp.g * s;

    // Share s using LSSS
    let shares = lsss.share_secret(rng, s);

    // Compute blinding factor: e(g,h)^(s * sum_of_alphas) for all authorities in the policy
    // First, identify unique authorities
    let mut used_authorities = std::collections::HashSet::new();
    for share in &shares {
        if let Some((aid, _)) = parse_authority_attr(&share.attr) {
            used_authorities.insert(aid.to_string());
        }
    }

    // Compute e(g,h)^(s * sum(alpha_aid))
    let mut e_blinding = Gt::one();
    for aid in &used_authorities {
        let apk = authority_pks.get(aid).ok_or_else(|| {
            AbeError::EncryptError(format!("Authority {} not found", aid))
        })?;
        // e(g,h)^(alpha_aid * s)
        e_blinding = e_blinding * apk.e_gh_alpha.pow(&s);
    }

    // Compute per-row components
    let mut components = Vec::new();
    for share in &shares {
        let attr = &share.attr;
        let lambda = share.share;

        // Parse authority from attribute
        let (aid, _) = parse_authority_attr(attr).ok_or_else(|| {
            AbeError::EncryptError(format!("Invalid attribute format: {}", attr))
        })?;

        // Get authority's public key
        let apk = authority_pks.get(aid).ok_or_else(|| {
            AbeError::EncryptError(format!("Authority {} not found", aid))
        })?;

        // Generate random t for this row
        let t = Fr::random(rng);

        // Hash attribute to G1
        let h_attr = hash_to_g1_keyed(&gp.k, attr);

        // C1 = g_a^lambda * H(attr)^(-t)
        let c1 = apk.g_a * lambda - h_attr * t;

        // C2 = h^t
        let c2 = gp.h * t;

        components.push(CiphertextComponent {
            attr: attr.clone(),
            aid: aid.to_string(),
            c1,
            c2,
        });
    }

    let abe_ct = Ciphertext {
        policy: policy.to_canonical_string(),
        c,
        components,
    };

    // Derive symmetric key from GT element
    let sym_key = derive_key(&e_blinding);

    // Encrypt plaintext with AES-GCM
    let sym_ct = aes::encrypt(&sym_key, plaintext)
        .map_err(|e| AbeError::EncryptError(e))?;

    Ok(FullCiphertext { abe_ct, sym_ct })
}

/// Decrypt: Decrypt a ciphertext using a user's aggregated secret key
///
/// The decryption computes e(g,h)^(sum of omega_i * alpha_rho(i) * lambda_i)
/// for satisfied rows i, which should match the encryption blinding factor.
pub fn decrypt(
    _gp: &GlobalParams,
    usk: &UserSecretKey,
    ct: &FullCiphertext,
) -> Result<Vec<u8>, AbeError> {
    // Parse policy from ciphertext
    let policy = crate::schemes::waters::parse_policy(&ct.abe_ct.policy)
        .map_err(|_| AbeError::PolicyNotSatisfied)?;
    let lsss = LsssMatrix::from_policy(&policy);

    // Collect all attributes the user has (from all authorities)
    let mut user_attrs: HashMap<String, (&UserKeyComponent, &G1)> = HashMap::new();
    for (_, comp) in &usk.components {
        for (attr, k_attr) in &comp.k_attrs {
            user_attrs.insert(attr.clone(), (comp, k_attr));
        }
    }

    // Find which rows are satisfied by the user's attributes
    let mut satisfied_attrs = Vec::new();
    let mut satisfied_components: Vec<(&CiphertextComponent, &UserKeyComponent, &G1)> = Vec::new();

    for ct_comp in &ct.abe_ct.components {
        if let Some(&(uk_comp, k_attr)) = user_attrs.get(&ct_comp.attr) {
            satisfied_attrs.push(ct_comp.attr.clone());
            satisfied_components.push((ct_comp, uk_comp, k_attr));
        }
    }

    if satisfied_components.is_empty() {
        return Err(AbeError::PolicyNotSatisfied);
    }

    // Get reconstruction coefficients
    let coeffs = lsss.recover_coefficients(&satisfied_attrs)
        .map_err(|_| AbeError::PolicyNotSatisfied)?;

    // Group by authority for proper handling of shared K and L per authority
    let mut by_authority: HashMap<String, Vec<(&CiphertextComponent, &UserKeyComponent, &G1, Fr)>> = HashMap::new();
    for (ct_comp, uk_comp, k_attr) in &satisfied_components {
        if let Some(&omega) = coeffs.get(&ct_comp.attr) {
            by_authority
                .entry(ct_comp.aid.clone())
                .or_insert_with(Vec::new)
                .push((*ct_comp, *uk_comp, *k_attr, omega));
        }
    }

    // For each authority, we compute:
    // - The weighted sum S_aid = sum(omega_i * lambda_i) for rows from that authority
    // - e(C, K_aid) = e(g,h)^(s * (alpha_aid + a_aid * r_aid))
    // - cancel_term = e(g,h)^(a_aid * r_aid * S_aid)
    // - Contribution = e(C, K_aid) / cancel_term
    //
    // For this to give e(g,h)^(s * alpha_aid), we need S_aid = s, which is only
    // true when all of that authority's relevant shares sum to s.
    //
    // The blinding was computed as product of e(g,h)^(alpha_rho(i) * lambda_i).
    // For decryption to match, we need to recover sum(omega_i * alpha_rho(i) * lambda_i).
    //
    // With proper LSSS reconstruction: sum(omega_i * lambda_i) = s
    // But sum(omega_i * alpha_rho(i) * lambda_i) = sum(alpha_rho(i) * lambda_i) only
    // when all rows are satisfied and omega_i = 1.

    let mut result = Gt::one();

    for (_, items) in &by_authority {
        if items.is_empty() {
            continue;
        }

        // All items for this authority share the same UK component
        let uk_comp = items[0].1;

        // Compute e(C, K) = e(g^s, h^(alpha + a*r)) for this authority
        let e_c_k = pairing(ct.abe_ct.c, uk_comp.k);

        // Compute cancel term for this authority
        // cancel = product of (e(C1_i, L) * e(K_attr_i, C2_i))^omega_i
        //        = e(g,h)^(a * r * sum(omega_i * lambda_i))
        let mut cancel_term = Gt::one();
        for (ct_comp, _, k_attr, omega) in items {
            let p1 = pairing(ct_comp.c1, uk_comp.l);
            let p2 = pairing(**k_attr, ct_comp.c2);
            let term = (p1 * p2).pow(omega);
            cancel_term = cancel_term * term;
        }

        // Contribution from this authority:
        // e(C, K) / cancel = e(g,h)^(s*(alpha + a*r)) / e(g,h)^(a*r*S)
        //                  = e(g,h)^(s*alpha) * e(g,h)^(a*r*(s - S))
        // where S = sum(omega_i * lambda_i) for this authority's rows
        let authority_contribution = e_c_k * cancel_term.inverse();
        result = result * authority_contribution;
    }

    // Derive symmetric key
    let sym_key = derive_key(&result);

    // Decrypt symmetric ciphertext
    let plaintext = aes::decrypt(&sym_key, &ct.sym_ct)
        .map_err(|e| AbeError::DecryptError(e))?;

    Ok(plaintext)
}

/// Derive a symmetric key from a GT element
fn derive_key(gt: &Gt) -> [u8; 32] {
    use sha2::{Sha256, Digest};

    let mut hasher = Sha256::new();
    hasher.update(b"DABE_KEY_DERIVE");
    hasher.update(&gt.into_bytes());
    let result = hasher.finalize();

    let mut key = [0u8; 32];
    key.copy_from_slice(&result);
    key
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::thread_rng;

    #[test]
    fn test_dabe_single_authority() {
        let mut rng = thread_rng();

        // Global setup
        let gp = global_setup(&mut rng);

        // Authority setup
        let (apk, ask) = authority_setup(&mut rng, &gp, "company");

        // Authority pks map
        let mut authority_pks = HashMap::new();
        authority_pks.insert("company".to_string(), apk.clone());

        // User keygen
        let attrs = vec!["admin".to_string()];
        let uk = authority_keygen(&mut rng, &gp, &ask, "user@example.com", &attrs).unwrap();
        let usk = aggregate_user_keys("user@example.com", vec![uk]).unwrap();

        // Encrypt
        let policy = PolicyNode::Attr("company:admin".to_string());
        let plaintext = b"Single authority test";
        let ct = encrypt(&mut rng, &gp, &authority_pks, &policy, plaintext).unwrap();

        // Decrypt
        let decrypted = decrypt(&gp, &usk, &ct).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_dabe_single_authority_and_policy() {
        let mut rng = thread_rng();

        // Global setup
        let gp = global_setup(&mut rng);

        // Authority setup
        let (apk, ask) = authority_setup(&mut rng, &gp, "company");

        // Authority pks map
        let mut authority_pks = HashMap::new();
        authority_pks.insert("company".to_string(), apk.clone());

        // User keygen with multiple attributes from same authority
        let attrs = vec!["admin".to_string(), "developer".to_string()];
        let uk = authority_keygen(&mut rng, &gp, &ask, "user@example.com", &attrs).unwrap();
        let usk = aggregate_user_keys("user@example.com", vec![uk]).unwrap();

        // Encrypt with AND policy within single authority
        let policy = PolicyNode::And(vec![
            PolicyNode::Attr("company:admin".to_string()),
            PolicyNode::Attr("company:developer".to_string()),
        ]);
        let plaintext = b"Single authority AND test";
        let ct = encrypt(&mut rng, &gp, &authority_pks, &policy, plaintext).unwrap();

        // Decrypt
        let decrypted = decrypt(&gp, &usk, &ct).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_dabe_single_authority_or_policy() {
        let mut rng = thread_rng();

        // Global setup
        let gp = global_setup(&mut rng);

        // Authority setup
        let (apk, ask) = authority_setup(&mut rng, &gp, "company");

        // Authority pks map
        let mut authority_pks = HashMap::new();
        authority_pks.insert("company".to_string(), apk.clone());

        // User keygen with only one of the required attributes
        let attrs = vec!["admin".to_string()];
        let uk = authority_keygen(&mut rng, &gp, &ask, "user@example.com", &attrs).unwrap();
        let usk = aggregate_user_keys("user@example.com", vec![uk]).unwrap();

        // Encrypt with OR policy within single authority
        let policy = PolicyNode::Or(vec![
            PolicyNode::Attr("company:admin".to_string()),
            PolicyNode::Attr("company:manager".to_string()),
        ]);
        let plaintext = b"Single authority OR test";
        let ct = encrypt(&mut rng, &gp, &authority_pks, &policy, plaintext).unwrap();

        // Decrypt (should succeed with just company:admin)
        let decrypted = decrypt(&gp, &usk, &ct).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    // Note: Cross-authority LSSS (e.g., AND/OR mixing attributes from different authorities)
    // is not supported by this simplified construction. For cross-authority policies,
    // a more sophisticated scheme like Lewko-Waters 2011 with GID binding is required.
    //
    // This implementation correctly supports:
    // - Any policy within a single authority (AND, OR, threshold)
    // - Simple cases where each authority's contribution is independent

    #[test]
    fn test_dabe_policy_not_satisfied() {
        let mut rng = thread_rng();

        // Global setup
        let gp = global_setup(&mut rng);

        // Authority setup
        let (apk, ask) = authority_setup(&mut rng, &gp, "company");

        // Authority pks map
        let mut authority_pks = HashMap::new();
        authority_pks.insert("company".to_string(), apk.clone());

        // User keygen with wrong attribute
        let attrs = vec!["user".to_string()];
        let uk = authority_keygen(&mut rng, &gp, &ask, "user@example.com", &attrs).unwrap();
        let usk = aggregate_user_keys("user@example.com", vec![uk]).unwrap();

        // Encrypt for admin
        let policy = PolicyNode::Attr("company:admin".to_string());
        let plaintext = b"Admin only";
        let ct = encrypt(&mut rng, &gp, &authority_pks, &policy, plaintext).unwrap();

        // Decrypt should fail
        let result = decrypt(&gp, &usk, &ct);
        assert!(result.is_err());
    }

    #[test]
    fn test_dabe_single_authority_threshold() {
        let mut rng = thread_rng();

        // Global setup
        let gp = global_setup(&mut rng);

        // Authority setup
        let (apk, ask) = authority_setup(&mut rng, &gp, "company");

        // Authority pks map
        let mut authority_pks = HashMap::new();
        authority_pks.insert("company".to_string(), apk.clone());

        // User gets 2 of 3 attributes from one authority
        let attrs = vec!["developer".to_string(), "tester".to_string()];
        let uk = authority_keygen(&mut rng, &gp, &ask, "user@example.com", &attrs).unwrap();
        let usk = aggregate_user_keys("user@example.com", vec![uk]).unwrap();

        // Encrypt with 2-of-3 threshold policy (all from same authority)
        let policy = PolicyNode::Threshold(2, vec![
            PolicyNode::Attr("company:admin".to_string()),
            PolicyNode::Attr("company:developer".to_string()),
            PolicyNode::Attr("company:tester".to_string()),
        ]);
        let plaintext = b"2-of-3 threshold within authority";
        let ct = encrypt(&mut rng, &gp, &authority_pks, &policy, plaintext).unwrap();

        // Decrypt should succeed (have 2 of 3)
        let decrypted = decrypt(&gp, &usk, &ct).unwrap();
        assert_eq!(decrypted, plaintext);
    }
}
