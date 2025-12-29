//! GPSW KP-ABE (Key-Policy Attribute-Based Encryption)
//!
//! Implementation based on:
//! "Attribute-Based Encryption for Fine-Grained Access Control of Encrypted Data"
//! Goyal, Pandey, Sahai, Waters (ACM CCS 2006)
//!
//! In KP-ABE:
//! - The **ciphertext** is encrypted under a set of attributes
//! - The **secret key** embeds an access policy (LSSS)
//! - A user can decrypt iff their policy is satisfied by the ciphertext's attributes
//!
//! This implementation uses BLS12-381 for 128-bit security.
//!
//! ## Construction
//!
//! Setup:
//! - g1 in G1, g2 in G2
//! - alpha random scalar
//! - egg_alpha = e(g1, g2)^alpha
//!
//! Encrypt(attributes S):
//! - Choose random s
//! - C' = g2^s (in G2)
//! - For each attr: C_attr = H(attr)^s (in G1)
//! - Derive key from e(g1, g2)^(alpha*s)
//!
//! KeyGen(policy):
//! - LSSS shares lambda_i of alpha
//! - For each row i with attr:
//!   - D_i = g1^lambda_i * H(attr)^r_i (in G1)
//!   - D'_i = g2^r_i (in G2)
//!
//! Decrypt:
//! - For satisfied rows: e(D_i, C') / e(C_attr, D'_i) = e(g1, g2)^(lambda_i * s)
//! - Combine with LSSS coefficients to get e(g1, g2)^(alpha * s)

use crate::error::AbeError;
use crate::lsss::{PolicyNode, get_or_compute_lsss};
use crate::utils::{hash_to_g1_keyed_cached, aes};
use rabe_bls12381::{Fr, G1, G2, Gt, pairing, multi_pairing};
use rand::{RngCore, CryptoRng};
use std::collections::HashMap;
use zeroize::Zeroize;

#[cfg(feature = "parallel")]
use rayon::prelude::*;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Hash key length in bytes
const HASH_KEY_LEN: usize = 32;

/// Master Public Key for GPSW KP-ABE
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Mpk {
    /// Generator g1 in G1
    pub g1: G1,
    /// Generator g2 in G2
    pub g2: G2,
    /// e(g1, g2)^alpha
    pub egg_alpha: Gt,
    /// Hash key prefix for attribute hashing
    pub k: Vec<u8>,
}

/// Master Secret Key for GPSW KP-ABE
///
/// # Security
///
/// This structure contains secret key material that is zeroized on drop.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Msk {
    /// alpha exponent
    pub alpha: Fr,
}

impl Drop for Msk {
    fn drop(&mut self) {
        self.alpha = Fr::zero();
    }
}

/// Secret Key component for a row in the policy LSSS
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SecretKeyComponent {
    /// Attribute for this component
    pub attr: String,
    /// D = g1^lambda * H(attr)^r (in G1)
    pub d: G1,
    /// D' = g2^r (in G2)
    pub d_prime: G2,
}

/// User Secret Key for GPSW KP-ABE
/// The key embeds an access policy (LSSS matrix)
///
/// # Security
///
/// This structure contains secret key material that is zeroized on drop.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SecretKey {
    /// The policy this key enforces (canonical string)
    pub policy: String,
    /// Per-row key components with their attributes
    pub components: Vec<SecretKeyComponent>,
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        self.policy.zeroize();
        for comp in &mut self.components {
            comp.attr.zeroize();
        }
        self.components.clear();
    }
}

/// Ciphertext component for an attribute
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct CiphertextComponent {
    /// C_attr = H(attr)^s (in G1)
    pub c: G1,
}

/// Ciphertext for GPSW KP-ABE
/// Encrypted under a set of attributes
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Ciphertext {
    /// The set of attributes this ciphertext is encrypted under
    pub attributes: Vec<String>,
    /// C' = g2^s (in G2)
    pub c_prime: G2,
    /// Per-attribute ciphertext components
    pub components: HashMap<String, CiphertextComponent>,
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

/// Setup: Generate master public and secret keys
///
/// # Arguments
/// * `rng` - Random number generator
///
/// # Returns
/// Tuple of (master public key, master secret key)
pub fn setup<R: RngCore + CryptoRng>(rng: &mut R) -> (Mpk, Msk) {
    // Generate random alpha
    let alpha = Fr::random(rng);

    // Pick generators
    let g1 = G1::one();
    let g2 = G2::one();

    // Compute e(g1, g2)^alpha
    let g2alpha = g2 * alpha;
    let egg_alpha = pairing(g1, g2alpha);

    // Generate hash key
    let mut k = vec![0u8; HASH_KEY_LEN];
    rng.fill_bytes(&mut k);

    let mpk = Mpk {
        g1,
        g2,
        egg_alpha,
        k,
    };

    let msk = Msk { alpha };

    (mpk, msk)
}

/// KeyGen: Generate a secret key for a user with an access policy
///
/// In KP-ABE, the key embeds the policy. The user can decrypt any ciphertext
/// whose attributes satisfy the policy.
///
/// # Arguments
/// * `rng` - Random number generator
/// * `mpk` - Master public key
/// * `msk` - Master secret key
/// * `policy` - Access policy (as a PolicyNode tree)
///
/// # Returns
/// Secret key for the given policy
pub fn keygen<R: RngCore + CryptoRng>(
    rng: &mut R,
    mpk: &Mpk,
    msk: &Msk,
    policy: &PolicyNode,
) -> Result<SecretKey, AbeError> {
    // Convert policy to LSSS matrix (cached for repeated policies)
    let lsss = get_or_compute_lsss(policy)?;

    // Share the secret alpha using LSSS
    // Each row gets a share of alpha
    let shares = lsss.share_secret(rng, msk.alpha);

    // Pre-generate random r values for parallel processing
    let r_values: Vec<Fr> = shares.iter().map(|_| Fr::random(rng)).collect();

    // For each share (each row in LSSS) - parallelized when enabled
    #[cfg(feature = "parallel")]
    let components: Vec<SecretKeyComponent> = shares
        .par_iter()
        .zip(r_values.par_iter())
        .map(|(share, r)| {
            let h_attr = hash_to_g1_keyed_cached(&mpk.k, &share.attr);
            let d = mpk.g1 * share.share + h_attr * *r;
            let d_prime = mpk.g2 * *r;
            SecretKeyComponent {
                attr: share.attr.clone(),
                d,
                d_prime,
            }
        })
        .collect();

    #[cfg(not(feature = "parallel"))]
    let components: Vec<SecretKeyComponent> = shares
        .iter()
        .zip(r_values.iter())
        .map(|(share, r)| {
            let h_attr = hash_to_g1_keyed_cached(&mpk.k, &share.attr);
            let d = mpk.g1 * share.share + h_attr * *r;
            let d_prime = mpk.g2 * *r;
            SecretKeyComponent {
                attr: share.attr.clone(),
                d,
                d_prime,
            }
        })
        .collect();

    Ok(SecretKey {
        policy: policy.to_canonical_string(),
        components,
    })
}

/// Encrypt: Encrypt a message under a set of attributes
///
/// # Arguments
/// * `rng` - Random number generator
/// * `mpk` - Master public key
/// * `attributes` - Set of attributes to encrypt under
/// * `plaintext` - Message to encrypt
///
/// # Returns
/// Full ciphertext (ABE + symmetric)
pub fn encrypt<R: RngCore + CryptoRng>(
    rng: &mut R,
    mpk: &Mpk,
    attributes: &[String],
    plaintext: &[u8],
) -> Result<FullCiphertext, AbeError> {
    // Generate random s
    let s = Fr::random(rng);

    // C' = g2^s (in G2)
    let c_prime = mpk.g2 * s;

    // Compute e(g1, g2)^(alpha * s) = egg_alpha^s
    let egg_alpha_s = mpk.egg_alpha.pow(&s);

    // Compute per-attribute components (parallelized when enabled)
    #[cfg(feature = "parallel")]
    let components: HashMap<String, CiphertextComponent> = attributes
        .par_iter()
        .map(|attr| {
            let h_attr = hash_to_g1_keyed_cached(&mpk.k, attr);
            (attr.clone(), CiphertextComponent { c: h_attr * s })
        })
        .collect();

    #[cfg(not(feature = "parallel"))]
    let components: HashMap<String, CiphertextComponent> = attributes
        .iter()
        .map(|attr| {
            let h_attr = hash_to_g1_keyed_cached(&mpk.k, attr);
            (attr.clone(), CiphertextComponent { c: h_attr * s })
        })
        .collect();

    let abe_ct = Ciphertext {
        attributes: attributes.to_vec(),
        c_prime,
        components,
    };

    // Derive symmetric key from GT element
    let sym_key = derive_key(&egg_alpha_s);

    // Encrypt plaintext with AES-GCM
    let sym_ct = aes::encrypt(&sym_key, plaintext)
        .map_err(|e| AbeError::EncryptError(e))?;

    Ok(FullCiphertext { abe_ct, sym_ct })
}

/// Decrypt: Decrypt a ciphertext using a secret key
///
/// Decryption succeeds iff the ciphertext's attributes satisfy the key's policy.
///
/// # Arguments
/// * `mpk` - Master public key
/// * `sk` - User's secret key (with policy)
/// * `ct` - Full ciphertext (with attributes)
///
/// # Returns
/// Decrypted plaintext
pub fn decrypt(
    mpk: &Mpk,
    sk: &SecretKey,
    ct: &FullCiphertext,
) -> Result<Vec<u8>, AbeError> {
    // Find which key components have matching ciphertext attributes
    let mut matched_components: Vec<(&SecretKeyComponent, &CiphertextComponent)> = Vec::new();
    let mut matched_attrs: Vec<String> = Vec::new();

    for sk_comp in &sk.components {
        if let Some(ct_comp) = ct.abe_ct.components.get(&sk_comp.attr) {
            matched_components.push((sk_comp, ct_comp));
            matched_attrs.push(sk_comp.attr.clone());
        }
    }

    if matched_components.is_empty() {
        return Err(AbeError::PolicyNotSatisfied);
    }

    // Reconstruct the LSSS matrix to get coefficients
    // We parse the policy from the canonical string
    let policy = crate::schemes::waters::parse_policy(&sk.policy)
        .map_err(|_| AbeError::PolicyNotSatisfied)?;

    // Quick check: can the policy possibly be satisfied?
    let attr_set: std::collections::HashSet<String> = matched_attrs.iter().cloned().collect();
    if !policy.can_satisfy(&attr_set) {
        return Err(AbeError::PolicyNotSatisfied);
    }

    // Get LSSS matrix (cached for repeated policies)
    let lsss = get_or_compute_lsss(&policy)?;

    // Get reconstruction coefficients
    let coeffs = lsss.recover_coefficients(&matched_attrs)
        .map_err(|_| AbeError::PolicyNotSatisfied)?;

    // Collect items for processing
    let items: Vec<_> = matched_components
        .iter()
        .filter_map(|(sk_comp, ct_comp)| {
            let omega = coeffs.get(&sk_comp.attr)?;
            Some((sk_comp.d, sk_comp.d_prime, ct_comp.c, *omega))
        })
        .collect();

    // Optimization: Use bilinearity to convert e(a,b)^omega to e(a*omega, b)
    // This allows us to use MSM + multi-pairing for significant speedup
    //
    // Original: ∏ (e(d_i, c') / e(c_i, d'_i))^omega_i
    // Using bilinearity: ∏ e(d_i * omega_i, c') * e(c_i * (-omega_i), d'_i)
    // As multi-pairing: multi_pairing([d*omega, c*(-omega), ...], [c', d', ...])

    // Extract and scale points using parallel iteration when available
    #[cfg(feature = "parallel")]
    let (g1_points, g2_points): (Vec<G1>, Vec<G2>) = {
        let scaled: Vec<_> = items
            .par_iter()
            .flat_map(|(d, d_prime, c, omega)| {
                let neg_omega = -(*omega);
                vec![
                    (*d * *omega, ct.abe_ct.c_prime),
                    (*c * neg_omega, *d_prime),
                ]
            })
            .collect();
        scaled.into_iter().unzip()
    };

    #[cfg(not(feature = "parallel"))]
    let (g1_points, g2_points): (Vec<G1>, Vec<G2>) = {
        let mut g1s = Vec::with_capacity(items.len() * 2);
        let mut g2s = Vec::with_capacity(items.len() * 2);
        for (d, d_prime, c, omega) in &items {
            let neg_omega = -(*omega);
            g1s.push(*d * *omega);
            g2s.push(ct.abe_ct.c_prime);
            g1s.push(*c * neg_omega);
            g2s.push(*d_prime);
        }
        (g1s, g2s)
    };

    // Use multi-pairing to compute the product efficiently
    let result = multi_pairing(&g1_points, &g2_points);

    // result should now be e(g1, g2)^(alpha * s)

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
    hasher.update(b"GPSW_KEY_DERIVE");
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
    fn test_gpsw_single_attr() {
        let mut rng = thread_rng();

        // Setup
        let (mpk, msk) = setup(&mut rng);

        // Create a key with simple policy: developer
        let policy = PolicyNode::Attr("developer".to_string());
        let sk = keygen(&mut rng, &mpk, &msk, &policy).unwrap();

        // Encrypt under that attribute
        let attributes = vec!["developer".to_string()];
        let plaintext = b"Single attribute KP-ABE";
        let ct = encrypt(&mut rng, &mpk, &attributes, plaintext).unwrap();

        // Decrypt should succeed
        let decrypted = decrypt(&mpk, &sk, &ct).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_gpsw_simple_or() {
        let mut rng = thread_rng();

        // Setup
        let (mpk, msk) = setup(&mut rng);

        // Create a key with policy: admin OR manager
        let policy = PolicyNode::Or(vec![
            PolicyNode::Attr("admin".to_string()),
            PolicyNode::Attr("manager".to_string()),
        ]);
        let sk = keygen(&mut rng, &mpk, &msk, &policy).unwrap();

        // Encrypt under only one attribute
        let attributes = vec!["manager".to_string()];
        let plaintext = b"Secret for managers";
        let ct = encrypt(&mut rng, &mpk, &attributes, plaintext).unwrap();

        // Decrypt should succeed
        let decrypted = decrypt(&mpk, &sk, &ct).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_gpsw_simple_and() {
        let mut rng = thread_rng();

        // Setup
        let (mpk, msk) = setup(&mut rng);

        // Create a key with policy: admin AND developer
        let policy = PolicyNode::And(vec![
            PolicyNode::Attr("admin".to_string()),
            PolicyNode::Attr("developer".to_string()),
        ]);
        let sk = keygen(&mut rng, &mpk, &msk, &policy).unwrap();

        // Encrypt under both attributes
        let attributes = vec!["admin".to_string(), "developer".to_string()];
        let plaintext = b"Secret for admin developers";
        let ct = encrypt(&mut rng, &mpk, &attributes, plaintext).unwrap();

        // Decrypt should succeed
        let decrypted = decrypt(&mpk, &sk, &ct).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_gpsw_policy_not_satisfied() {
        let mut rng = thread_rng();

        // Setup
        let (mpk, msk) = setup(&mut rng);

        // Create a key with policy: admin AND developer
        let policy = PolicyNode::And(vec![
            PolicyNode::Attr("admin".to_string()),
            PolicyNode::Attr("developer".to_string()),
        ]);
        let sk = keygen(&mut rng, &mpk, &msk, &policy).unwrap();

        // Encrypt under only one attribute (doesn't satisfy AND policy)
        let attributes = vec!["admin".to_string()];
        let plaintext = b"This won't decrypt";
        let ct = encrypt(&mut rng, &mpk, &attributes, plaintext).unwrap();

        // Decrypt should fail
        let result = decrypt(&mpk, &sk, &ct);
        assert!(result.is_err());
    }

    #[test]
    fn test_gpsw_extra_attributes() {
        let mut rng = thread_rng();

        // Setup
        let (mpk, msk) = setup(&mut rng);

        // Create a key with simple policy: developer
        let policy = PolicyNode::Attr("developer".to_string());
        let sk = keygen(&mut rng, &mpk, &msk, &policy).unwrap();

        // Encrypt under multiple attributes (superset of required)
        let attributes = vec![
            "admin".to_string(),
            "developer".to_string(),
            "tester".to_string(),
        ];
        let plaintext = b"Extra attributes OK";
        let ct = encrypt(&mut rng, &mpk, &attributes, plaintext).unwrap();

        // Decrypt should succeed (policy is subset of attributes)
        let decrypted = decrypt(&mpk, &sk, &ct).unwrap();
        assert_eq!(decrypted, plaintext);
    }
}
