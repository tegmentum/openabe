//! AC17 CP-ABE (Agrawal-Chase 2017 Ciphertext-Policy ABE)
//!
//! Implementation inspired by:
//! "Practical Attribute-Based Encryption: Traitor Tracing, Revocation, and Large Universe"
//! Shashank Agrawal and Melissa Chase, ACM CCS 2017
//!
//! This is a CP-ABE scheme optimized for efficiency with:
//! - Constant-size secret key components per attribute
//! - Large universe construction (hash-based attributes)
//! - Full LSSS policy support
//!
//! The construction is adapted for Type-3 pairings (BLS12-381).

use crate::error::AbeError;
use crate::lsss::{PolicyNode, get_or_compute_lsss};
use crate::utils::{hash_to_g1_keyed_cached, aes};
use rabe_bls12381::{Fr, G1, G2, Gt, pairing};
use rand::{RngCore, CryptoRng};
use std::collections::HashMap;
use zeroize::Zeroize;

#[cfg(feature = "parallel")]
use rayon::prelude::*;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Hash key length in bytes
const HASH_KEY_LEN: usize = 32;

/// Master Public Key for AC17 CP-ABE
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Mpk {
    /// Generator g in G1
    pub g: G1,
    /// Generator h in G2
    pub h: G2,
    /// g^a in G1
    pub g_a: G1,
    /// e(g, h)^alpha
    pub e_gh_alpha: Gt,
    /// Hash key for attribute hashing
    pub k: Vec<u8>,
}

/// Master Secret Key for AC17 CP-ABE
///
/// # Security
///
/// This structure contains secret key material that is zeroized on drop.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Msk {
    /// Alpha exponent
    pub alpha: Fr,
    /// a exponent
    pub a: Fr,
}

impl Drop for Msk {
    fn drop(&mut self) {
        self.alpha = Fr::zero();
        self.a = Fr::zero();
    }
}

/// User Secret Key for AC17 CP-ABE
///
/// In AC17, all attributes share a single random r value.
/// K and L are computed once, while K_attr is computed per attribute.
///
/// # Security
///
/// This structure contains secret key material that is zeroized on drop.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SecretKey {
    /// List of attributes this key is for
    pub attributes: Vec<String>,
    /// K = h^(alpha + a*r) - shared component (in G2)
    pub k: G2,
    /// L = h^r - shared component (in G2)
    pub l: G2,
    /// K_attr = H(attr)^r for each attribute (in G1)
    pub k_attrs: HashMap<String, G1>,
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        for attr in &mut self.attributes {
            attr.zeroize();
        }
        self.attributes.clear();
        self.k_attrs.clear();
    }
}

/// Ciphertext component for a row in the policy LSSS
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct CiphertextComponent {
    /// Attribute for this row
    pub attr: String,
    /// C1 = g_a^share * H(attr)^(-t) (in G1)
    pub c1: G1,
    /// C2 = h^t (in G2)
    pub c2: G2,
}

/// Ciphertext for AC17 CP-ABE
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Ciphertext {
    /// The policy in canonical string form
    pub policy: String,
    /// C = g^s
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

/// Setup: Generate master public and secret keys
pub fn setup<R: RngCore + CryptoRng>(rng: &mut R) -> (Mpk, Msk) {
    // Generate random exponents
    let alpha = Fr::random(rng);
    let a = Fr::random(rng);

    // Generators
    let g = G1::one();
    let h = G2::one();

    // Compute public key elements
    let g_a = g * a;
    let h_alpha = h * alpha;
    let e_gh_alpha = pairing(g, h_alpha); // e(g, h)^alpha

    // Generate hash key
    let mut k = vec![0u8; HASH_KEY_LEN];
    rng.fill_bytes(&mut k);

    let mpk = Mpk {
        g,
        h,
        g_a,
        e_gh_alpha,
        k,
    };

    let msk = Msk { alpha, a };

    (mpk, msk)
}

/// KeyGen: Generate a secret key for a user with given attributes
///
/// All attributes share a single random r value. K and L are computed once,
/// while K_attr is computed for each attribute.
pub fn keygen<R: RngCore + CryptoRng>(
    rng: &mut R,
    mpk: &Mpk,
    msk: &Msk,
    attributes: &[String],
) -> Result<SecretKey, AbeError> {
    // Generate a single random r for all attributes
    let r = Fr::random(rng);

    // K = h^alpha * h^(a*r) = h^(alpha + a*r)
    let k = mpk.h * msk.alpha + mpk.h * (msk.a * r);

    // L = h^r
    let l = mpk.h * r;

    // Compute K_attr for each attribute (parallelized when enabled)
    #[cfg(feature = "parallel")]
    let k_attrs: HashMap<String, G1> = attributes
        .par_iter()
        .map(|attr| {
            let h_attr = hash_to_g1_keyed_cached(&mpk.k, attr);
            (attr.clone(), h_attr * r)
        })
        .collect();

    #[cfg(not(feature = "parallel"))]
    let k_attrs: HashMap<String, G1> = attributes
        .iter()
        .map(|attr| {
            let h_attr = hash_to_g1_keyed_cached(&mpk.k, attr);
            (attr.clone(), h_attr * r)
        })
        .collect();

    Ok(SecretKey {
        attributes: attributes.to_vec(),
        k,
        l,
        k_attrs,
    })
}

/// Encrypt: Encrypt a message under an access policy
pub fn encrypt<R: RngCore + CryptoRng>(
    rng: &mut R,
    mpk: &Mpk,
    policy: &PolicyNode,
    plaintext: &[u8],
) -> Result<FullCiphertext, AbeError> {
    // Convert policy to LSSS matrix (cached for repeated policies)
    let lsss = get_or_compute_lsss(policy)?;

    // Generate random s
    let s = Fr::random(rng);

    // C = g^s
    let c = mpk.g * s;

    // e(g, h)^(alpha*s) for key derivation
    let e_gh_alpha_s = mpk.e_gh_alpha.pow(&s);

    // Share s using LSSS
    let shares = lsss.share_secret(rng, s);

    // Pre-generate random t values for parallel processing
    let t_values: Vec<Fr> = shares.iter().map(|_| Fr::random(rng)).collect();

    // Compute per-row components (parallelized when enabled)
    #[cfg(feature = "parallel")]
    let components: Vec<CiphertextComponent> = shares
        .par_iter()
        .zip(t_values.par_iter())
        .map(|(share, t)| {
            let h_attr = hash_to_g1_keyed_cached(&mpk.k, &share.attr);
            let c1 = mpk.g_a * share.share - h_attr * *t;
            let c2 = mpk.h * *t;
            CiphertextComponent {
                attr: share.attr.clone(),
                c1,
                c2,
            }
        })
        .collect();

    #[cfg(not(feature = "parallel"))]
    let components: Vec<CiphertextComponent> = shares
        .iter()
        .zip(t_values.iter())
        .map(|(share, t)| {
            let h_attr = hash_to_g1_keyed_cached(&mpk.k, &share.attr);
            let c1 = mpk.g_a * share.share - h_attr * *t;
            let c2 = mpk.h * *t;
            CiphertextComponent {
                attr: share.attr.clone(),
                c1,
                c2,
            }
        })
        .collect();

    let abe_ct = Ciphertext {
        policy: policy.to_canonical_string(),
        c,
        components,
    };

    // Derive symmetric key from GT element
    let sym_key = derive_key(&e_gh_alpha_s);

    // Encrypt plaintext with AES-GCM
    let sym_ct = aes::encrypt(&sym_key, plaintext)
        .map_err(|e| AbeError::EncryptError(e))?;

    Ok(FullCiphertext { abe_ct, sym_ct })
}

/// Decrypt: Decrypt a ciphertext using a secret key
///
/// Decryption uses pairing operations to recover e(g,h)^(alpha*s):
///
/// Since all attributes share a single r:
///   e(C, K) = e(g^s, h^(alpha + a*r)) = e(g,h)^(s*alpha + s*a*r)
///
/// For each satisfied row i with coefficient omega_i:
///   e(C1_i, L) * e(K_attr_i, C2_i)
///   = e(g_a^lambda_i * H_i^(-t_i), h^r) * e(H_i^r, h^t_i)
///   = e(g,h)^(a*lambda_i*r) * e(H_i,h)^(-t_i*r) * e(H_i,h)^(r*t_i)
///   = e(g,h)^(a*lambda_i*r)
///
/// Product with weights: prod((e(g,h)^(a*lambda_i*r))^omega_i)
///                     = e(g,h)^(a*r*sum(omega_i*lambda_i))
///                     = e(g,h)^(a*r*s)
///
/// Final: e(C, K) / product = e(g,h)^(s*alpha + s*a*r - a*r*s) = e(g,h)^(s*alpha)
pub fn decrypt(
    _mpk: &Mpk,
    sk: &SecretKey,
    ct: &FullCiphertext,
) -> Result<Vec<u8>, AbeError> {
    // Parse policy from ciphertext
    let policy = crate::schemes::waters::parse_policy(&ct.abe_ct.policy)
        .map_err(|_| AbeError::PolicyNotSatisfied)?;

    // Quick check: can the policy possibly be satisfied?
    if !policy.can_satisfy_attrs(&sk.attributes) {
        return Err(AbeError::PolicyNotSatisfied);
    }

    // Get LSSS matrix (cached for repeated policies)
    let lsss = get_or_compute_lsss(&policy)?;

    // Find which rows are satisfied by the user's attributes
    let mut satisfied_attrs = Vec::new();
    let mut satisfied_ct_components: Vec<&CiphertextComponent> = Vec::new();

    for ct_comp in &ct.abe_ct.components {
        if sk.k_attrs.contains_key(&ct_comp.attr) {
            satisfied_attrs.push(ct_comp.attr.clone());
            satisfied_ct_components.push(ct_comp);
        }
    }

    if satisfied_ct_components.is_empty() {
        return Err(AbeError::PolicyNotSatisfied);
    }

    // Get reconstruction coefficients
    let coeffs = lsss.recover_coefficients(&satisfied_attrs)
        .map_err(|_| AbeError::PolicyNotSatisfied)?;

    // Compute e(C, K) = e(g^s, h^(alpha + a*r))
    let e_c_k = pairing(ct.abe_ct.c, sk.k);

    // Collect items for parallel processing
    let items: Vec<_> = satisfied_ct_components
        .iter()
        .filter_map(|ct_comp| {
            let omega = coeffs.get(&ct_comp.attr)?;
            let k_attr = sk.k_attrs.get(&ct_comp.attr)?;
            Some((ct_comp.c1, ct_comp.c2, *k_attr, *omega))
        })
        .collect();

    // Compute the cancel term: product of e(C1_i, L) * e(K_attr_i, C2_i) weighted by omega_i
    #[cfg(feature = "parallel")]
    let cancel_term = items
        .par_iter()
        .map(|(c1, c2, k_attr, omega)| {
            let p1 = pairing(*c1, sk.l);
            let p2 = pairing(*k_attr, *c2);
            (p1 * p2).pow(omega)
        })
        .reduce(|| Gt::one(), |acc, term| acc * term);

    #[cfg(not(feature = "parallel"))]
    let cancel_term = items
        .iter()
        .fold(Gt::one(), |acc, (c1, c2, k_attr, omega)| {
            let p1 = pairing(*c1, sk.l);
            let p2 = pairing(*k_attr, *c2);
            acc * (p1 * p2).pow(omega)
        });

    // Result = e(C, K) / cancel_term = e(g,h)^(s*alpha)
    let result = e_c_k * cancel_term.inverse();

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
    hasher.update(b"AC17_KEY_DERIVE");
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
    fn test_ac17_single_attr() {
        let mut rng = thread_rng();

        // Setup
        let (mpk, msk) = setup(&mut rng);

        // Keygen
        let attrs = vec!["admin".to_string()];
        let sk = keygen(&mut rng, &mpk, &msk, &attrs).unwrap();

        // Encrypt
        let policy = PolicyNode::Attr("admin".to_string());
        let plaintext = b"AC17 test message";
        let ct = encrypt(&mut rng, &mpk, &policy, plaintext).unwrap();

        // Decrypt
        let decrypted = decrypt(&mpk, &sk, &ct).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_ac17_and_policy() {
        let mut rng = thread_rng();

        // Setup
        let (mpk, msk) = setup(&mut rng);

        // Keygen with both attributes
        let attrs = vec!["admin".to_string(), "developer".to_string()];
        let sk = keygen(&mut rng, &mpk, &msk, &attrs).unwrap();

        // Encrypt with AND policy
        let policy = PolicyNode::And(vec![
            PolicyNode::Attr("admin".to_string()),
            PolicyNode::Attr("developer".to_string()),
        ]);
        let plaintext = b"Admin developer secret";
        let ct = encrypt(&mut rng, &mpk, &policy, plaintext).unwrap();

        // Decrypt
        let decrypted = decrypt(&mpk, &sk, &ct).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_ac17_or_policy() {
        let mut rng = thread_rng();

        // Setup
        let (mpk, msk) = setup(&mut rng);

        // Keygen with only one attribute
        let attrs = vec!["manager".to_string()];
        let sk = keygen(&mut rng, &mpk, &msk, &attrs).unwrap();

        // Encrypt with OR policy
        let policy = PolicyNode::Or(vec![
            PolicyNode::Attr("admin".to_string()),
            PolicyNode::Attr("manager".to_string()),
        ]);
        let plaintext = b"Manager or admin secret";
        let ct = encrypt(&mut rng, &mpk, &policy, plaintext).unwrap();

        // Decrypt
        let decrypted = decrypt(&mpk, &sk, &ct).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_ac17_policy_not_satisfied() {
        let mut rng = thread_rng();

        // Setup
        let (mpk, msk) = setup(&mut rng);

        // Keygen with wrong attributes
        let attrs = vec!["user".to_string()];
        let sk = keygen(&mut rng, &mpk, &msk, &attrs).unwrap();

        // Encrypt with policy user doesn't satisfy
        let policy = PolicyNode::Attr("admin".to_string());
        let plaintext = b"Admin only";
        let ct = encrypt(&mut rng, &mpk, &policy, plaintext).unwrap();

        // Decrypt should fail
        let result = decrypt(&mpk, &sk, &ct);
        assert!(result.is_err());
    }

    #[test]
    fn test_ac17_threshold() {
        let mut rng = thread_rng();

        // Setup
        let (mpk, msk) = setup(&mut rng);

        // Keygen with 2 of 3 attributes
        let attrs = vec!["developer".to_string(), "tester".to_string()];
        let sk = keygen(&mut rng, &mpk, &msk, &attrs).unwrap();

        // Encrypt with 2-of-3 threshold
        let policy = PolicyNode::Threshold(2, vec![
            PolicyNode::Attr("admin".to_string()),
            PolicyNode::Attr("developer".to_string()),
            PolicyNode::Attr("tester".to_string()),
        ]);
        let plaintext = b"Threshold secret";
        let ct = encrypt(&mut rng, &mpk, &policy, plaintext).unwrap();

        // Decrypt should succeed (have 2 of 3)
        let decrypted = decrypt(&mpk, &sk, &ct).unwrap();
        assert_eq!(decrypted, plaintext);
    }
}
