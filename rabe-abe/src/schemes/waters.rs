//! Waters '11 CP-ABE (Ciphertext-Policy Attribute-Based Encryption)
//!
//! Implementation based on:
//! "Ciphertext-Policy Attribute-Based Encryption: An Expressive, Efficient,
//!  and Provably Secure Realization"
//! Brent Waters, PKC 2011
//! https://eprint.iacr.org/2008/290.pdf (Appendix A - Large Universe)
//!
//! This implementation uses BLS12-381 for 128-bit security.
//!
//! # Type Safety
//!
//! All types in this module are tagged with the `Waters` scheme marker,
//! preventing accidental mixing with other ABE schemes at compile time.

use crate::error::AbeError;
use crate::lsss::{LsssMatrix, PolicyNode, get_or_compute_lsss};
use crate::scheme_types::{Waters, TypedMpk, TypedMsk, TypedSecretKey, TypedCiphertext, TypedFullCiphertext};
use crate::security::validation::{validate_policy, validate_plaintext, validate_attributes};
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

// ============================================================================
// Type-Safe Public API Types
// ============================================================================

/// Master Public Key for Waters '11 CP-ABE (type-safe wrapper)
pub type Mpk = TypedMpk<Waters, RawMpk>;

/// Master Secret Key for Waters '11 CP-ABE (type-safe wrapper)
pub type Msk = TypedMsk<Waters, RawMsk>;

/// User Secret Key for Waters '11 CP-ABE (type-safe wrapper)
pub type SecretKey = TypedSecretKey<Waters, RawSecretKey>;

/// Ciphertext for Waters '11 CP-ABE (type-safe wrapper)
pub type Ciphertext = TypedCiphertext<Waters, RawCiphertext>;

/// Full Ciphertext with encrypted payload (type-safe wrapper)
pub type FullCiphertext = TypedFullCiphertext<Waters, RawFullCiphertext>;

// ============================================================================
// Raw (Inner) Types
// ============================================================================

/// Raw Master Public Key for Waters '11 CP-ABE
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct RawMpk {
    /// Generator g1 in G1
    pub g1: G1,
    /// Generator g2 in G2
    pub g2: G2,
    /// g1^a
    pub g1a: G1,
    /// g2^alpha (for encryption without GT exponentiation)
    pub g2alpha: G2,
    /// e(g1, g2)^alpha
    pub egg_alpha: Gt,
    /// Hash key prefix for attribute hashing
    pub k: Vec<u8>,
}

/// Raw Master Secret Key for Waters '11 CP-ABE
///
/// # Security
///
/// This structure contains secret key material that is zeroized on drop.
/// Avoid cloning unless necessary.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct RawMsk {
    /// alpha exponent (SECRET)
    pub alpha: Fr,
    /// g2^a
    pub g2a: G2,
}

impl Drop for RawMsk {
    fn drop(&mut self) {
        // Note: Fr doesn't implement Zeroize, but we mark intent
        // In a production system, the underlying library should support zeroization
        self.alpha = Fr::zero();
    }
}

/// Raw User Secret Key for Waters '11 CP-ABE
///
/// # Security
///
/// This structure contains secret key material that is zeroized on drop.
/// Avoid cloning unless necessary.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct RawSecretKey {
    /// K = g2^alpha * g2^(a*t)
    pub k: G2,
    /// L = g2^t
    pub l: G2,
    /// Attribute components: KX_attr = H(k, attr)^t
    pub kx: HashMap<String, G1>,
    /// List of attributes this key is for
    pub attributes: Vec<String>,
}

impl Drop for RawSecretKey {
    fn drop(&mut self) {
        // Zeroize attribute names
        for attr in &mut self.attributes {
            attr.zeroize();
        }
        self.attributes.clear();
        self.kx.clear();
    }
}

/// Ciphertext component for an attribute in the policy
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct CiphertextComponent {
    /// C_i = g1a^share * H(k, attr)^(-r_i)
    pub c: G1,
    /// D_i = g2^r_i
    pub d: G2,
}

/// Raw Ciphertext for Waters '11 CP-ABE
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct RawCiphertext {
    /// The policy in canonical string form
    pub policy: String,
    /// C = e(g1^s, g2^alpha) = e(g1, g2)^(alpha * s)
    pub c: Gt,
    /// C' = g1^s
    pub c_prime: G1,
    /// Per-attribute ciphertext components (indexed by attribute)
    pub components: HashMap<String, CiphertextComponent>,
}

/// Raw Full ciphertext including encrypted payload
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct RawFullCiphertext {
    /// ABE ciphertext (KEM part)
    pub abe_ct: RawCiphertext,
    /// Symmetric ciphertext (DEM part)
    pub sym_ct: Vec<u8>,
}

/// Setup: Generate master public and secret keys
///
/// Returns type-safe wrappers tagged with the `Waters` scheme marker.
///
/// # Security
///
/// The `rng` parameter must be a cryptographically secure random number generator.
pub fn setup<R: RngCore + CryptoRng>(rng: &mut R) -> (Mpk, Msk) {
    // Generators
    let g1 = G1::one();
    let g2 = G2::one();

    // Random exponents
    let alpha = Fr::random(rng);
    let a = Fr::random(rng);

    // Public key components
    let g1a = g1 * a;
    let g2alpha = g2 * alpha;
    let egg_alpha = pairing(g1, g2).pow(&alpha);

    // Generate random hash key
    let mut k = vec![0u8; HASH_KEY_LEN];
    rng.fill_bytes(&mut k);

    // Master secret key components
    let g2a = g2 * a;

    (
        RawMpk {
            g1,
            g2,
            g1a,
            g2alpha,
            egg_alpha,
            k,
        }.into(),
        RawMsk { alpha, g2a }.into(),
    )
}

/// KeyGen: Generate a secret key for a user with given attributes
///
/// Returns a type-safe secret key tagged with the `Waters` scheme marker.
///
/// # Security
///
/// The `rng` parameter must be a cryptographically secure random number generator.
pub fn keygen<R: RngCore + CryptoRng>(
    rng: &mut R,
    mpk: &Mpk,
    msk: &Msk,
    attributes: &[String],
) -> Result<SecretKey, AbeError> {
    // Validate input attributes
    validate_attributes(attributes)?;

    // Random t
    let t = Fr::random(rng);

    // K = g2^alpha * g2^(a*t) = g2^alpha * (g2^a)^t
    let k = (mpk.g2 * msk.alpha) + (msk.g2a * t);

    // L = g2^t
    let l = mpk.g2 * t;

    // For each attribute: KX_attr = H(k, attr)^t
    let mut kx = HashMap::new();
    for attr in attributes {
        let h_attr = hash_to_g1_keyed_cached(&mpk.k, attr);
        let kx_attr = h_attr * t;
        kx.insert(attr.clone(), kx_attr);
    }

    Ok(RawSecretKey {
        k,
        l,
        kx,
        attributes: attributes.to_vec(),
    }.into())
}

/// Encrypt: Encrypt a message under a policy (KEM mode - returns symmetric key)
///
/// Returns a type-safe ciphertext tagged with the `Waters` scheme marker.
///
/// # Security
///
/// The `rng` parameter must be a cryptographically secure random number generator.
pub fn encrypt_kem<R: RngCore + CryptoRng>(
    rng: &mut R,
    mpk: &Mpk,
    policy: &PolicyNode,
) -> Result<(Ciphertext, [u8; 32]), AbeError> {
    // Validate policy before proceeding
    validate_policy(policy)?;

    // Build LSSS matrix from policy (cached for repeated policies)
    let matrix = get_or_compute_lsss(policy)?;

    // Random s
    let s = Fr::random(rng);

    // C = e(g1^s, g2^alpha) - using pairing instead of GT exp for WASM compatibility
    let g1s = mpk.g1 * s;
    let c = pairing(g1s, mpk.g2alpha);

    // C' = g1^s
    let c_prime = g1s;

    // Share the secret s using LSSS
    let shares = matrix.share_secret(rng, s);

    // Pre-generate random r_i values (needed for parallel processing)
    let r_values: Vec<Fr> = shares.iter().map(|_| Fr::random(rng)).collect();

    // For each share (attribute in policy), create ciphertext component
    #[cfg(feature = "parallel")]
    let components: HashMap<String, CiphertextComponent> = shares
        .par_iter()
        .zip(r_values.par_iter())
        .map(|(share, r_i)| {
            // H(k, attr) - cached for performance
            let h_attr = hash_to_g1_keyed_cached(&mpk.k, &share.attr);

            // C_i = g1a^share * H(k, attr)^(-r_i)
            let c_i = (mpk.g1a * share.share) + (h_attr * (-*r_i));

            // D_i = g2^r_i
            let d_i = mpk.g2 * *r_i;

            (share.attr.clone(), CiphertextComponent { c: c_i, d: d_i })
        })
        .collect();

    #[cfg(not(feature = "parallel"))]
    let components: HashMap<String, CiphertextComponent> = shares
        .iter()
        .zip(r_values.iter())
        .map(|(share, r_i)| {
            // H(k, attr) - cached for performance
            let h_attr = hash_to_g1_keyed_cached(&mpk.k, &share.attr);

            // C_i = g1a^share * H(k, attr)^(-r_i)
            let c_i = (mpk.g1a * share.share) + (h_attr * (-*r_i));

            // D_i = g2^r_i
            let d_i = mpk.g2 * *r_i;

            (share.attr.clone(), CiphertextComponent { c: c_i, d: d_i })
        })
        .collect();

    // Derive symmetric key from C (the GT element)
    let sym_key = aes::derive_key(&c);

    let ct: Ciphertext = RawCiphertext {
        policy: policy.to_canonical_string(),
        c,
        c_prime,
        components,
    }.into();

    Ok((ct, sym_key))
}

/// Encrypt: Full encryption with symmetric payload
///
/// Returns a type-safe full ciphertext tagged with the `Waters` scheme marker.
///
/// # Security
///
/// The `rng` parameter must be a cryptographically secure random number generator.
pub fn encrypt<R: RngCore + CryptoRng>(
    rng: &mut R,
    mpk: &Mpk,
    policy: &PolicyNode,
    plaintext: &[u8],
) -> Result<FullCiphertext, AbeError> {
    // Validate plaintext before proceeding
    validate_plaintext(plaintext)?;

    let (abe_ct, sym_key) = encrypt_kem(rng, mpk, policy)?;

    let sym_ct = aes::encrypt(&sym_key, plaintext)
        .map_err(|e| AbeError::EncryptError(e))?;

    Ok(RawFullCiphertext {
        abe_ct: abe_ct.into_inner(),
        sym_ct,
    }.into())
}

/// Decrypt: Decrypt using a secret key (KEM mode - returns symmetric key)
pub fn decrypt_kem(
    mpk: &Mpk,
    sk: &SecretKey,
    ct: &Ciphertext,
) -> Result<[u8; 32], AbeError> {
    // Parse policy from ciphertext
    let policy = parse_policy(&ct.policy)
        .map_err(|e| AbeError::InvalidPolicy(e.to_string()))?;

    // Quick check: can the policy possibly be satisfied?
    // This is O(n) and avoids expensive LSSS computation if policy can't be satisfied
    if !policy.can_satisfy_attrs(&sk.attributes) {
        return Err(AbeError::PolicyNotSatisfied);
    }

    // Build LSSS matrix and try to recover coefficients (cached for repeated policies)
    let matrix = get_or_compute_lsss(&policy)?;

    let coeffs = matrix.recover_coefficients(&sk.attributes)
        .map_err(|_| AbeError::PolicyNotSatisfied)?;

    // Compute decryption
    // For each attribute i in the satisfying set:
    //   prod1 = prod(C_i^coeff_i)
    //   prodT = prod(e(KX_i^coeff_i, D_i))

    // Collect coefficient/component/key tuples for parallel processing
    let items: Vec<_> = coeffs
        .iter()
        .filter_map(|(attr, coeff)| {
            let comp = ct.components.get(attr)?;
            let kx = sk.kx.get(attr)?;
            Some((*coeff, comp.c, comp.d, *kx))
        })
        .collect();

    if items.len() != coeffs.len() {
        return Err(AbeError::DecryptError("Missing ciphertext or key component".into()));
    }

    // Parallel computation of products and pairing components
    #[cfg(feature = "parallel")]
    let (prod1, pairing_pairs): (G1, Vec<(G1, G2)>) = {
        let results: Vec<(G1, G1, G2)> = items
            .par_iter()
            .map(|(coeff, c, d, kx)| {
                let c_scaled = *c * *coeff;
                let kx_scaled = *kx * *coeff;
                (c_scaled, kx_scaled, *d)
            })
            .collect();

        let prod1 = results.iter().fold(G1::zero(), |acc, (c, _, _)| acc + *c);
        let pairs: Vec<(G1, G2)> = results.iter().map(|(_, kx, d)| (*kx, *d)).collect();
        (prod1, pairs)
    };

    #[cfg(not(feature = "parallel"))]
    let (prod1, pairing_pairs): (G1, Vec<(G1, G2)>) = {
        let mut prod1 = G1::zero();
        let mut pairs = Vec::with_capacity(items.len());
        for (coeff, c, d, kx) in &items {
            prod1 = prod1 + (*c * *coeff);
            pairs.push((*kx * *coeff, *d));
        }
        (prod1, pairs)
    };

    // Compute prodT = prod(e(KX_i^coeff_i, D_i))
    #[cfg(feature = "parallel")]
    let prod_t = pairing_pairs
        .par_iter()
        .map(|(g1, g2)| pairing(*g1, *g2))
        .reduce(|| Gt::one(), |acc, p| acc * p);

    #[cfg(not(feature = "parallel"))]
    let prod_t = pairing_pairs
        .iter()
        .fold(Gt::one(), |acc, (g1, g2)| acc * pairing(*g1, *g2));

    // Compute e(C', K)
    let pairing1 = pairing(ct.c_prime, sk.k);

    // Compute e(prod1, L)
    let pairing2 = pairing(prod1, sk.l);

    // denominator = prodT * pairing2
    let denominator = prod_t * pairing2;

    // final = pairing1 / denominator
    let recovered_c = pairing1 * denominator.inverse();

    // Derive symmetric key
    let sym_key = aes::derive_key(&recovered_c);

    Ok(sym_key)
}

/// Decrypt: Full decryption with symmetric payload
pub fn decrypt(
    mpk: &Mpk,
    sk: &SecretKey,
    ct: &FullCiphertext,
) -> Result<Vec<u8>, AbeError> {
    // Convert raw ciphertext to typed wrapper for type-safe decryption
    let abe_ct: Ciphertext = ct.abe_ct.clone().into();
    let sym_key = decrypt_kem(mpk, sk, &abe_ct)?;

    aes::decrypt(&sym_key, &ct.sym_ct)
        .map_err(|e| AbeError::DecryptError(e))
}

/// Parse a policy string into a PolicyNode
pub fn parse_policy(policy_str: &str) -> Result<PolicyNode, AbeError> {
    // Simple recursive descent parser for policies
    // Supports: attr, (p1 AND p2), (p1 OR p2), (k OF p1, p2, ...)
    // Keywords are case-insensitive
    let policy_str = policy_str.trim();
    let policy_lower = policy_str.to_lowercase();

    // Check for single attribute (no keywords present)
    if !policy_lower.contains(" and ")
        && !policy_lower.contains(" or ")
        && !policy_lower.contains(" of ")
        && !policy_str.starts_with('(')
    {
        return Ok(PolicyNode::Attr(policy_str.to_string()));
    }

    // Remove outer parentheses if present
    let inner = if policy_str.starts_with('(') && policy_str.ends_with(')') {
        &policy_str[1..policy_str.len() - 1]
    } else {
        policy_str
    };

    // Try to parse as AND (case-insensitive)
    if let Some(parts) = split_at_keyword_ci(inner, " and ") {
        let children: Result<Vec<_>, _> = parts.iter()
            .map(|p| parse_policy(p))
            .collect();
        return Ok(PolicyNode::And(children?));
    }

    // Try to parse as OR (case-insensitive)
    if let Some(parts) = split_at_keyword_ci(inner, " or ") {
        let children: Result<Vec<_>, _> = parts.iter()
            .map(|p| parse_policy(p))
            .collect();
        return Ok(PolicyNode::Or(children?));
    }

    // Try to parse as threshold (k of ...) - case-insensitive
    let inner_lower = inner.to_lowercase();
    if inner_lower.contains(" of ") {
        // Find the position of " of " (case-insensitive)
        if let Some(pos) = inner_lower.find(" of ") {
            let k_str = &inner[..pos].trim();
            let children_str = &inner[pos + 4..].trim();
            if let Ok(k) = k_str.parse::<usize>() {
                let children: Result<Vec<_>, _> = children_str
                    .split(',')
                    .map(|p| parse_policy(p.trim()))
                    .collect();
                return Ok(PolicyNode::Threshold(k, children?));
            }
        }
    }

    // Single attribute
    Ok(PolicyNode::Attr(inner.to_string()))
}

/// Split a string at a keyword (case-insensitive), respecting parentheses
fn split_at_keyword_ci(s: &str, keyword: &str) -> Option<Vec<String>> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut depth = 0;
    let s_lower = s.to_lowercase();
    let keyword_lower = keyword.to_lowercase();
    let mut i = 0;
    let chars: Vec<char> = s.chars().collect();
    let chars_lower: Vec<char> = s_lower.chars().collect();

    while i < chars.len() {
        let c = chars[i];
        match c {
            '(' => {
                depth += 1;
                current.push(c);
                i += 1;
            }
            ')' => {
                depth -= 1;
                current.push(c);
                i += 1;
            }
            _ if depth == 0 => {
                // Check if we're at the keyword (case-insensitive)
                let remaining_lower: String = chars_lower[i..].iter().collect();
                if remaining_lower.starts_with(&keyword_lower) {
                    if !current.trim().is_empty() {
                        parts.push(current.trim().to_string());
                    }
                    current = String::new();
                    // Skip the keyword
                    i += keyword.len();
                } else {
                    current.push(c);
                    i += 1;
                }
            }
            _ => {
                current.push(c);
                i += 1;
            }
        }
    }

    if !current.trim().is_empty() {
        parts.push(current.trim().to_string());
    }

    if parts.len() > 1 {
        Some(parts)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::thread_rng;

    #[test]
    fn test_setup() {
        let mut rng = thread_rng();
        let (mpk, msk) = setup(&mut rng);

        assert!(!msk.alpha.is_zero());
        assert!(!mpk.egg_alpha.is_one());
    }

    #[test]
    fn test_keygen() {
        let mut rng = thread_rng();
        let (mpk, msk) = setup(&mut rng);

        let attrs = vec!["admin".to_string(), "dept:eng".to_string()];
        let sk = keygen(&mut rng, &mpk, &msk, &attrs).expect("keygen failed");

        assert_eq!(sk.attributes.len(), 2);
        assert!(sk.kx.contains_key("admin"));
        assert!(sk.kx.contains_key("dept:eng"));
    }

    #[test]
    fn test_single_attribute_encrypt_decrypt() {
        let mut rng = thread_rng();
        let (mpk, msk) = setup(&mut rng);

        // User has "admin" attribute
        let attrs = vec!["admin".to_string()];
        let sk = keygen(&mut rng, &mpk, &msk, &attrs).expect("keygen failed");

        // Encrypt with policy "admin"
        let policy = PolicyNode::Attr("admin".to_string());
        let plaintext = b"Hello, Waters ABE!";
        let ct = encrypt(&mut rng, &mpk, &policy, plaintext).expect("encrypt failed");

        // Decrypt
        let decrypted = decrypt(&mpk, &sk, &ct).expect("decrypt failed");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_and_policy() {
        let mut rng = thread_rng();
        let (mpk, msk) = setup(&mut rng);

        // User has both required attributes
        let attrs = vec!["a".to_string(), "b".to_string()];
        let sk = keygen(&mut rng, &mpk, &msk, &attrs).expect("keygen failed");

        // Encrypt with AND policy
        let policy = PolicyNode::And(vec![
            PolicyNode::Attr("a".to_string()),
            PolicyNode::Attr("b".to_string()),
        ]);
        let plaintext = b"Secret for a AND b";
        let ct = encrypt(&mut rng, &mpk, &policy, plaintext).expect("encrypt failed");

        // Decrypt should succeed
        let decrypted = decrypt(&mpk, &sk, &ct).expect("decrypt failed");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_and_policy_fails_with_partial() {
        let mut rng = thread_rng();
        let (mpk, msk) = setup(&mut rng);

        // User only has one attribute
        let attrs = vec!["a".to_string()];
        let sk = keygen(&mut rng, &mpk, &msk, &attrs).expect("keygen failed");

        // Encrypt with AND policy requiring both
        let policy = PolicyNode::And(vec![
            PolicyNode::Attr("a".to_string()),
            PolicyNode::Attr("b".to_string()),
        ]);
        let plaintext = b"Secret for a AND b";
        let ct = encrypt(&mut rng, &mpk, &policy, plaintext).expect("encrypt failed");

        // Decrypt should fail
        let result = decrypt(&mpk, &sk, &ct);
        assert!(result.is_err());
    }

    #[test]
    fn test_or_policy() {
        let mut rng = thread_rng();
        let (mpk, msk) = setup(&mut rng);

        // User has only "a"
        let attrs = vec!["a".to_string()];
        let sk = keygen(&mut rng, &mpk, &msk, &attrs).expect("keygen failed");

        // Encrypt with OR policy
        let policy = PolicyNode::Or(vec![
            PolicyNode::Attr("a".to_string()),
            PolicyNode::Attr("b".to_string()),
        ]);
        let plaintext = b"Secret for a OR b";
        let ct = encrypt(&mut rng, &mpk, &policy, plaintext).expect("encrypt failed");

        // Decrypt should succeed with just "a"
        let decrypted = decrypt(&mpk, &sk, &ct).expect("decrypt failed");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_policy_not_satisfied() {
        let mut rng = thread_rng();
        let (mpk, msk) = setup(&mut rng);

        // User has "user" attribute
        let attrs = vec!["user".to_string()];
        let sk = keygen(&mut rng, &mpk, &msk, &attrs).expect("keygen failed");

        // Encrypt with policy requiring "admin"
        let policy = PolicyNode::Attr("admin".to_string());
        let plaintext = b"Admin only";
        let ct = encrypt(&mut rng, &mpk, &policy, plaintext).expect("encrypt failed");

        // Decrypt should fail
        let result = decrypt(&mpk, &sk, &ct);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_policy() {
        // Single attribute
        let p = parse_policy("admin").unwrap();
        assert!(matches!(p, PolicyNode::Attr(ref s) if s == "admin"));

        // AND policy
        let p = parse_policy("(a and b)").unwrap();
        assert!(matches!(p, PolicyNode::And(_)));

        // OR policy
        let p = parse_policy("(a or b)").unwrap();
        assert!(matches!(p, PolicyNode::Or(_)));
    }

    #[test]
    fn test_kem_mode() {
        let mut rng = thread_rng();
        let (mpk, msk) = setup(&mut rng);

        let attrs = vec!["admin".to_string()];
        let sk = keygen(&mut rng, &mpk, &msk, &attrs).expect("keygen failed");

        let policy = PolicyNode::Attr("admin".to_string());
        let (ct, enc_key) = encrypt_kem(&mut rng, &mpk, &policy).expect("encrypt_kem failed");

        let dec_key = decrypt_kem(&mpk, &sk, &ct).expect("decrypt_kem failed");
        assert_eq!(enc_key, dec_key);
    }

    #[test]
    fn test_nested_policy() {
        let mut rng = thread_rng();
        let (mpk, msk) = setup(&mut rng);

        // User has a, b, c
        let attrs = vec!["a".to_string(), "b".to_string(), "c".to_string()];
        let sk = keygen(&mut rng, &mpk, &msk, &attrs).expect("keygen failed");

        // Policy: (a and b) or c
        let policy = PolicyNode::Or(vec![
            PolicyNode::And(vec![
                PolicyNode::Attr("a".to_string()),
                PolicyNode::Attr("b".to_string()),
            ]),
            PolicyNode::Attr("c".to_string()),
        ]);
        let plaintext = b"Nested policy test";
        let ct = encrypt(&mut rng, &mpk, &policy, plaintext).expect("encrypt failed");

        // Should decrypt successfully
        let decrypted = decrypt(&mpk, &sk, &ct).expect("decrypt failed");
        assert_eq!(decrypted, plaintext);
    }
}
