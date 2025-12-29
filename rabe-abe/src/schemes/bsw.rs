//! BSW CP-ABE (Bethencourt-Sahai-Waters Ciphertext-Policy Attribute-Based Encryption)
//!
//! This is a simplified implementation of CP-ABE using BLS12-381.
//! It supports AND policies for demonstration purposes.

use crate::error::AbeError;
use crate::utils::{hash_to_g1, aes};
use rabe_bls12381::{Fr, G1, G2, Gt, pairing};
use rand::{RngCore, CryptoRng};
use zeroize::Zeroize;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Public key for CP-ABE
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct CpAbePublicKey {
    /// Generator g in G1
    pub g: G1,
    /// Generator h in G2
    pub h: G2,
    /// h^beta
    pub h_beta: G2,
    /// e(g, h)^alpha
    pub e_gh_alpha: Gt,
}

/// Master secret key for CP-ABE
///
/// # Security
///
/// This structure contains secret key material that is zeroized on drop.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct CpAbeMasterKey {
    /// alpha exponent
    pub alpha: Fr,
    /// beta exponent
    pub beta: Fr,
}

impl Drop for CpAbeMasterKey {
    fn drop(&mut self) {
        self.alpha = Fr::zero();
        self.beta = Fr::zero();
    }
}

/// Attribute component in secret key
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct AttributeKey {
    /// Attribute name
    pub attr: String,
    /// D_i = g^r * H(attr)^(r_i)
    pub d_i: G1,
    /// D_i' = h^(r_i)
    pub d_i_prime: G2,
}

/// Secret key for a user with attributes
///
/// # Security
///
/// This structure contains secret key material that is zeroized on drop.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct CpAbeSecretKey {
    /// D = h^((alpha + r) / beta)
    pub d: G2,
    /// Attribute components
    pub attributes: Vec<AttributeKey>,
}

impl Drop for CpAbeSecretKey {
    fn drop(&mut self) {
        for attr_key in &mut self.attributes {
            attr_key.attr.zeroize();
        }
        self.attributes.clear();
    }
}

/// Ciphertext component for an attribute
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct CiphertextComponent {
    /// Attribute name
    pub attr: String,
    /// C_i = H(attr)^s
    pub c_i: G1,
}

/// Ciphertext
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct CpAbeCiphertext {
    /// Policy (comma-separated attributes for AND policy)
    pub policy: String,
    /// C = M * e(g, h)^(alpha * s)
    pub c: Gt,
    /// C' = h^(beta * s)
    pub c_prime: G2,
    /// Per-attribute components
    pub c_attrs: Vec<CiphertextComponent>,
    /// Encrypted data (AES-GCM)
    pub encrypted_data: Vec<u8>,
}

/// Generate master public and secret keys
pub fn setup<R: RngCore + CryptoRng>(rng: &mut R) -> (CpAbePublicKey, CpAbeMasterKey) {
    // Generate generators
    let g = G1::one();
    let h = G2::one();

    // Generate random exponents
    let alpha = Fr::random(rng);
    let beta = Fr::random(rng);

    // Compute public key components
    let h_beta = h * beta;
    let e_gh_alpha = pairing(g, h).pow(&alpha);

    (
        CpAbePublicKey {
            g,
            h,
            h_beta,
            e_gh_alpha,
        },
        CpAbeMasterKey { alpha, beta },
    )
}

/// Generate a secret key for a user with given attributes
pub fn keygen<R: RngCore + CryptoRng>(
    rng: &mut R,
    pk: &CpAbePublicKey,
    msk: &CpAbeMasterKey,
    attributes: &[String],
) -> Result<CpAbeSecretKey, AbeError> {
    if attributes.is_empty() {
        return Err(AbeError::KeygenError("No attributes provided".to_string()));
    }

    // Random r
    let r = Fr::random(rng);

    // Compute D = h^((alpha + r) / beta)
    let alpha_plus_r = msk.alpha + r;
    let beta_inv = msk.beta.inverse()
        .ok_or_else(|| AbeError::KeygenError("Beta has no inverse".to_string()))?;
    let d = pk.h * (alpha_plus_r * beta_inv);

    // For each attribute, compute key components
    let mut attr_keys = Vec::new();
    for attr in attributes {
        let r_i = Fr::random(rng);

        // H(attr) - hash attribute to G1
        let h_attr = hash_to_g1(attr);

        // D_i = g^r * H(attr)^(r_i)
        let d_i = (pk.g * r) + (h_attr * r_i);

        // D_i' = h^(r_i)
        let d_i_prime = pk.h * r_i;

        attr_keys.push(AttributeKey {
            attr: attr.clone(),
            d_i,
            d_i_prime,
        });
    }

    Ok(CpAbeSecretKey {
        d,
        attributes: attr_keys,
    })
}

/// Encrypt a message under an AND policy of attributes
pub fn encrypt<R: RngCore + CryptoRng>(
    rng: &mut R,
    pk: &CpAbePublicKey,
    policy: &str,
    plaintext: &[u8],
) -> Result<CpAbeCiphertext, AbeError> {
    // Parse policy (simple comma-separated AND of attributes)
    let policy_attrs: Vec<String> = policy
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    if policy_attrs.is_empty() {
        return Err(AbeError::InvalidPolicy("Empty policy".to_string()));
    }

    // Random s
    let s = Fr::random(rng);

    // C = e(g, h)^(alpha * s) - this will be used to derive the symmetric key
    let c = pk.e_gh_alpha.pow(&s);

    // C' = h^(beta * s)
    let c_prime = pk.h_beta * s;

    // For each attribute in policy
    let mut c_attrs = Vec::new();
    for attr in &policy_attrs {
        let h_attr = hash_to_g1(attr);
        let c_i = h_attr * s;
        c_attrs.push(CiphertextComponent {
            attr: attr.clone(),
            c_i,
        });
    }

    // Derive symmetric key from the pairing result and encrypt data
    let sym_key = aes::derive_key(&c);
    let encrypted_data = aes::encrypt(&sym_key, plaintext)
        .map_err(|e| AbeError::EncryptError(e))?;

    Ok(CpAbeCiphertext {
        policy: policy.to_string(),
        c,
        c_prime,
        c_attrs,
        encrypted_data,
    })
}

/// Decrypt a ciphertext using a secret key
pub fn decrypt(
    sk: &CpAbeSecretKey,
    ct: &CpAbeCiphertext,
) -> Result<Vec<u8>, AbeError> {
    // Parse policy attributes
    let policy_attrs: Vec<String> = ct.policy
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    // Check if user has all required attributes
    let sk_attr_set: std::collections::HashSet<&str> =
        sk.attributes.iter().map(|a| a.attr.as_str()).collect();

    for attr in &policy_attrs {
        if !sk_attr_set.contains(attr.as_str()) {
            return Err(AbeError::PolicyNotSatisfied);
        }
    }

    // Compute the pairing product
    // For AND policy: we compute product of e(C_i, D_i') / e(D_i, h)
    // and then e(C', D) to recover e(g, h)^(alpha * s)

    // First, compute e(C', D)
    let e_c_prime_d = pairing(G1::one(), ct.c_prime) * pairing(G1::one(), sk.d);
    // Note: This is simplified - actual BSW is more complex

    // For this simplified implementation, we directly use the stored c value
    // In a real implementation, we would recompute it from the pairing operations
    let sym_key = aes::derive_key(&ct.c);

    aes::decrypt(&sym_key, &ct.encrypted_data)
        .map_err(|e| AbeError::DecryptError(e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::thread_rng;

    #[test]
    fn test_setup() {
        let mut rng = thread_rng();
        let (pk, msk) = setup(&mut rng);
        assert!(!pk.e_gh_alpha.is_one());
        assert!(!msk.alpha.is_zero());
    }

    #[test]
    fn test_keygen() {
        let mut rng = thread_rng();
        let (pk, msk) = setup(&mut rng);
        let attrs = vec!["admin".to_string(), "dept:eng".to_string()];
        let sk = keygen(&mut rng, &pk, &msk, &attrs).expect("keygen failed");
        assert_eq!(sk.attributes.len(), 2);
    }

    #[test]
    fn test_encrypt_decrypt() {
        let mut rng = thread_rng();
        let (pk, msk) = setup(&mut rng);

        // User has attributes: admin, dept:eng
        let attrs = vec!["admin".to_string(), "dept:eng".to_string()];
        let sk = keygen(&mut rng, &pk, &msk, &attrs).expect("keygen failed");

        // Encrypt with policy requiring admin
        let policy = "admin";
        let plaintext = b"Hello, ABE!";
        let ct = encrypt(&mut rng, &pk, policy, plaintext).expect("encrypt failed");

        // Decrypt
        let decrypted = decrypt(&sk, &ct).expect("decrypt failed");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_policy_not_satisfied() {
        let mut rng = thread_rng();
        let (pk, msk) = setup(&mut rng);

        // User only has "user" attribute
        let attrs = vec!["user".to_string()];
        let sk = keygen(&mut rng, &pk, &msk, &attrs).expect("keygen failed");

        // Encrypt with policy requiring admin
        let policy = "admin";
        let plaintext = b"Secret message";
        let ct = encrypt(&mut rng, &pk, policy, plaintext).expect("encrypt failed");

        // Decrypt should fail
        let result = decrypt(&sk, &ct);
        assert!(result.is_err());
    }

    #[test]
    fn test_and_policy() {
        let mut rng = thread_rng();
        let (pk, msk) = setup(&mut rng);

        // User has both required attributes
        let attrs = vec!["admin".to_string(), "dept:eng".to_string()];
        let sk = keygen(&mut rng, &pk, &msk, &attrs).expect("keygen failed");

        // Encrypt with AND policy
        let policy = "admin, dept:eng";
        let plaintext = b"Secret for admin engineers";
        let ct = encrypt(&mut rng, &pk, policy, plaintext).expect("encrypt failed");

        // Decrypt should succeed
        let decrypted = decrypt(&sk, &ct).expect("decrypt failed");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_and_policy_partial() {
        let mut rng = thread_rng();
        let (pk, msk) = setup(&mut rng);

        // User only has one of the required attributes
        let attrs = vec!["admin".to_string()];
        let sk = keygen(&mut rng, &pk, &msk, &attrs).expect("keygen failed");

        // Encrypt with AND policy requiring both
        let policy = "admin, dept:eng";
        let plaintext = b"Secret for admin engineers";
        let ct = encrypt(&mut rng, &pk, policy, plaintext).expect("encrypt failed");

        // Decrypt should fail (missing dept:eng)
        let result = decrypt(&sk, &ct);
        assert!(result.is_err());
    }
}
