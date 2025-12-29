//! CCA-secure Waters '11 CP-ABE using Fujisaki-Okamoto Transform
//!
//! This module wraps the CPA-secure Waters '11 scheme to provide
//! CCA (Chosen Ciphertext Attack) security using the Fujisaki-Okamoto
//! transform.
//!
//! The transform works as follows:
//!
//! **Encryption:**
//! 1. Generate random r and K
//! 2. Derive deterministic PRNG seed: u = H(r || K || policy)
//! 3. Encrypt using deterministic randomness, embedding M = (r || K)
//! 4. Return (ciphertext, K)
//!
//! **Decryption:**
//! 1. Decrypt to recover M' = (r' || K')
//! 2. Re-encrypt M' with same deterministic PRNG
//! 3. Verify re-encrypted ciphertext matches original
//! 4. If match, return K'; otherwise reject

use crate::error::AbeError;
use crate::lsss::{LsssMatrix, PolicyNode};
use crate::schemes::waters::{self, Ciphertext, RawCiphertext, Mpk, SecretKey, CiphertextComponent};
use crate::utils::{aes, hash_to_g1_keyed};
use rabe_bls12381::{Fr, G1, Gt, pairing};
use rand::{RngCore, CryptoRng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use sha2::{Sha256, Digest};
use std::collections::HashMap;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Key length in bytes for the symmetric key and randomness
const KEY_LEN: usize = 32;

/// CCA-secure ciphertext
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct CcaCiphertext {
    /// The underlying CPA ciphertext
    pub cpa_ct: Ciphertext,
    /// Encrypted message M = (r || K) using AES
    pub encrypted_m: Vec<u8>,
    /// Unique identifier derived from encryption randomness
    pub uid: [u8; 16],
}

/// Full CCA ciphertext with encrypted payload
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct CcaFullCiphertext {
    /// CCA ciphertext (KEM part)
    pub cca_ct: CcaCiphertext,
    /// Symmetric ciphertext (DEM part) with IV and tag
    pub sym_ct: Vec<u8>,
}

/// Derive a deterministic PRNG seed from r, K, and policy
fn derive_prng_seed(r: &[u8], k: &[u8], policy: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"CCA_SEED_1");
    hasher.update(r);
    hasher.update(k);
    hasher.update(policy.as_bytes());
    let result = hasher.finalize();
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&result);
    seed
}

/// Derive a UID from the PRNG seed
fn derive_uid(seed: &[u8; 32]) -> [u8; 16] {
    let mut hasher = Sha256::new();
    hasher.update(b"CCA_UID");
    hasher.update(seed);
    let result = hasher.finalize();
    let mut uid = [0u8; 16];
    uid.copy_from_slice(&result[..16]);
    uid
}

/// Derive a key for encrypting M from the GT element
fn derive_m_encryption_key(gt: &Gt) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"CCA_M_KEY");
    hasher.update(&gt.into_bytes());
    let result = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&result);
    key
}

/// CCA-secure encryption (KEM mode)
///
/// Returns the CCA ciphertext and the encapsulated symmetric key.
pub fn encrypt_kem<R: RngCore + CryptoRng>(
    rng: &mut R,
    mpk: &Mpk,
    policy: &PolicyNode,
) -> Result<(CcaCiphertext, [u8; 32]), AbeError> {
    // Generate random r and K
    let mut r = [0u8; KEY_LEN];
    let mut k = [0u8; KEY_LEN];
    rng.fill_bytes(&mut r);
    rng.fill_bytes(&mut k);

    // Get canonical policy string
    let policy_str = policy.to_canonical_string();

    // Derive deterministic PRNG seed
    let seed = derive_prng_seed(&r, &k, &policy_str);
    let uid = derive_uid(&seed);

    // Create deterministic RNG
    let mut det_rng = ChaCha20Rng::from_seed(seed);

    // Encrypt using deterministic randomness
    let cpa_ct = encrypt_cpa_deterministic(&mut det_rng, mpk, policy)?;

    // Derive M encryption key from the GT element in the ciphertext
    // This allows decryption to recover M before verification
    let m_key = derive_m_encryption_key(&cpa_ct.c);

    // Encrypt M = (r || K) with the M-encryption key
    let mut m = Vec::with_capacity(2 * KEY_LEN);
    m.extend_from_slice(&r);
    m.extend_from_slice(&k);

    // Use XOR with key-derived stream for simplicity (or AES)
    let encrypted_m = xor_encrypt(&m, &m_key);

    Ok((CcaCiphertext { cpa_ct, encrypted_m, uid }, k))
}

/// XOR-based encryption (simple stream cipher using SHA256 as PRNG)
fn xor_encrypt(plaintext: &[u8], key: &[u8; 32]) -> Vec<u8> {
    let mut result = Vec::with_capacity(plaintext.len());
    let mut counter = 0u64;

    for chunk in plaintext.chunks(32) {
        let mut hasher = Sha256::new();
        hasher.update(key);
        hasher.update(counter.to_le_bytes());
        let keystream = hasher.finalize();

        for (i, &byte) in chunk.iter().enumerate() {
            result.push(byte ^ keystream[i]);
        }
        counter += 1;
    }

    result
}

/// XOR decryption (same as encryption for XOR cipher)
fn xor_decrypt(ciphertext: &[u8], key: &[u8; 32]) -> Vec<u8> {
    xor_encrypt(ciphertext, key)  // XOR is symmetric
}

/// Internal CPA encryption with deterministic randomness
fn encrypt_cpa_deterministic<R: RngCore + CryptoRng>(
    rng: &mut R,
    mpk: &Mpk,
    policy: &PolicyNode,
) -> Result<Ciphertext, AbeError> {
    // Build LSSS matrix from policy
    let matrix = LsssMatrix::from_policy(policy)?;

    // Random s (deterministic from our seeded RNG)
    let s = Fr::random(rng);

    // C = e(g1^s, g2^alpha)
    let g1s = mpk.g1 * s;
    let c = pairing(g1s, mpk.g2alpha);

    // C' = g1^s
    let c_prime = g1s;

    // Share the secret s using LSSS
    let shares = matrix.share_secret(rng, s);

    // For each share, create ciphertext component
    let mut components = HashMap::new();
    for share in shares {
        let r_i = Fr::random(rng);
        let h_attr = hash_to_g1_keyed(&mpk.k, &share.attr);
        let c_i = (mpk.g1a * share.share) + (h_attr * (-r_i));
        let d_i = mpk.g2 * r_i;

        components.insert(
            share.attr.clone(),
            CiphertextComponent { c: c_i, d: d_i },
        );
    }

    Ok(RawCiphertext {
        policy: policy.to_canonical_string(),
        c,
        c_prime,
        components,
    }.into())
}

/// CCA-secure encryption with payload
pub fn encrypt<R: RngCore + CryptoRng>(
    rng: &mut R,
    mpk: &Mpk,
    policy: &PolicyNode,
    plaintext: &[u8],
) -> Result<CcaFullCiphertext, AbeError> {
    let (cca_ct, sym_key) = encrypt_kem(rng, mpk, policy)?;

    // Encrypt payload with the symmetric key
    // Use the UID as part of the nonce for uniqueness
    let sym_ct = aes::encrypt_with_nonce(&sym_key, plaintext, &cca_ct.uid)
        .map_err(|e| AbeError::EncryptError(e))?;

    Ok(CcaFullCiphertext { cca_ct, sym_ct })
}

/// CCA-secure decryption (KEM mode)
///
/// Returns the encapsulated symmetric key if verification succeeds.
pub fn decrypt_kem(
    mpk: &Mpk,
    sk: &SecretKey,
    ct: &CcaCiphertext,
) -> Result<[u8; 32], AbeError> {
    // Parse policy from ciphertext
    let policy = waters::parse_policy(&ct.cpa_ct.policy)
        .map_err(|e| AbeError::InvalidPolicy(e.to_string()))?;

    // Do CPA decryption to get the raw GT element
    let recovered_gt = decrypt_cpa_to_gt(mpk, sk, &ct.cpa_ct)?;

    // Derive M encryption key from the recovered GT element
    // This must match the key used during encryption (derived from cpa_ct.c)
    let m_key = derive_m_encryption_key(&recovered_gt);

    // Decrypt M using the GT-derived key
    let m = xor_decrypt(&ct.encrypted_m, &m_key);

    if m.len() != 2 * KEY_LEN {
        return Err(AbeError::DecryptError("Invalid message length".to_string()));
    }

    // Extract r and k from M
    let mut r = [0u8; KEY_LEN];
    let mut k = [0u8; KEY_LEN];
    r.copy_from_slice(&m[..KEY_LEN]);
    k.copy_from_slice(&m[KEY_LEN..]);

    // Verify by re-encrypting
    let policy_str = policy.to_canonical_string();
    let seed = derive_prng_seed(&r, &k, &policy_str);
    let expected_uid = derive_uid(&seed);

    // Check UID first (fast rejection)
    if ct.uid != expected_uid {
        return Err(AbeError::DecryptError("CCA verification failed: UID mismatch".to_string()));
    }

    // Create deterministic RNG and re-encrypt
    let mut det_rng = ChaCha20Rng::from_seed(seed);
    let reencrypted_ct = encrypt_cpa_deterministic(&mut det_rng, mpk, &policy)?;

    // Compare ciphertexts
    if !ciphertexts_equal(&ct.cpa_ct, &reencrypted_ct) {
        return Err(AbeError::DecryptError("CCA verification failed: ciphertext mismatch".to_string()));
    }

    // Verify encrypted_m matches using the re-encrypted GT element
    let reenc_m_key = derive_m_encryption_key(&reencrypted_ct.c);
    let mut m_reconstructed = Vec::with_capacity(2 * KEY_LEN);
    m_reconstructed.extend_from_slice(&r);
    m_reconstructed.extend_from_slice(&k);
    let expected_encrypted_m = xor_encrypt(&m_reconstructed, &reenc_m_key);

    if ct.encrypted_m != expected_encrypted_m {
        return Err(AbeError::DecryptError("CCA verification failed: M encryption mismatch".to_string()));
    }

    Ok(k)
}

/// Decrypt CPA ciphertext to get the raw GT element
fn decrypt_cpa_to_gt(
    _mpk: &Mpk,
    sk: &SecretKey,
    ct: &Ciphertext,
) -> Result<Gt, AbeError> {
    let policy = waters::parse_policy(&ct.policy)
        .map_err(|e| AbeError::InvalidPolicy(e.to_string()))?;

    let matrix = LsssMatrix::from_policy(&policy)?;

    let coeffs = matrix.recover_coefficients(&sk.attributes)
        .map_err(|_| AbeError::PolicyNotSatisfied)?;

    let mut prod1 = G1::zero();
    let mut g1_for_pairing = Vec::new();
    let mut g2_for_pairing = Vec::new();

    for (attr, coeff) in &coeffs {
        let comp = ct.components.get(attr)
            .ok_or_else(|| AbeError::DecryptError("Missing ciphertext component".into()))?;
        let kx = sk.kx.get(attr)
            .ok_or_else(|| AbeError::DecryptError("Missing key component".into()))?;

        prod1 = prod1 + (comp.c * *coeff);
        g1_for_pairing.push(*kx * *coeff);
        g2_for_pairing.push(comp.d);
    }

    let mut prod_t = Gt::one();
    for (g1_elem, g2_elem) in g1_for_pairing.iter().zip(g2_for_pairing.iter()) {
        prod_t = prod_t * pairing(*g1_elem, *g2_elem);
    }

    let pairing1 = pairing(ct.c_prime, sk.k);
    let pairing2 = pairing(prod1, sk.l);
    let denominator = prod_t * pairing2;
    let recovered_c = pairing1 * denominator.inverse();

    Ok(recovered_c)
}

/// Compare two ciphertexts for equality
fn ciphertexts_equal(ct1: &Ciphertext, ct2: &Ciphertext) -> bool {
    // Compare policies
    if ct1.policy != ct2.policy {
        return false;
    }

    // Compare GT elements
    if ct1.c.into_bytes() != ct2.c.into_bytes() {
        return false;
    }

    // Compare G1 elements
    if ct1.c_prime.into_bytes() != ct2.c_prime.into_bytes() {
        return false;
    }

    // Compare components
    if ct1.components.len() != ct2.components.len() {
        return false;
    }

    for (attr, comp1) in &ct1.components {
        match ct2.components.get(attr) {
            Some(comp2) => {
                if comp1.c.into_bytes() != comp2.c.into_bytes() {
                    return false;
                }
                if comp1.d.into_bytes() != comp2.d.into_bytes() {
                    return false;
                }
            }
            None => return false,
        }
    }

    true
}

/// CCA-secure decryption with payload
pub fn decrypt(
    mpk: &Mpk,
    sk: &SecretKey,
    ct: &CcaFullCiphertext,
) -> Result<Vec<u8>, AbeError> {
    let sym_key = decrypt_kem(mpk, sk, &ct.cca_ct)?;

    // Decrypt payload
    aes::decrypt_with_nonce(&sym_key, &ct.sym_ct, &ct.cca_ct.uid)
        .map_err(|e| AbeError::DecryptError(e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schemes::waters;
    use rand::thread_rng;

    #[test]
    fn test_cca_single_attr() {
        let mut rng = thread_rng();
        let (mpk, msk) = waters::setup(&mut rng);

        let attrs = vec!["admin".to_string()];
        let sk = waters::keygen(&mut rng, &mpk, &msk, &attrs).unwrap();

        let policy = PolicyNode::Attr("admin".to_string());
        let plaintext = b"Hello, CCA-secure ABE!";

        let ct = encrypt(&mut rng, &mpk, &policy, plaintext).unwrap();
        let decrypted = decrypt(&mpk, &sk, &ct).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_cca_and_policy() {
        let mut rng = thread_rng();
        let (mpk, msk) = waters::setup(&mut rng);

        let attrs = vec!["a".to_string(), "b".to_string()];
        let sk = waters::keygen(&mut rng, &mpk, &msk, &attrs).unwrap();

        let policy = PolicyNode::And(vec![
            PolicyNode::Attr("a".to_string()),
            PolicyNode::Attr("b".to_string()),
        ]);
        let plaintext = b"Secret for a AND b";

        let ct = encrypt(&mut rng, &mpk, &policy, plaintext).unwrap();
        let decrypted = decrypt(&mpk, &sk, &ct).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_cca_policy_not_satisfied() {
        let mut rng = thread_rng();
        let (mpk, msk) = waters::setup(&mut rng);

        let attrs = vec!["user".to_string()];
        let sk = waters::keygen(&mut rng, &mpk, &msk, &attrs).unwrap();

        let policy = PolicyNode::Attr("admin".to_string());
        let plaintext = b"Admin only";

        let ct = encrypt(&mut rng, &mpk, &policy, plaintext).unwrap();
        let result = decrypt(&mpk, &sk, &ct);

        assert!(result.is_err());
    }

    #[test]
    fn test_cca_kem_mode() {
        let mut rng = thread_rng();
        let (mpk, msk) = waters::setup(&mut rng);

        let attrs = vec!["admin".to_string()];
        let sk = waters::keygen(&mut rng, &mpk, &msk, &attrs).unwrap();

        let policy = PolicyNode::Attr("admin".to_string());

        let (ct, enc_key) = encrypt_kem(&mut rng, &mpk, &policy).unwrap();
        let dec_key = decrypt_kem(&mpk, &sk, &ct).unwrap();

        assert_eq!(enc_key, dec_key);
    }

    #[test]
    fn test_cca_or_policy() {
        let mut rng = thread_rng();
        let (mpk, msk) = waters::setup(&mut rng);

        // User only has "a"
        let attrs = vec!["a".to_string()];
        let sk = waters::keygen(&mut rng, &mpk, &msk, &attrs).unwrap();

        // Policy: a OR b
        let policy = PolicyNode::Or(vec![
            PolicyNode::Attr("a".to_string()),
            PolicyNode::Attr("b".to_string()),
        ]);
        let plaintext = b"Secret for a OR b";

        let ct = encrypt(&mut rng, &mpk, &policy, plaintext).unwrap();
        let decrypted = decrypt(&mpk, &sk, &ct).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_cca_tamper_detection() {
        let mut rng = thread_rng();
        let (mpk, msk) = waters::setup(&mut rng);

        let attrs = vec!["admin".to_string()];
        let sk = waters::keygen(&mut rng, &mpk, &msk, &attrs).unwrap();

        let policy = PolicyNode::Attr("admin".to_string());

        let (mut ct, _) = encrypt_kem(&mut rng, &mpk, &policy).unwrap();

        // Tamper with the encrypted_m
        if !ct.encrypted_m.is_empty() {
            ct.encrypted_m[0] ^= 0xFF;
        }

        // Decryption should fail
        let result = decrypt_kem(&mpk, &sk, &ct);
        assert!(result.is_err());
    }
}
