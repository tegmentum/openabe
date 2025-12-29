//! Utility functions for ABE

use rabe_bls12381::{Fr, G1, G2, Gt};
use sha3::{Sha3_256, Digest};
use std::sync::RwLock;
use lru::LruCache;
use std::num::NonZeroUsize;

/// Default cache size for hash-to-curve operations
const HASH_CACHE_SIZE: usize = 1024;

/// Thread-safe LRU cache for G1 hash results
/// Key format: hex(key_prefix) + ":" + attribute
static G1_HASH_CACHE: std::sync::LazyLock<RwLock<LruCache<String, G1>>> =
    std::sync::LazyLock::new(|| {
        RwLock::new(LruCache::new(NonZeroUsize::new(HASH_CACHE_SIZE).unwrap()))
    });

/// Thread-safe LRU cache for G2 hash results
static G2_HASH_CACHE: std::sync::LazyLock<RwLock<LruCache<String, G2>>> =
    std::sync::LazyLock::new(|| {
        RwLock::new(LruCache::new(NonZeroUsize::new(HASH_CACHE_SIZE).unwrap()))
    });

/// Build cache key from key prefix and attribute
#[inline]
fn build_cache_key(key: &[u8], attr: &str) -> String {
    // Use hex encoding for key prefix to ensure unique cache keys
    format!("{}:{}", hex::encode(key), attr)
}

/// Hash an attribute string to a G1 point
pub fn hash_to_g1(attr: &str) -> G1 {
    G1::hash_to_curve(attr.as_bytes())
}

/// Hash an attribute string to a G1 point with a key prefix (Waters '11 style)
///
/// Note: Use `hash_to_g1_keyed_cached` for repeated hashing of same attributes.
pub fn hash_to_g1_keyed(key: &[u8], attr: &str) -> G1 {
    // Concatenate key and attribute
    let mut data = Vec::with_capacity(key.len() + attr.len());
    data.extend_from_slice(key);
    data.extend_from_slice(attr.as_bytes());
    G1::hash_to_curve(&data)
}

/// Hash an attribute string to a G1 point with caching
///
/// Uses an LRU cache to avoid repeated hash-to-curve computations for the same
/// key/attribute combination. This is especially beneficial during decryption
/// where attributes are hashed multiple times.
pub fn hash_to_g1_keyed_cached(key: &[u8], attr: &str) -> G1 {
    let cache_key = build_cache_key(key, attr);

    // Try to get from cache (read lock)
    if let Ok(cache) = G1_HASH_CACHE.read() {
        if let Some(result) = cache.peek(&cache_key) {
            return *result;
        }
    }

    // Cache miss - compute the hash
    let result = hash_to_g1_keyed(key, attr);

    // Store in cache (write lock)
    if let Ok(mut cache) = G1_HASH_CACHE.write() {
        cache.put(cache_key, result);
    }

    result
}

/// Hash an attribute string to a G2 point with a key prefix
///
/// Note: Use `hash_to_g2_keyed_cached` for repeated hashing of same attributes.
pub fn hash_to_g2_keyed(key: &[u8], attr: &str) -> G2 {
    // Concatenate key and attribute
    let mut data = Vec::with_capacity(key.len() + attr.len());
    data.extend_from_slice(key);
    data.extend_from_slice(attr.as_bytes());
    G2::hash_to_curve(&data)
}

/// Hash an attribute string to a G2 point with caching
///
/// Uses an LRU cache to avoid repeated hash-to-curve computations for the same
/// key/attribute combination.
pub fn hash_to_g2_keyed_cached(key: &[u8], attr: &str) -> G2 {
    let cache_key = build_cache_key(key, attr);

    // Try to get from cache (read lock)
    if let Ok(cache) = G2_HASH_CACHE.read() {
        if let Some(result) = cache.peek(&cache_key) {
            return *result;
        }
    }

    // Cache miss - compute the hash
    let result = hash_to_g2_keyed(key, attr);

    // Store in cache (write lock)
    if let Ok(mut cache) = G2_HASH_CACHE.write() {
        cache.put(cache_key, result);
    }

    result
}

/// Clear the hash caches (useful for testing or memory management)
pub fn clear_hash_caches() {
    if let Ok(mut cache) = G1_HASH_CACHE.write() {
        cache.clear();
    }
    if let Ok(mut cache) = G2_HASH_CACHE.write() {
        cache.clear();
    }
}

/// Hash data to a field element
pub fn hash_to_fr(data: &[u8]) -> Fr {
    let mut hasher = Sha3_256::new();
    hasher.update(data);
    let result = hasher.finalize();

    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(&result);
    Fr::interpret(&buf)
}

/// AES-GCM encryption with proper nonce handling
pub mod aes {
    use aes_gcm::{
        aead::{Aead, KeyInit},
        Aes256Gcm, Nonce,
    };
    use hkdf::Hkdf;
    use sha2::Sha256;
    use rabe_bls12381::Gt;
    use zeroize::Zeroize;

    /// Nonce size for AES-GCM (96 bits)
    pub const NONCE_SIZE: usize = 12;

    /// Domain separation salt for HKDF
    const HKDF_SALT: &[u8] = b"rabe-abe-v1";

    /// Derive a symmetric key from a GT element using HKDF
    ///
    /// Uses HKDF-SHA256 with domain separation for proper key derivation.
    pub fn derive_key(gt: &Gt) -> [u8; 32] {
        derive_key_with_context(gt, b"abe-session-key")
    }

    /// Derive a symmetric key from a GT element with custom context
    ///
    /// The context provides domain separation between different uses.
    pub fn derive_key_with_context(gt: &Gt, context: &[u8]) -> [u8; 32] {
        let ikm = gt.into_bytes();
        let hk = Hkdf::<Sha256>::new(Some(HKDF_SALT), &ikm);

        let mut key = [0u8; 32];
        hk.expand(context, &mut key).expect("HKDF expand failed");
        key
    }

    /// Encrypt plaintext with a derived key
    ///
    /// Generates a random 12-byte nonce and prepends it to the ciphertext.
    /// Output format: [nonce (12 bytes)][ciphertext][auth_tag (16 bytes)]
    pub fn encrypt(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, String> {
        // Generate random nonce
        let mut nonce_bytes = [0u8; NONCE_SIZE];
        getrandom::getrandom(&mut nonce_bytes)
            .map_err(|_| "Failed to generate random nonce")?;

        let cipher = Aes256Gcm::new_from_slice(key)
            .map_err(|_| "Invalid key")?;

        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher.encrypt(nonce, plaintext)
            .map_err(|_| "Encryption failed")?;

        // Prepend nonce to ciphertext
        let mut result = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend(ciphertext);

        Ok(result)
    }

    /// Decrypt ciphertext with a derived key
    ///
    /// Extracts the nonce from the first 12 bytes of the ciphertext.
    pub fn decrypt(key: &[u8; 32], ciphertext: &[u8]) -> Result<Vec<u8>, String> {
        if ciphertext.len() < NONCE_SIZE {
            return Err("Ciphertext too short".into());
        }

        let (nonce_bytes, ct) = ciphertext.split_at(NONCE_SIZE);
        let nonce = Nonce::from_slice(nonce_bytes);

        let cipher = Aes256Gcm::new_from_slice(key)
            .map_err(|_| "Invalid key")?;

        cipher.decrypt(nonce, ct)
            .map_err(|_| "Decryption failed".into())
    }

    /// Encrypt plaintext with a derived key and explicit nonce material
    ///
    /// For use with deterministic encryption (e.g., CCA transform).
    /// The nonce is NOT prepended; caller must manage nonce storage.
    pub fn encrypt_with_nonce(key: &[u8; 32], plaintext: &[u8], nonce_material: &[u8; 16]) -> Result<Vec<u8>, String> {
        let cipher = Aes256Gcm::new_from_slice(key)
            .map_err(|_| "Invalid key")?;

        // Derive 12-byte nonce from the 16-byte material
        let mut nonce_bytes = [0u8; NONCE_SIZE];
        nonce_bytes.copy_from_slice(&nonce_material[..NONCE_SIZE]);
        let nonce = Nonce::from_slice(&nonce_bytes);

        cipher.encrypt(nonce, plaintext)
            .map_err(|_| "Encryption failed".into())
    }

    /// Decrypt ciphertext with a derived key and explicit nonce material
    ///
    /// For use with deterministic encryption (e.g., CCA transform).
    pub fn decrypt_with_nonce(key: &[u8; 32], ciphertext: &[u8], nonce_material: &[u8; 16]) -> Result<Vec<u8>, String> {
        let cipher = Aes256Gcm::new_from_slice(key)
            .map_err(|_| "Invalid key")?;

        // Derive 12-byte nonce from the 16-byte material
        let mut nonce_bytes = [0u8; NONCE_SIZE];
        nonce_bytes.copy_from_slice(&nonce_material[..NONCE_SIZE]);
        let nonce = Nonce::from_slice(&nonce_bytes);

        cipher.decrypt(nonce, ciphertext)
            .map_err(|_| "Decryption failed".into())
    }

    /// Securely compare two byte slices in constant time
    pub fn secure_compare(a: &[u8], b: &[u8]) -> bool {
        use subtle::ConstantTimeEq;
        if a.len() != b.len() {
            return false;
        }
        a.ct_eq(b).into()
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn test_nonce_uniqueness() {
            let key = [0u8; 32];
            let ct1 = encrypt(&key, b"test").unwrap();
            let ct2 = encrypt(&key, b"test").unwrap();
            // Nonces (first 12 bytes) must differ
            assert_ne!(&ct1[..NONCE_SIZE], &ct2[..NONCE_SIZE]);
        }

        #[test]
        fn test_encrypt_decrypt_roundtrip() {
            let key = [42u8; 32];
            let plaintext = b"Hello, World!";
            let ciphertext = encrypt(&key, plaintext).unwrap();
            let decrypted = decrypt(&key, &ciphertext).unwrap();
            assert_eq!(plaintext.as_slice(), decrypted.as_slice());
        }

        #[test]
        fn test_ciphertext_too_short() {
            let key = [0u8; 32];
            let result = decrypt(&key, &[0u8; 5]);
            assert!(result.is_err());
        }

        #[test]
        fn test_secure_compare() {
            let a = b"secret";
            let b = b"secret";
            let c = b"secreT";
            assert!(secure_compare(a, b));
            assert!(!secure_compare(a, c));
            assert!(!secure_compare(a, &b[..5])); // Different lengths
        }

        #[test]
        fn test_hkdf_key_derivation() {
            use rabe_bls12381::{G1, G2, pairing};
            let gt = pairing(G1::one(), G2::one());
            let key1 = derive_key(&gt);
            let key2 = derive_key_with_context(&gt, b"different-context");
            // Same GT with different contexts should produce different keys
            assert_ne!(key1, key2);
        }
    }
}
