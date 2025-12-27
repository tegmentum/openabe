//! Utility functions for ABE

use rabe_bls12381::{Fr, G1, G2, Gt};
use sha3::{Sha3_256, Digest};

/// Hash an attribute string to a G1 point
pub fn hash_to_g1(attr: &str) -> G1 {
    G1::hash_to_curve(attr.as_bytes())
}

/// Hash an attribute string to a G1 point with a key prefix (Waters '11 style)
pub fn hash_to_g1_keyed(key: &[u8], attr: &str) -> G1 {
    // Concatenate key and attribute
    let mut data = Vec::with_capacity(key.len() + attr.len());
    data.extend_from_slice(key);
    data.extend_from_slice(attr.as_bytes());
    G1::hash_to_curve(&data)
}

/// Hash an attribute string to a G2 point with a key prefix
pub fn hash_to_g2_keyed(key: &[u8], attr: &str) -> G2 {
    // Concatenate key and attribute
    let mut data = Vec::with_capacity(key.len() + attr.len());
    data.extend_from_slice(key);
    data.extend_from_slice(attr.as_bytes());
    G2::hash_to_curve(&data)
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

/// AES-GCM encryption
pub mod aes {
    use aes_gcm::{
        aead::{Aead, KeyInit},
        Aes256Gcm, Nonce,
    };
    use sha2::{Sha256, Digest};
    use rabe_bls12381::Gt;

    /// Derive a symmetric key from a GT element
    pub fn derive_key(gt: &Gt) -> [u8; 32] {
        let bytes = gt.into_bytes();
        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        let result = hasher.finalize();
        let mut key = [0u8; 32];
        key.copy_from_slice(&result);
        key
    }

    /// Encrypt plaintext with a derived key
    pub fn encrypt(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, String> {
        let cipher = Aes256Gcm::new_from_slice(key)
            .map_err(|e| format!("Invalid key: {}", e))?;

        // Use a fixed nonce for simplicity (in production, use random nonce)
        let nonce = Nonce::from_slice(b"unique nonce"); // 12 bytes

        cipher.encrypt(nonce, plaintext)
            .map_err(|e| format!("Encryption failed: {}", e))
    }

    /// Decrypt ciphertext with a derived key
    pub fn decrypt(key: &[u8; 32], ciphertext: &[u8]) -> Result<Vec<u8>, String> {
        let cipher = Aes256Gcm::new_from_slice(key)
            .map_err(|e| format!("Invalid key: {}", e))?;

        let nonce = Nonce::from_slice(b"unique nonce");

        cipher.decrypt(nonce, ciphertext)
            .map_err(|e| format!("Decryption failed: {}", e))
    }

    /// Encrypt plaintext with a derived key and custom nonce material
    pub fn encrypt_with_nonce(key: &[u8; 32], plaintext: &[u8], nonce_material: &[u8; 16]) -> Result<Vec<u8>, String> {
        let cipher = Aes256Gcm::new_from_slice(key)
            .map_err(|e| format!("Invalid key: {}", e))?;

        // Derive 12-byte nonce from the 16-byte material
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes.copy_from_slice(&nonce_material[..12]);
        let nonce = Nonce::from_slice(&nonce_bytes);

        cipher.encrypt(nonce, plaintext)
            .map_err(|e| format!("Encryption failed: {}", e))
    }

    /// Decrypt ciphertext with a derived key and custom nonce material
    pub fn decrypt_with_nonce(key: &[u8; 32], ciphertext: &[u8], nonce_material: &[u8; 16]) -> Result<Vec<u8>, String> {
        let cipher = Aes256Gcm::new_from_slice(key)
            .map_err(|e| format!("Invalid key: {}", e))?;

        // Derive 12-byte nonce from the 16-byte material
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes.copy_from_slice(&nonce_material[..12]);
        let nonce = Nonce::from_slice(&nonce_bytes);

        cipher.decrypt(nonce, ciphertext)
            .map_err(|e| format!("Decryption failed: {}", e))
    }
}
