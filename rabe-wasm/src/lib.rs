//! OpenABE-RABE: Attribute-Based Encryption library with WASM support
//!
//! This library wraps the RABE (Rust ABE) library to provide CP-ABE and KP-ABE
//! functionality with first-class WebAssembly support.

use serde::{Deserialize, Serialize};
use thiserror::Error;

// Re-export RABE schemes for native usage
pub use rabe::schemes::bsw as cpabe;
pub use rabe::schemes::ac17;
pub use rabe::utils::policy::pest::PolicyLanguage;

#[derive(Error, Debug)]
pub enum AbeError {
    #[error("Setup failed")]
    SetupError,
    #[error("Key generation failed: {0}")]
    KeygenError(String),
    #[error("Encryption failed: {0}")]
    EncryptError(String),
    #[error("Decryption failed: {0}")]
    DecryptError(String),
    #[error("Serialization failed: {0}")]
    SerializationError(String),
    #[error("Invalid policy: {0}")]
    PolicyError(String),
}

/// Serializable wrapper for master public key
#[derive(Serialize, Deserialize, Clone)]
pub struct MasterPublicKey {
    pub scheme: String,
    pub data: String, // Base64 encoded
}

/// Serializable wrapper for master secret key
#[derive(Serialize, Deserialize, Clone)]
pub struct MasterSecretKey {
    pub scheme: String,
    pub data: String, // Base64 encoded
}

/// Serializable wrapper for user secret key
#[derive(Serialize, Deserialize, Clone)]
pub struct UserSecretKey {
    pub scheme: String,
    pub attributes: Vec<String>,
    pub data: String, // Base64 encoded
}

/// Serializable wrapper for ciphertext
#[derive(Serialize, Deserialize, Clone)]
pub struct Ciphertext {
    pub scheme: String,
    pub policy: String,
    pub data: String, // Base64 encoded
}

// ============================================================================
// BSW CP-ABE Implementation (same scheme as OpenABE's CP-Waters)
// ============================================================================

pub mod bsw {
    use super::*;
    use rabe::schemes::bsw::{
        setup as bsw_setup,
        keygen as bsw_keygen,
        encrypt as bsw_encrypt,
        decrypt as bsw_decrypt,
        CpAbeMasterKey,
        CpAbePublicKey,
        CpAbeSecretKey,
        CpAbeCiphertext,
    };
    use rabe::utils::policy::pest::PolicyLanguage;
    use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};

    /// Generate master public and secret keys
    pub fn setup() -> Result<(MasterPublicKey, MasterSecretKey), AbeError> {
        let (pk, msk) = bsw_setup();

        let pk_json = serde_json::to_string(&pk)
            .map_err(|e| AbeError::SerializationError(e.to_string()))?;
        let msk_json = serde_json::to_string(&msk)
            .map_err(|e| AbeError::SerializationError(e.to_string()))?;

        Ok((
            MasterPublicKey {
                scheme: "BSW-CP-ABE".to_string(),
                data: BASE64.encode(pk_json.as_bytes()),
            },
            MasterSecretKey {
                scheme: "BSW-CP-ABE".to_string(),
                data: BASE64.encode(msk_json.as_bytes()),
            },
        ))
    }

    /// Generate a user secret key for given attributes
    pub fn keygen(
        mpk: &MasterPublicKey,
        msk: &MasterSecretKey,
        attributes: &[String],
    ) -> Result<UserSecretKey, AbeError> {
        let pk_bytes = BASE64.decode(&mpk.data)
            .map_err(|e| AbeError::SerializationError(e.to_string()))?;
        let msk_bytes = BASE64.decode(&msk.data)
            .map_err(|e| AbeError::SerializationError(e.to_string()))?;

        let pk: CpAbePublicKey = serde_json::from_slice(&pk_bytes)
            .map_err(|e| AbeError::SerializationError(e.to_string()))?;
        let msk_inner: CpAbeMasterKey = serde_json::from_slice(&msk_bytes)
            .map_err(|e| AbeError::SerializationError(e.to_string()))?;

        // Convert &[String] to Vec<&str> for RABE API
        let attr_refs: Vec<&str> = attributes.iter().map(|s| s.as_str()).collect();

        let sk = bsw_keygen(&pk, &msk_inner, &attr_refs)
            .ok_or_else(|| AbeError::KeygenError("Key generation failed".to_string()))?;

        let sk_json = serde_json::to_string(&sk)
            .map_err(|e| AbeError::SerializationError(e.to_string()))?;

        Ok(UserSecretKey {
            scheme: "BSW-CP-ABE".to_string(),
            attributes: attributes.to_vec(),
            data: BASE64.encode(sk_json.as_bytes()),
        })
    }

    /// Encrypt plaintext under an access policy
    pub fn encrypt(
        mpk: &MasterPublicKey,
        policy: &str,
        plaintext: &[u8],
    ) -> Result<Ciphertext, AbeError> {
        let pk_bytes = BASE64.decode(&mpk.data)
            .map_err(|e| AbeError::SerializationError(e.to_string()))?;

        let pk: CpAbePublicKey = serde_json::from_slice(&pk_bytes)
            .map_err(|e| AbeError::SerializationError(e.to_string()))?;

        let ct = bsw_encrypt(&pk, &policy.to_string(), PolicyLanguage::HumanPolicy, plaintext)
            .map_err(|e| AbeError::EncryptError(format!("{:?}", e)))?;

        let ct_json = serde_json::to_string(&ct)
            .map_err(|e| AbeError::SerializationError(e.to_string()))?;

        Ok(Ciphertext {
            scheme: "BSW-CP-ABE".to_string(),
            policy: policy.to_string(),
            data: BASE64.encode(ct_json.as_bytes()),
        })
    }

    /// Decrypt ciphertext using a user secret key
    pub fn decrypt(
        sk: &UserSecretKey,
        ct: &Ciphertext,
    ) -> Result<Vec<u8>, AbeError> {
        let sk_bytes = BASE64.decode(&sk.data)
            .map_err(|e| AbeError::SerializationError(e.to_string()))?;
        let ct_bytes = BASE64.decode(&ct.data)
            .map_err(|e| AbeError::SerializationError(e.to_string()))?;

        let sk_inner: CpAbeSecretKey = serde_json::from_slice(&sk_bytes)
            .map_err(|e| AbeError::SerializationError(e.to_string()))?;
        let ct_inner: CpAbeCiphertext = serde_json::from_slice(&ct_bytes)
            .map_err(|e| AbeError::SerializationError(e.to_string()))?;

        bsw_decrypt(&sk_inner, &ct_inner)
            .map_err(|e| AbeError::DecryptError(format!("{:?}", e)))
    }
}

// ============================================================================
// AC17 CP-ABE Implementation (more modern scheme)
// ============================================================================

pub mod ac17_cp {
    use super::*;
    use rabe::schemes::ac17::{
        setup as ac17_setup,
        cp_keygen,
        cp_encrypt,
        cp_decrypt,
        Ac17MasterKey,
        Ac17PublicKey,
        Ac17CpSecretKey,
        Ac17CpCiphertext,
    };
    use rabe::utils::policy::pest::PolicyLanguage;
    use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};

    /// Generate master public and secret keys
    pub fn setup() -> Result<(MasterPublicKey, MasterSecretKey), AbeError> {
        let (pk, msk) = ac17_setup();

        let pk_json = serde_json::to_string(&pk)
            .map_err(|e| AbeError::SerializationError(e.to_string()))?;
        let msk_json = serde_json::to_string(&msk)
            .map_err(|e| AbeError::SerializationError(e.to_string()))?;

        Ok((
            MasterPublicKey {
                scheme: "AC17-CP-ABE".to_string(),
                data: BASE64.encode(pk_json.as_bytes()),
            },
            MasterSecretKey {
                scheme: "AC17-CP-ABE".to_string(),
                data: BASE64.encode(msk_json.as_bytes()),
            },
        ))
    }

    /// Generate a user secret key for given attributes
    pub fn keygen(
        mpk: &MasterPublicKey,
        msk: &MasterSecretKey,
        attributes: &[String],
    ) -> Result<UserSecretKey, AbeError> {
        let pk_bytes = BASE64.decode(&mpk.data)
            .map_err(|e| AbeError::SerializationError(e.to_string()))?;
        let msk_bytes = BASE64.decode(&msk.data)
            .map_err(|e| AbeError::SerializationError(e.to_string()))?;

        let _pk: Ac17PublicKey = serde_json::from_slice(&pk_bytes)
            .map_err(|e| AbeError::SerializationError(e.to_string()))?;
        let msk_inner: Ac17MasterKey = serde_json::from_slice(&msk_bytes)
            .map_err(|e| AbeError::SerializationError(e.to_string()))?;

        // Convert &[String] to Vec<&str> for RABE API
        let attr_refs: Vec<&str> = attributes.iter().map(|s| s.as_str()).collect();

        let sk = cp_keygen(&msk_inner, &attr_refs)
            .map_err(|e| AbeError::KeygenError(format!("{:?}", e)))?;

        let sk_json = serde_json::to_string(&sk)
            .map_err(|e| AbeError::SerializationError(e.to_string()))?;

        Ok(UserSecretKey {
            scheme: "AC17-CP-ABE".to_string(),
            attributes: attributes.to_vec(),
            data: BASE64.encode(sk_json.as_bytes()),
        })
    }

    /// Encrypt plaintext under an access policy
    pub fn encrypt(
        mpk: &MasterPublicKey,
        policy: &str,
        plaintext: &[u8],
    ) -> Result<Ciphertext, AbeError> {
        let pk_bytes = BASE64.decode(&mpk.data)
            .map_err(|e| AbeError::SerializationError(e.to_string()))?;

        let pk: Ac17PublicKey = serde_json::from_slice(&pk_bytes)
            .map_err(|e| AbeError::SerializationError(e.to_string()))?;

        let ct = cp_encrypt(&pk, &policy.to_string(), plaintext, PolicyLanguage::HumanPolicy)
            .map_err(|e| AbeError::EncryptError(format!("{:?}", e)))?;

        let ct_json = serde_json::to_string(&ct)
            .map_err(|e| AbeError::SerializationError(e.to_string()))?;

        Ok(Ciphertext {
            scheme: "AC17-CP-ABE".to_string(),
            policy: policy.to_string(),
            data: BASE64.encode(ct_json.as_bytes()),
        })
    }

    /// Decrypt ciphertext using a user secret key
    pub fn decrypt(
        sk: &UserSecretKey,
        ct: &Ciphertext,
    ) -> Result<Vec<u8>, AbeError> {
        let sk_bytes = BASE64.decode(&sk.data)
            .map_err(|e| AbeError::SerializationError(e.to_string()))?;
        let ct_bytes = BASE64.decode(&ct.data)
            .map_err(|e| AbeError::SerializationError(e.to_string()))?;

        let sk_inner: Ac17CpSecretKey = serde_json::from_slice(&sk_bytes)
            .map_err(|e| AbeError::SerializationError(e.to_string()))?;
        let ct_inner: Ac17CpCiphertext = serde_json::from_slice(&ct_bytes)
            .map_err(|e| AbeError::SerializationError(e.to_string()))?;

        cp_decrypt(&sk_inner, &ct_inner)
            .map_err(|e| AbeError::DecryptError(format!("{:?}", e)))
    }
}

// ============================================================================
// WASM Bindings (only compiled when wasm feature is enabled)
// ============================================================================

#[cfg(feature = "wasm")]
pub mod wasm {
    use super::*;
    use wasm_bindgen::prelude::*;

    #[wasm_bindgen(start)]
    pub fn init() {
        // Set up panic hook for better error messages in WASM
        #[cfg(feature = "console_error_panic_hook")]
        console_error_panic_hook::set_once();
    }

    /// Result type for WASM operations
    #[wasm_bindgen]
    pub struct WasmResult {
        success: bool,
        data: String,
        error: String,
    }

    #[wasm_bindgen]
    impl WasmResult {
        #[wasm_bindgen(getter)]
        pub fn success(&self) -> bool {
            self.success
        }

        #[wasm_bindgen(getter)]
        pub fn data(&self) -> String {
            self.data.clone()
        }

        #[wasm_bindgen(getter)]
        pub fn error(&self) -> String {
            self.error.clone()
        }
    }

    fn ok_result(data: String) -> WasmResult {
        WasmResult {
            success: true,
            data,
            error: String::new(),
        }
    }

    fn err_result(error: String) -> WasmResult {
        WasmResult {
            success: false,
            data: String::new(),
            error,
        }
    }

    // ========================================================================
    // BSW CP-ABE WASM bindings
    // ========================================================================

    /// Generate BSW CP-ABE master keys
    /// Returns JSON: { "mpk": {...}, "msk": {...} }
    #[wasm_bindgen]
    pub fn bsw_setup() -> WasmResult {
        match bsw::setup() {
            Ok((mpk, msk)) => {
                let result = serde_json::json!({
                    "mpk": mpk,
                    "msk": msk
                });
                ok_result(result.to_string())
            }
            Err(e) => err_result(e.to_string()),
        }
    }

    /// Generate BSW CP-ABE user key
    /// mpk_json: Serialized MasterPublicKey
    /// msk_json: Serialized MasterSecretKey
    /// attributes_json: JSON array of attribute strings
    #[wasm_bindgen]
    pub fn bsw_keygen(mpk_json: &str, msk_json: &str, attributes_json: &str) -> WasmResult {
        let mpk: MasterPublicKey = match serde_json::from_str(mpk_json) {
            Ok(v) => v,
            Err(e) => return err_result(format!("Invalid MPK: {}", e)),
        };
        let msk: MasterSecretKey = match serde_json::from_str(msk_json) {
            Ok(v) => v,
            Err(e) => return err_result(format!("Invalid MSK: {}", e)),
        };
        let attributes: Vec<String> = match serde_json::from_str(attributes_json) {
            Ok(v) => v,
            Err(e) => return err_result(format!("Invalid attributes: {}", e)),
        };

        match bsw::keygen(&mpk, &msk, &attributes) {
            Ok(sk) => {
                match serde_json::to_string(&sk) {
                    Ok(json) => ok_result(json),
                    Err(e) => err_result(format!("Serialization error: {}", e)),
                }
            }
            Err(e) => err_result(e.to_string()),
        }
    }

    /// Encrypt with BSW CP-ABE
    /// mpk_json: Serialized MasterPublicKey
    /// policy: Access policy string (e.g., "attr1 AND attr2")
    /// plaintext_b64: Base64-encoded plaintext
    #[wasm_bindgen]
    pub fn bsw_encrypt(mpk_json: &str, policy: &str, plaintext_b64: &str) -> WasmResult {
        use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};

        let mpk: MasterPublicKey = match serde_json::from_str(mpk_json) {
            Ok(v) => v,
            Err(e) => return err_result(format!("Invalid MPK: {}", e)),
        };

        let plaintext = match BASE64.decode(plaintext_b64) {
            Ok(v) => v,
            Err(e) => return err_result(format!("Invalid base64: {}", e)),
        };

        match bsw::encrypt(&mpk, policy, &plaintext) {
            Ok(ct) => {
                match serde_json::to_string(&ct) {
                    Ok(json) => ok_result(json),
                    Err(e) => err_result(format!("Serialization error: {}", e)),
                }
            }
            Err(e) => err_result(e.to_string()),
        }
    }

    /// Decrypt with BSW CP-ABE
    /// sk_json: Serialized UserSecretKey
    /// ct_json: Serialized Ciphertext
    /// Returns base64-encoded plaintext
    #[wasm_bindgen]
    pub fn bsw_decrypt(sk_json: &str, ct_json: &str) -> WasmResult {
        use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};

        let sk: UserSecretKey = match serde_json::from_str(sk_json) {
            Ok(v) => v,
            Err(e) => return err_result(format!("Invalid SK: {}", e)),
        };
        let ct: Ciphertext = match serde_json::from_str(ct_json) {
            Ok(v) => v,
            Err(e) => return err_result(format!("Invalid ciphertext: {}", e)),
        };

        match bsw::decrypt(&sk, &ct) {
            Ok(plaintext) => ok_result(BASE64.encode(&plaintext)),
            Err(e) => err_result(e.to_string()),
        }
    }

    // ========================================================================
    // AC17 CP-ABE WASM bindings
    // ========================================================================

    /// Generate AC17 CP-ABE master keys
    #[wasm_bindgen]
    pub fn ac17_cp_setup() -> WasmResult {
        match ac17_cp::setup() {
            Ok((mpk, msk)) => {
                let result = serde_json::json!({
                    "mpk": mpk,
                    "msk": msk
                });
                ok_result(result.to_string())
            }
            Err(e) => err_result(e.to_string()),
        }
    }

    /// Generate AC17 CP-ABE user key
    #[wasm_bindgen]
    pub fn ac17_cp_keygen(mpk_json: &str, msk_json: &str, attributes_json: &str) -> WasmResult {
        let mpk: MasterPublicKey = match serde_json::from_str(mpk_json) {
            Ok(v) => v,
            Err(e) => return err_result(format!("Invalid MPK: {}", e)),
        };
        let msk: MasterSecretKey = match serde_json::from_str(msk_json) {
            Ok(v) => v,
            Err(e) => return err_result(format!("Invalid MSK: {}", e)),
        };
        let attributes: Vec<String> = match serde_json::from_str(attributes_json) {
            Ok(v) => v,
            Err(e) => return err_result(format!("Invalid attributes: {}", e)),
        };

        match ac17_cp::keygen(&mpk, &msk, &attributes) {
            Ok(sk) => {
                match serde_json::to_string(&sk) {
                    Ok(json) => ok_result(json),
                    Err(e) => err_result(format!("Serialization error: {}", e)),
                }
            }
            Err(e) => err_result(e.to_string()),
        }
    }

    /// Encrypt with AC17 CP-ABE
    #[wasm_bindgen]
    pub fn ac17_cp_encrypt(mpk_json: &str, policy: &str, plaintext_b64: &str) -> WasmResult {
        use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};

        let mpk: MasterPublicKey = match serde_json::from_str(mpk_json) {
            Ok(v) => v,
            Err(e) => return err_result(format!("Invalid MPK: {}", e)),
        };

        let plaintext = match BASE64.decode(plaintext_b64) {
            Ok(v) => v,
            Err(e) => return err_result(format!("Invalid base64: {}", e)),
        };

        match ac17_cp::encrypt(&mpk, policy, &plaintext) {
            Ok(ct) => {
                match serde_json::to_string(&ct) {
                    Ok(json) => ok_result(json),
                    Err(e) => err_result(format!("Serialization error: {}", e)),
                }
            }
            Err(e) => err_result(e.to_string()),
        }
    }

    /// Decrypt with AC17 CP-ABE
    #[wasm_bindgen]
    pub fn ac17_cp_decrypt(sk_json: &str, ct_json: &str) -> WasmResult {
        use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};

        let sk: UserSecretKey = match serde_json::from_str(sk_json) {
            Ok(v) => v,
            Err(e) => return err_result(format!("Invalid SK: {}", e)),
        };
        let ct: Ciphertext = match serde_json::from_str(ct_json) {
            Ok(v) => v,
            Err(e) => return err_result(format!("Invalid ciphertext: {}", e)),
        };

        match ac17_cp::decrypt(&sk, &ct) {
            Ok(plaintext) => ok_result(BASE64.encode(&plaintext)),
            Err(e) => err_result(e.to_string()),
        }
    }

    /// Simple test function to verify WASM is working
    #[wasm_bindgen]
    pub fn test_wasm() -> String {
        "RABE WASM module loaded successfully!".to_string()
    }

    /// Full roundtrip test for BSW CP-ABE
    #[wasm_bindgen]
    pub fn test_bsw_roundtrip() -> WasmResult {
        // Setup
        let (mpk, msk) = match bsw::setup() {
            Ok(keys) => keys,
            Err(e) => return err_result(format!("Setup failed: {}", e)),
        };

        // Keygen
        let attributes = vec!["role:admin".to_string(), "dept:engineering".to_string()];
        let sk = match bsw::keygen(&mpk, &msk, &attributes) {
            Ok(sk) => sk,
            Err(e) => return err_result(format!("Keygen failed: {}", e)),
        };

        // Encrypt
        let policy = r#""role:admin""#;
        let plaintext = b"Hello from WASM!";
        let ct = match bsw::encrypt(&mpk, policy, plaintext) {
            Ok(ct) => ct,
            Err(e) => return err_result(format!("Encrypt failed: {}", e)),
        };

        // Decrypt
        match bsw::decrypt(&sk, &ct) {
            Ok(decrypted) => {
                if decrypted == plaintext {
                    ok_result("Roundtrip test PASSED!".to_string())
                } else {
                    err_result("Decrypted data doesn't match plaintext".to_string())
                }
            }
            Err(e) => err_result(format!("Decrypt failed: {}", e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bsw_roundtrip() {
        // Setup
        let (mpk, msk) = bsw::setup().expect("Setup failed");

        // Keygen
        let attributes = vec!["role:admin".to_string(), "dept:engineering".to_string()];
        let sk = bsw::keygen(&mpk, &msk, &attributes).expect("Keygen failed");

        // Encrypt with policy that matches attributes (RABE uses quoted attribute names)
        let policy = r#""role:admin" and "dept:engineering""#;
        let plaintext = b"Secret message for testing";
        let ct = bsw::encrypt(&mpk, policy, plaintext).expect("Encrypt failed");

        // Decrypt
        let decrypted = bsw::decrypt(&sk, &ct).expect("Decrypt failed");

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_bsw_policy_not_satisfied() {
        let (mpk, msk) = bsw::setup().expect("Setup failed");

        // User only has role:user attribute
        let attributes = vec!["role:user".to_string()];
        let sk = bsw::keygen(&mpk, &msk, &attributes).expect("Keygen failed");

        // Encrypt with policy requiring admin
        let policy = r#""role:admin""#;
        let plaintext = b"Admin-only secret";
        let ct = bsw::encrypt(&mpk, policy, plaintext).expect("Encrypt failed");

        // Decrypt should fail
        let result = bsw::decrypt(&sk, &ct);
        assert!(result.is_err());
    }

    #[test]
    fn test_ac17_roundtrip() {
        // Setup
        let (mpk, msk) = ac17_cp::setup().expect("Setup failed");

        // Keygen
        let attributes = vec!["A".to_string(), "B".to_string()];
        let sk = ac17_cp::keygen(&mpk, &msk, &attributes).expect("Keygen failed");

        // Encrypt (RABE uses quoted attribute names)
        let policy = r#""A" and "B""#;
        let plaintext = b"AC17 test message";
        let ct = ac17_cp::encrypt(&mpk, policy, plaintext).expect("Encrypt failed");

        // Decrypt
        let decrypted = ac17_cp::decrypt(&sk, &ct).expect("Decrypt failed");

        assert_eq!(decrypted, plaintext);
    }
}
