//! OpenABE-RABE: Attribute-Based Encryption library with WASM support
//!
//! This library provides CP-ABE functionality using BLS12-381 for 128-bit security.
//! It supports both native Rust and WebAssembly targets.
//!
//! ## Schemes
//!
//! - **BSW CP-ABE**: Bethencourt-Sahai-Waters (simplified, AND-only policies)
//! - **Waters '11 CP-ABE**: Full LSSS support, CPA-secure
//! - **Waters '11 CCA**: CCA-secure via Fujisaki-Okamoto transform
//!
//! ## Serialization
//!
//! - JSON: For human-readable interchange
//! - CBOR: For cross-platform binary interchange (native <-> WASM)

use serde::{Deserialize, Serialize};
use thiserror::Error;
use rand::thread_rng;

// Re-export ABE types
pub use rabe_abe::schemes::bsw;
pub use rabe_abe::schemes::waters;
pub use rabe_abe::schemes::waters_cca;
pub use rabe_abe::lsss::PolicyNode;
pub use rabe_abe::cbor;
pub use rabe_bls12381::{Fr, G1, G2, Gt};

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
    pub data: String, // JSON encoded
}

/// Serializable wrapper for master secret key
#[derive(Serialize, Deserialize, Clone)]
pub struct MasterSecretKey {
    pub scheme: String,
    pub data: String, // JSON encoded
}

/// Serializable wrapper for user secret key
#[derive(Serialize, Deserialize, Clone)]
pub struct UserSecretKey {
    pub scheme: String,
    pub attributes: Vec<String>,
    pub data: String, // JSON encoded
}

/// Serializable wrapper for ciphertext
#[derive(Serialize, Deserialize, Clone)]
pub struct Ciphertext {
    pub scheme: String,
    pub policy: String,
    pub data: String, // JSON encoded
}

// ============================================================================
// BSW CP-ABE Implementation using BLS12-381
// ============================================================================

pub mod bsw_cp {
    use super::*;
    use rabe_abe::schemes::bsw::{
        setup as bsw_setup,
        keygen as bsw_keygen,
        encrypt as bsw_encrypt,
        decrypt as bsw_decrypt,
        CpAbePublicKey,
        CpAbeMasterKey,
        CpAbeSecretKey,
        CpAbeCiphertext,
    };

    /// Generate master public and secret keys
    pub fn setup() -> Result<(MasterPublicKey, MasterSecretKey), AbeError> {
        let mut rng = thread_rng();
        let (pk, msk) = bsw_setup(&mut rng);

        let pk_json = serde_json::to_string(&pk)
            .map_err(|e| AbeError::SerializationError(e.to_string()))?;
        let msk_json = serde_json::to_string(&msk)
            .map_err(|e| AbeError::SerializationError(e.to_string()))?;

        Ok((
            MasterPublicKey {
                scheme: "BSW-CP-ABE-BLS12381".to_string(),
                data: pk_json,
            },
            MasterSecretKey {
                scheme: "BSW-CP-ABE-BLS12381".to_string(),
                data: msk_json,
            },
        ))
    }

    /// Generate a user secret key for given attributes
    pub fn keygen(
        mpk: &MasterPublicKey,
        msk: &MasterSecretKey,
        attributes: &[String],
    ) -> Result<UserSecretKey, AbeError> {
        let pk: CpAbePublicKey = serde_json::from_str(&mpk.data)
            .map_err(|e| AbeError::SerializationError(e.to_string()))?;
        let msk_inner: CpAbeMasterKey = serde_json::from_str(&msk.data)
            .map_err(|e| AbeError::SerializationError(e.to_string()))?;

        let mut rng = thread_rng();
        let sk = bsw_keygen(&mut rng, &pk, &msk_inner, attributes)
            .map_err(|e| AbeError::KeygenError(format!("{:?}", e)))?;

        let sk_json = serde_json::to_string(&sk)
            .map_err(|e| AbeError::SerializationError(e.to_string()))?;

        Ok(UserSecretKey {
            scheme: "BSW-CP-ABE-BLS12381".to_string(),
            attributes: attributes.to_vec(),
            data: sk_json,
        })
    }

    /// Encrypt plaintext under an access policy
    pub fn encrypt(
        mpk: &MasterPublicKey,
        policy: &str,
        plaintext: &[u8],
    ) -> Result<Ciphertext, AbeError> {
        let pk: CpAbePublicKey = serde_json::from_str(&mpk.data)
            .map_err(|e| AbeError::SerializationError(e.to_string()))?;

        let mut rng = thread_rng();
        let ct = bsw_encrypt(&mut rng, &pk, policy, plaintext)
            .map_err(|e| AbeError::EncryptError(format!("{:?}", e)))?;

        let ct_json = serde_json::to_string(&ct)
            .map_err(|e| AbeError::SerializationError(e.to_string()))?;

        Ok(Ciphertext {
            scheme: "BSW-CP-ABE-BLS12381".to_string(),
            policy: policy.to_string(),
            data: ct_json,
        })
    }

    /// Decrypt ciphertext using a user secret key
    pub fn decrypt(
        sk: &UserSecretKey,
        ct: &Ciphertext,
    ) -> Result<Vec<u8>, AbeError> {
        let sk_inner: CpAbeSecretKey = serde_json::from_str(&sk.data)
            .map_err(|e| AbeError::SerializationError(e.to_string()))?;
        let ct_inner: CpAbeCiphertext = serde_json::from_str(&ct.data)
            .map_err(|e| AbeError::SerializationError(e.to_string()))?;

        bsw_decrypt(&sk_inner, &ct_inner)
            .map_err(|e| AbeError::DecryptError(format!("{:?}", e)))
    }
}

// ============================================================================
// Waters '11 CP-ABE (CPA-secure) using BLS12-381
// ============================================================================

pub mod waters_cp {
    use super::*;
    use rabe_abe::schemes::waters::{
        setup as waters_setup,
        keygen as waters_keygen,
        encrypt as waters_encrypt,
        decrypt as waters_decrypt,
        parse_policy,
        Mpk, Msk, SecretKey, FullCiphertext,
    };
    use rabe_abe::lsss::PolicyNode;

    pub const SCHEME_ID: &str = "WATERS11-CP-ABE-BLS12381";

    /// Generate master public and secret keys
    pub fn setup() -> Result<(MasterPublicKey, MasterSecretKey), AbeError> {
        let mut rng = thread_rng();
        let (mpk, msk) = waters_setup(&mut rng);

        let mpk_json = serde_json::to_string(&mpk)
            .map_err(|e| AbeError::SerializationError(e.to_string()))?;
        let msk_json = serde_json::to_string(&msk)
            .map_err(|e| AbeError::SerializationError(e.to_string()))?;

        Ok((
            MasterPublicKey {
                scheme: SCHEME_ID.to_string(),
                data: mpk_json,
            },
            MasterSecretKey {
                scheme: SCHEME_ID.to_string(),
                data: msk_json,
            },
        ))
    }

    /// Generate a user secret key for given attributes
    pub fn keygen(
        mpk: &MasterPublicKey,
        msk: &MasterSecretKey,
        attributes: &[String],
    ) -> Result<UserSecretKey, AbeError> {
        let mpk_inner: Mpk = serde_json::from_str(&mpk.data)
            .map_err(|e| AbeError::SerializationError(e.to_string()))?;
        let msk_inner: Msk = serde_json::from_str(&msk.data)
            .map_err(|e| AbeError::SerializationError(e.to_string()))?;

        let mut rng = thread_rng();
        let sk = waters_keygen(&mut rng, &mpk_inner, &msk_inner, attributes)
            .map_err(|e| AbeError::KeygenError(format!("{:?}", e)))?;

        let sk_json = serde_json::to_string(&sk)
            .map_err(|e| AbeError::SerializationError(e.to_string()))?;

        Ok(UserSecretKey {
            scheme: SCHEME_ID.to_string(),
            attributes: attributes.to_vec(),
            data: sk_json,
        })
    }

    /// Parse a policy string to PolicyNode
    pub fn parse_policy_str(policy_str: &str) -> Result<PolicyNode, AbeError> {
        parse_policy(policy_str)
            .map_err(|e| AbeError::PolicyError(e.to_string()))
    }

    /// Encrypt plaintext under an access policy
    pub fn encrypt(
        mpk: &MasterPublicKey,
        policy: &PolicyNode,
        plaintext: &[u8],
    ) -> Result<Ciphertext, AbeError> {
        let mpk_inner: Mpk = serde_json::from_str(&mpk.data)
            .map_err(|e| AbeError::SerializationError(e.to_string()))?;

        let mut rng = thread_rng();
        let ct = waters_encrypt(&mut rng, &mpk_inner, policy, plaintext)
            .map_err(|e| AbeError::EncryptError(format!("{:?}", e)))?;

        let ct_json = serde_json::to_string(&ct)
            .map_err(|e| AbeError::SerializationError(e.to_string()))?;

        Ok(Ciphertext {
            scheme: SCHEME_ID.to_string(),
            policy: policy.to_canonical_string(),
            data: ct_json,
        })
    }

    /// Decrypt ciphertext using a user secret key
    pub fn decrypt(
        mpk: &MasterPublicKey,
        sk: &UserSecretKey,
        ct: &Ciphertext,
    ) -> Result<Vec<u8>, AbeError> {
        let mpk_inner: Mpk = serde_json::from_str(&mpk.data)
            .map_err(|e| AbeError::SerializationError(e.to_string()))?;
        let sk_inner: SecretKey = serde_json::from_str(&sk.data)
            .map_err(|e| AbeError::SerializationError(e.to_string()))?;
        let ct_inner: FullCiphertext = serde_json::from_str(&ct.data)
            .map_err(|e| AbeError::SerializationError(e.to_string()))?;

        waters_decrypt(&mpk_inner, &sk_inner, &ct_inner)
            .map_err(|e| AbeError::DecryptError(format!("{:?}", e)))
    }
}

// ============================================================================
// Waters '11 CP-ABE with CCA Security
// ============================================================================

pub mod waters_cca_cp {
    use super::*;
    use rabe_abe::schemes::waters::{
        setup as waters_setup,
        keygen as waters_keygen,
        parse_policy,
        Mpk, Msk, SecretKey,
    };
    use rabe_abe::schemes::waters_cca::{
        encrypt as cca_encrypt,
        decrypt as cca_decrypt,
        CcaFullCiphertext,
    };
    use rabe_abe::lsss::PolicyNode;

    pub const SCHEME_ID: &str = "WATERS11-CCA-CP-ABE-BLS12381";

    /// Generate master public and secret keys (same as CPA)
    pub fn setup() -> Result<(MasterPublicKey, MasterSecretKey), AbeError> {
        let mut rng = thread_rng();
        let (mpk, msk) = waters_setup(&mut rng);

        let mpk_json = serde_json::to_string(&mpk)
            .map_err(|e| AbeError::SerializationError(e.to_string()))?;
        let msk_json = serde_json::to_string(&msk)
            .map_err(|e| AbeError::SerializationError(e.to_string()))?;

        Ok((
            MasterPublicKey {
                scheme: SCHEME_ID.to_string(),
                data: mpk_json,
            },
            MasterSecretKey {
                scheme: SCHEME_ID.to_string(),
                data: msk_json,
            },
        ))
    }

    /// Generate a user secret key for given attributes (same as CPA)
    pub fn keygen(
        mpk: &MasterPublicKey,
        msk: &MasterSecretKey,
        attributes: &[String],
    ) -> Result<UserSecretKey, AbeError> {
        let mpk_inner: Mpk = serde_json::from_str(&mpk.data)
            .map_err(|e| AbeError::SerializationError(e.to_string()))?;
        let msk_inner: Msk = serde_json::from_str(&msk.data)
            .map_err(|e| AbeError::SerializationError(e.to_string()))?;

        let mut rng = thread_rng();
        let sk = waters_keygen(&mut rng, &mpk_inner, &msk_inner, attributes)
            .map_err(|e| AbeError::KeygenError(format!("{:?}", e)))?;

        let sk_json = serde_json::to_string(&sk)
            .map_err(|e| AbeError::SerializationError(e.to_string()))?;

        Ok(UserSecretKey {
            scheme: SCHEME_ID.to_string(),
            attributes: attributes.to_vec(),
            data: sk_json,
        })
    }

    /// Parse a policy string to PolicyNode
    pub fn parse_policy_str(policy_str: &str) -> Result<PolicyNode, AbeError> {
        parse_policy(policy_str)
            .map_err(|e| AbeError::PolicyError(e.to_string()))
    }

    /// Encrypt plaintext under an access policy (CCA-secure)
    pub fn encrypt(
        mpk: &MasterPublicKey,
        policy: &PolicyNode,
        plaintext: &[u8],
    ) -> Result<Ciphertext, AbeError> {
        let mpk_inner: Mpk = serde_json::from_str(&mpk.data)
            .map_err(|e| AbeError::SerializationError(e.to_string()))?;

        let mut rng = thread_rng();
        let ct = cca_encrypt(&mut rng, &mpk_inner, policy, plaintext)
            .map_err(|e| AbeError::EncryptError(format!("{:?}", e)))?;

        let ct_json = serde_json::to_string(&ct)
            .map_err(|e| AbeError::SerializationError(e.to_string()))?;

        Ok(Ciphertext {
            scheme: SCHEME_ID.to_string(),
            policy: policy.to_canonical_string(),
            data: ct_json,
        })
    }

    /// Decrypt ciphertext using a user secret key (CCA-secure)
    pub fn decrypt(
        mpk: &MasterPublicKey,
        sk: &UserSecretKey,
        ct: &Ciphertext,
    ) -> Result<Vec<u8>, AbeError> {
        let mpk_inner: Mpk = serde_json::from_str(&mpk.data)
            .map_err(|e| AbeError::SerializationError(e.to_string()))?;
        let sk_inner: SecretKey = serde_json::from_str(&sk.data)
            .map_err(|e| AbeError::SerializationError(e.to_string()))?;
        let ct_inner: CcaFullCiphertext = serde_json::from_str(&ct.data)
            .map_err(|e| AbeError::SerializationError(e.to_string()))?;

        cca_decrypt(&mpk_inner, &sk_inner, &ct_inner)
            .map_err(|e| AbeError::DecryptError(format!("{:?}", e)))
    }
}

// ============================================================================
// CBOR Serialization Functions
// ============================================================================

pub mod cbor_ser {
    use super::*;
    use rabe_abe::cbor::{
        encode_mpk, decode_mpk,
        encode_msk, decode_msk,
        encode_sk, decode_sk,
        encode_cca_full_ct, decode_cca_full_ct,
    };
    use rabe_abe::schemes::waters::{Mpk, Msk, SecretKey};
    use rabe_abe::schemes::waters_cca::CcaFullCiphertext;

    /// Encode MPK to CBOR bytes
    pub fn mpk_to_cbor(mpk: &MasterPublicKey) -> Result<Vec<u8>, AbeError> {
        let mpk_inner: Mpk = serde_json::from_str(&mpk.data)
            .map_err(|e| AbeError::SerializationError(e.to_string()))?;
        encode_mpk(&mpk_inner)
            .map_err(|e| AbeError::SerializationError(format!("{:?}", e)))
    }

    /// Decode MPK from CBOR bytes
    pub fn mpk_from_cbor(data: &[u8]) -> Result<MasterPublicKey, AbeError> {
        let mpk = decode_mpk(data)
            .map_err(|e| AbeError::SerializationError(format!("{:?}", e)))?;
        let mpk_json = serde_json::to_string(&mpk)
            .map_err(|e| AbeError::SerializationError(e.to_string()))?;
        Ok(MasterPublicKey {
            scheme: "WATERS11-CP-ABE-BLS12381".to_string(),
            data: mpk_json,
        })
    }

    /// Encode MSK to CBOR bytes
    pub fn msk_to_cbor(msk: &MasterSecretKey) -> Result<Vec<u8>, AbeError> {
        let msk_inner: Msk = serde_json::from_str(&msk.data)
            .map_err(|e| AbeError::SerializationError(e.to_string()))?;
        encode_msk(&msk_inner)
            .map_err(|e| AbeError::SerializationError(format!("{:?}", e)))
    }

    /// Decode MSK from CBOR bytes
    pub fn msk_from_cbor(data: &[u8]) -> Result<MasterSecretKey, AbeError> {
        let msk = decode_msk(data)
            .map_err(|e| AbeError::SerializationError(format!("{:?}", e)))?;
        let msk_json = serde_json::to_string(&msk)
            .map_err(|e| AbeError::SerializationError(e.to_string()))?;
        Ok(MasterSecretKey {
            scheme: "WATERS11-CP-ABE-BLS12381".to_string(),
            data: msk_json,
        })
    }

    /// Encode SecretKey to CBOR bytes
    pub fn sk_to_cbor(sk: &UserSecretKey) -> Result<Vec<u8>, AbeError> {
        let sk_inner: SecretKey = serde_json::from_str(&sk.data)
            .map_err(|e| AbeError::SerializationError(e.to_string()))?;
        encode_sk(&sk_inner)
            .map_err(|e| AbeError::SerializationError(format!("{:?}", e)))
    }

    /// Decode SecretKey from CBOR bytes
    pub fn sk_from_cbor(data: &[u8]) -> Result<UserSecretKey, AbeError> {
        let sk = decode_sk(data)
            .map_err(|e| AbeError::SerializationError(format!("{:?}", e)))?;
        let sk_json = serde_json::to_string(&sk)
            .map_err(|e| AbeError::SerializationError(e.to_string()))?;
        Ok(UserSecretKey {
            scheme: "WATERS11-CP-ABE-BLS12381".to_string(),
            attributes: sk.attributes.clone(),
            data: sk_json,
        })
    }

    /// Encode CCA ciphertext to CBOR bytes
    pub fn cca_ct_to_cbor(ct: &Ciphertext) -> Result<Vec<u8>, AbeError> {
        let ct_inner: CcaFullCiphertext = serde_json::from_str(&ct.data)
            .map_err(|e| AbeError::SerializationError(e.to_string()))?;
        encode_cca_full_ct(&ct_inner)
            .map_err(|e| AbeError::SerializationError(format!("{:?}", e)))
    }

    /// Decode CCA ciphertext from CBOR bytes
    pub fn cca_ct_from_cbor(data: &[u8]) -> Result<Ciphertext, AbeError> {
        let ct = decode_cca_full_ct(data)
            .map_err(|e| AbeError::SerializationError(format!("{:?}", e)))?;
        let ct_json = serde_json::to_string(&ct)
            .map_err(|e| AbeError::SerializationError(e.to_string()))?;
        Ok(Ciphertext {
            scheme: "WATERS11-CCA-CP-ABE-BLS12381".to_string(),
            policy: ct.cca_ct.cpa_ct.policy.clone(),
            data: ct_json,
        })
    }
}

// ============================================================================
// WASM Bindings (only compiled when wasm feature is enabled)
// ============================================================================

#[cfg(feature = "wasm")]
pub mod wasm {
    use super::*;
    use wasm_bindgen::prelude::*;
    use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};

    #[wasm_bindgen(start)]
    pub fn init() {
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
    // BSW CP-ABE WASM bindings (BLS12-381)
    // ========================================================================

    /// Generate BSW CP-ABE master keys (BLS12-381)
    #[wasm_bindgen]
    pub fn bsw_setup() -> WasmResult {
        match bsw_cp::setup() {
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

        match bsw_cp::keygen(&mpk, &msk, &attributes) {
            Ok(sk) => {
                match serde_json::to_string(&sk) {
                    Ok(json) => ok_result(json),
                    Err(e) => err_result(format!("Serialization error: {}", e)),
                }
            }
            Err(e) => err_result(e.to_string()),
        }
    }

    /// Encrypt with BSW CP-ABE (BLS12-381)
    #[wasm_bindgen]
    pub fn bsw_encrypt(mpk_json: &str, policy: &str, plaintext_b64: &str) -> WasmResult {
        let mpk: MasterPublicKey = match serde_json::from_str(mpk_json) {
            Ok(v) => v,
            Err(e) => return err_result(format!("Invalid MPK: {}", e)),
        };

        let plaintext = match BASE64.decode(plaintext_b64) {
            Ok(v) => v,
            Err(e) => return err_result(format!("Invalid base64: {}", e)),
        };

        match bsw_cp::encrypt(&mpk, policy, &plaintext) {
            Ok(ct) => {
                match serde_json::to_string(&ct) {
                    Ok(json) => ok_result(json),
                    Err(e) => err_result(format!("Serialization error: {}", e)),
                }
            }
            Err(e) => err_result(e.to_string()),
        }
    }

    /// Decrypt with BSW CP-ABE (BLS12-381)
    #[wasm_bindgen]
    pub fn bsw_decrypt(sk_json: &str, ct_json: &str) -> WasmResult {
        let sk: UserSecretKey = match serde_json::from_str(sk_json) {
            Ok(v) => v,
            Err(e) => return err_result(format!("Invalid SK: {}", e)),
        };
        let ct: Ciphertext = match serde_json::from_str(ct_json) {
            Ok(v) => v,
            Err(e) => return err_result(format!("Invalid ciphertext: {}", e)),
        };

        match bsw_cp::decrypt(&sk, &ct) {
            Ok(plaintext) => ok_result(BASE64.encode(&plaintext)),
            Err(e) => err_result(e.to_string()),
        }
    }

    // ========================================================================
    // Waters '11 CCA CP-ABE WASM bindings (BLS12-381)
    // ========================================================================

    /// Generate Waters '11 CCA CP-ABE master keys (BLS12-381)
    #[wasm_bindgen]
    pub fn waters_cca_setup() -> WasmResult {
        match waters_cca_cp::setup() {
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

    /// Generate Waters '11 CCA CP-ABE user key
    #[wasm_bindgen]
    pub fn waters_cca_keygen(mpk_json: &str, msk_json: &str, attributes_json: &str) -> WasmResult {
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

        match waters_cca_cp::keygen(&mpk, &msk, &attributes) {
            Ok(sk) => {
                match serde_json::to_string(&sk) {
                    Ok(json) => ok_result(json),
                    Err(e) => err_result(format!("Serialization error: {}", e)),
                }
            }
            Err(e) => err_result(e.to_string()),
        }
    }

    /// Encrypt with Waters '11 CCA CP-ABE (BLS12-381)
    /// policy_json should be a JSON representation of PolicyNode
    #[wasm_bindgen]
    pub fn waters_cca_encrypt(mpk_json: &str, policy_str: &str, plaintext_b64: &str) -> WasmResult {
        let mpk: MasterPublicKey = match serde_json::from_str(mpk_json) {
            Ok(v) => v,
            Err(e) => return err_result(format!("Invalid MPK: {}", e)),
        };

        let policy = match waters_cca_cp::parse_policy_str(policy_str) {
            Ok(p) => p,
            Err(e) => return err_result(format!("Invalid policy: {}", e)),
        };

        let plaintext = match BASE64.decode(plaintext_b64) {
            Ok(v) => v,
            Err(e) => return err_result(format!("Invalid base64: {}", e)),
        };

        match waters_cca_cp::encrypt(&mpk, &policy, &plaintext) {
            Ok(ct) => {
                match serde_json::to_string(&ct) {
                    Ok(json) => ok_result(json),
                    Err(e) => err_result(format!("Serialization error: {}", e)),
                }
            }
            Err(e) => err_result(e.to_string()),
        }
    }

    /// Decrypt with Waters '11 CCA CP-ABE (BLS12-381)
    #[wasm_bindgen]
    pub fn waters_cca_decrypt(mpk_json: &str, sk_json: &str, ct_json: &str) -> WasmResult {
        let mpk: MasterPublicKey = match serde_json::from_str(mpk_json) {
            Ok(v) => v,
            Err(e) => return err_result(format!("Invalid MPK: {}", e)),
        };
        let sk: UserSecretKey = match serde_json::from_str(sk_json) {
            Ok(v) => v,
            Err(e) => return err_result(format!("Invalid SK: {}", e)),
        };
        let ct: Ciphertext = match serde_json::from_str(ct_json) {
            Ok(v) => v,
            Err(e) => return err_result(format!("Invalid ciphertext: {}", e)),
        };

        match waters_cca_cp::decrypt(&mpk, &sk, &ct) {
            Ok(plaintext) => ok_result(BASE64.encode(&plaintext)),
            Err(e) => err_result(e.to_string()),
        }
    }

    // ========================================================================
    // CBOR Serialization WASM bindings
    // ========================================================================

    /// Convert MPK to CBOR (base64 encoded)
    #[wasm_bindgen]
    pub fn mpk_to_cbor(mpk_json: &str) -> WasmResult {
        let mpk: MasterPublicKey = match serde_json::from_str(mpk_json) {
            Ok(v) => v,
            Err(e) => return err_result(format!("Invalid MPK: {}", e)),
        };

        match cbor_ser::mpk_to_cbor(&mpk) {
            Ok(bytes) => ok_result(BASE64.encode(&bytes)),
            Err(e) => err_result(e.to_string()),
        }
    }

    /// Convert CBOR (base64) to MPK
    #[wasm_bindgen]
    pub fn mpk_from_cbor(cbor_b64: &str) -> WasmResult {
        let bytes = match BASE64.decode(cbor_b64) {
            Ok(v) => v,
            Err(e) => return err_result(format!("Invalid base64: {}", e)),
        };

        match cbor_ser::mpk_from_cbor(&bytes) {
            Ok(mpk) => {
                match serde_json::to_string(&mpk) {
                    Ok(json) => ok_result(json),
                    Err(e) => err_result(format!("Serialization error: {}", e)),
                }
            }
            Err(e) => err_result(e.to_string()),
        }
    }

    /// Convert SK to CBOR (base64 encoded)
    #[wasm_bindgen]
    pub fn sk_to_cbor(sk_json: &str) -> WasmResult {
        let sk: UserSecretKey = match serde_json::from_str(sk_json) {
            Ok(v) => v,
            Err(e) => return err_result(format!("Invalid SK: {}", e)),
        };

        match cbor_ser::sk_to_cbor(&sk) {
            Ok(bytes) => ok_result(BASE64.encode(&bytes)),
            Err(e) => err_result(e.to_string()),
        }
    }

    /// Convert CBOR (base64) to SK
    #[wasm_bindgen]
    pub fn sk_from_cbor(cbor_b64: &str) -> WasmResult {
        let bytes = match BASE64.decode(cbor_b64) {
            Ok(v) => v,
            Err(e) => return err_result(format!("Invalid base64: {}", e)),
        };

        match cbor_ser::sk_from_cbor(&bytes) {
            Ok(sk) => {
                match serde_json::to_string(&sk) {
                    Ok(json) => ok_result(json),
                    Err(e) => err_result(format!("Serialization error: {}", e)),
                }
            }
            Err(e) => err_result(e.to_string()),
        }
    }

    /// Convert CCA ciphertext to CBOR (base64 encoded)
    #[wasm_bindgen]
    pub fn cca_ct_to_cbor(ct_json: &str) -> WasmResult {
        let ct: Ciphertext = match serde_json::from_str(ct_json) {
            Ok(v) => v,
            Err(e) => return err_result(format!("Invalid CT: {}", e)),
        };

        match cbor_ser::cca_ct_to_cbor(&ct) {
            Ok(bytes) => ok_result(BASE64.encode(&bytes)),
            Err(e) => err_result(e.to_string()),
        }
    }

    /// Convert CBOR (base64) to CCA ciphertext
    #[wasm_bindgen]
    pub fn cca_ct_from_cbor(cbor_b64: &str) -> WasmResult {
        let bytes = match BASE64.decode(cbor_b64) {
            Ok(v) => v,
            Err(e) => return err_result(format!("Invalid base64: {}", e)),
        };

        match cbor_ser::cca_ct_from_cbor(&bytes) {
            Ok(ct) => {
                match serde_json::to_string(&ct) {
                    Ok(json) => ok_result(json),
                    Err(e) => err_result(format!("Serialization error: {}", e)),
                }
            }
            Err(e) => err_result(e.to_string()),
        }
    }

    // ========================================================================
    // Test functions
    // ========================================================================

    /// Simple test function to verify WASM is working
    #[wasm_bindgen]
    pub fn test_wasm() -> String {
        "RABE BLS12-381 WASM module loaded successfully!".to_string()
    }

    /// Full roundtrip test for BSW CP-ABE (BLS12-381)
    #[wasm_bindgen]
    pub fn test_bsw_roundtrip() -> WasmResult {
        let (mpk, msk) = match bsw_cp::setup() {
            Ok(keys) => keys,
            Err(e) => return err_result(format!("Setup failed: {}", e)),
        };

        let attributes = vec!["admin".to_string(), "dept:engineering".to_string()];
        let sk = match bsw_cp::keygen(&mpk, &msk, &attributes) {
            Ok(sk) => sk,
            Err(e) => return err_result(format!("Keygen failed: {}", e)),
        };

        let policy = "admin";
        let plaintext = b"Hello from BLS12-381 WASM!";
        let ct = match bsw_cp::encrypt(&mpk, policy, plaintext) {
            Ok(ct) => ct,
            Err(e) => return err_result(format!("Encrypt failed: {}", e)),
        };

        match bsw_cp::decrypt(&sk, &ct) {
            Ok(decrypted) => {
                if decrypted == plaintext {
                    ok_result("BSW Roundtrip test PASSED!".to_string())
                } else {
                    err_result("Decrypted data doesn't match plaintext".to_string())
                }
            }
            Err(e) => err_result(format!("Decrypt failed: {}", e)),
        }
    }

    /// Full roundtrip test for Waters '11 CCA CP-ABE (BLS12-381)
    #[wasm_bindgen]
    pub fn test_waters_cca_roundtrip() -> WasmResult {
        let (mpk, msk) = match waters_cca_cp::setup() {
            Ok(keys) => keys,
            Err(e) => return err_result(format!("Setup failed: {}", e)),
        };

        let attributes = vec!["admin".to_string(), "dept:engineering".to_string()];
        let sk = match waters_cca_cp::keygen(&mpk, &msk, &attributes) {
            Ok(sk) => sk,
            Err(e) => return err_result(format!("Keygen failed: {}", e)),
        };

        let policy = match waters_cca_cp::parse_policy_str("admin AND dept:engineering") {
            Ok(p) => p,
            Err(e) => return err_result(format!("Policy parse failed: {}", e)),
        };

        let plaintext = b"Hello from Waters CCA WASM!";
        let ct = match waters_cca_cp::encrypt(&mpk, &policy, plaintext) {
            Ok(ct) => ct,
            Err(e) => return err_result(format!("Encrypt failed: {}", e)),
        };

        match waters_cca_cp::decrypt(&mpk, &sk, &ct) {
            Ok(decrypted) => {
                if decrypted == plaintext {
                    ok_result("Waters CCA Roundtrip test PASSED!".to_string())
                } else {
                    err_result("Decrypted data doesn't match plaintext".to_string())
                }
            }
            Err(e) => err_result(format!("Decrypt failed: {}", e)),
        }
    }

    /// Get the curve being used
    #[wasm_bindgen]
    pub fn get_curve() -> String {
        "BLS12-381".to_string()
    }

    /// Get available schemes
    #[wasm_bindgen]
    pub fn get_schemes() -> String {
        serde_json::json!({
            "schemes": [
                "BSW-CP-ABE-BLS12381",
                "WATERS11-CP-ABE-BLS12381",
                "WATERS11-CCA-CP-ABE-BLS12381"
            ]
        }).to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bsw_roundtrip() {
        let (mpk, msk) = bsw_cp::setup().expect("Setup failed");

        let attributes = vec!["admin".to_string(), "dept:engineering".to_string()];
        let sk = bsw_cp::keygen(&mpk, &msk, &attributes).expect("Keygen failed");

        let policy = "admin, dept:engineering";
        let plaintext = b"Secret message for testing";
        let ct = bsw_cp::encrypt(&mpk, policy, plaintext).expect("Encrypt failed");

        let decrypted = bsw_cp::decrypt(&sk, &ct).expect("Decrypt failed");

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_bsw_policy_not_satisfied() {
        let (mpk, msk) = bsw_cp::setup().expect("Setup failed");

        let attributes = vec!["user".to_string()];
        let sk = bsw_cp::keygen(&mpk, &msk, &attributes).expect("Keygen failed");

        let policy = "admin";
        let plaintext = b"Admin-only secret";
        let ct = bsw_cp::encrypt(&mpk, policy, plaintext).expect("Encrypt failed");

        let result = bsw_cp::decrypt(&sk, &ct);
        assert!(result.is_err());
    }

    #[test]
    fn test_waters_cca_roundtrip() {
        let (mpk, msk) = waters_cca_cp::setup().expect("Setup failed");

        let attributes = vec!["admin".to_string(), "dept:eng".to_string()];
        let sk = waters_cca_cp::keygen(&mpk, &msk, &attributes).expect("Keygen failed");

        let policy = waters_cca_cp::parse_policy_str("admin and dept:eng").expect("Parse failed");
        let plaintext = b"CCA-secure secret message";
        let ct = waters_cca_cp::encrypt(&mpk, &policy, plaintext).expect("Encrypt failed");

        let decrypted = waters_cca_cp::decrypt(&mpk, &sk, &ct).expect("Decrypt failed");

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_cbor_roundtrip() {
        // Use waters_cp for basic key roundtrip (MPK/MSK/SK are identical for CPA and CCA)
        let (mpk, msk) = waters_cp::setup().expect("Setup failed");

        // Test MPK CBOR roundtrip
        let mpk_cbor = cbor_ser::mpk_to_cbor(&mpk).expect("MPK to CBOR failed");
        let mpk2 = cbor_ser::mpk_from_cbor(&mpk_cbor).expect("MPK from CBOR failed");
        assert_eq!(mpk.scheme, mpk2.scheme);

        // Test MSK CBOR roundtrip
        let msk_cbor = cbor_ser::msk_to_cbor(&msk).expect("MSK to CBOR failed");
        let msk2 = cbor_ser::msk_from_cbor(&msk_cbor).expect("MSK from CBOR failed");
        assert_eq!(msk.scheme, msk2.scheme);

        // Test SK CBOR roundtrip
        let attrs = vec!["admin".to_string()];
        let sk = waters_cp::keygen(&mpk, &msk, &attrs).expect("Keygen failed");
        let sk_cbor = cbor_ser::sk_to_cbor(&sk).expect("SK to CBOR failed");
        let sk2 = cbor_ser::sk_from_cbor(&sk_cbor).expect("SK from CBOR failed");
        assert_eq!(sk.attributes, sk2.attributes);
    }
}
