//! Error types for ABE operations

use thiserror::Error;

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

    #[error("Policy not satisfied")]
    PolicyNotSatisfied,

    #[error("Invalid policy: {0}")]
    InvalidPolicy(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Invalid attribute: {0}")]
    InvalidAttribute(String),

    #[error("Tracing error: {0}")]
    TracingError(String),

    #[error("User revoked: {0}")]
    RevocationError(String),

    #[error("Internal error: {0}")]
    InternalError(String),

    #[error("Invalid ciphertext: {0}")]
    InvalidCiphertext(String),

    #[error("Cryptographic error: {0}")]
    CryptoError(String),
}
