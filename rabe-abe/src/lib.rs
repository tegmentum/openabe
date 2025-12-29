//! rabe-abe: Attribute-Based Encryption schemes using BLS12-381
//!
//! This crate provides ABE schemes built on top of the BLS12-381 pairing curve
//! for 128-bit security.
//!
//! # Schemes
//!
//! - `bsw`: Bethencourt-Sahai-Waters CP-ABE (simplified, AND policies only)
//! - `waters`: Waters '11 CP-ABE (full LSSS support, CPA-secure)
//!
//! # Example (Waters '11)
//!
//! ```rust
//! use rabe_abe::schemes::waters::{setup, keygen, encrypt, decrypt};
//! use rabe_abe::PolicyNode;
//! use rand::thread_rng;
//!
//! let mut rng = thread_rng();
//!
//! // Setup
//! let (mpk, msk) = setup(&mut rng);
//!
//! // Generate key for user with attributes
//! let attrs = vec!["admin".to_string(), "dept:eng".to_string()];
//! let sk = keygen(&mut rng, &mpk, &msk, &attrs).unwrap();
//!
//! // Encrypt with policy
//! let policy = PolicyNode::And(vec![
//!     PolicyNode::Attr("admin".to_string()),
//!     PolicyNode::Attr("dept:eng".to_string()),
//! ]);
//! let plaintext = b"Secret message";
//! let ct = encrypt(&mut rng, &mpk, &policy, plaintext).unwrap();
//!
//! // Decrypt
//! let decrypted = decrypt(&mpk, &sk, &ct).unwrap();
//! assert_eq!(decrypted, plaintext);
//! ```

pub mod schemes;
pub mod utils;
pub mod error;
pub mod lsss;
pub mod cbor;
pub mod tracing;
pub mod security;
pub mod scheme_types;

pub use error::AbeError;
pub use lsss::{LsssMatrix, LsssShare, PolicyNode};
pub use tracing::{UserId, TraceResult, RevocationList};
pub use security::{secure_compare, validate_policy, validate_plaintext};

// Re-export the pairing primitives
pub use rabe_bls12381::{Fr, G1, G2, Gt, pairing};

// Re-export scheme type markers and wrappers
pub use scheme_types::{
    Scheme, Waters, WatersCca, Ac17, Gpsw, Bsw, Dabe,
    TypedMpk, TypedMsk, TypedSecretKey, TypedCiphertext,
    TypedFullCiphertext, TypedReKey, TypedReEncryptedCiphertext,
};
