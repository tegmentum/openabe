//! ABE Schemes
//!
//! This module contains implementations of various ABE schemes.
//!
//! ## CP-ABE (Ciphertext-Policy)
//!
//! - `bsw`: Bethencourt-Sahai-Waters CP-ABE (simplified, AND policies only)
//! - `waters`: Waters '11 CP-ABE (CPA-secure, full LSSS support)
//! - `waters_cca`: Waters '11 CP-ABE with CCA security (Fujisaki-Okamoto transform)
//! - `ac17`: Agrawal-Chase 2017 CP-ABE (more efficient, full LSSS support)
//!
//! ## KP-ABE (Key-Policy)
//!
//! - `gpsw`: Goyal-Pandey-Sahai-Waters KP-ABE (CPA-secure, full LSSS support)
//!
//! ## Multi-Authority ABE
//!
//! - `dabe`: Decentralized Multi-Authority ABE (multiple independent authorities)

pub mod bsw;
pub mod waters;
pub mod waters_cca;
pub mod gpsw;
pub mod ac17;
pub mod dabe;

// Re-export commonly used types (BSW)
pub use bsw::{
    CpAbePublicKey, CpAbeMasterKey, CpAbeSecretKey, CpAbeCiphertext,
    setup, keygen, encrypt, decrypt,
};

// Re-export Waters '11 CPA types with prefix to avoid collision
pub use waters::{
    Mpk as WatersMpk,
    Msk as WatersMsk,
    SecretKey as WatersSecretKey,
    Ciphertext as WatersCiphertext,
    FullCiphertext as WatersFullCiphertext,
    setup as waters_setup,
    keygen as waters_keygen,
    encrypt as waters_encrypt,
    decrypt as waters_decrypt,
    encrypt_kem as waters_encrypt_kem,
    decrypt_kem as waters_decrypt_kem,
    parse_policy,
};

// Re-export Waters '11 CCA types
pub use waters_cca::{
    CcaCiphertext,
    CcaFullCiphertext,
    encrypt as waters_cca_encrypt,
    decrypt as waters_cca_decrypt,
    encrypt_kem as waters_cca_encrypt_kem,
    decrypt_kem as waters_cca_decrypt_kem,
};

// Re-export GPSW KP-ABE types
pub use gpsw::{
    Mpk as GpswMpk,
    Msk as GpswMsk,
    SecretKey as GpswSecretKey,
    Ciphertext as GpswCiphertext,
    FullCiphertext as GpswFullCiphertext,
    setup as gpsw_setup,
    keygen as gpsw_keygen,
    encrypt as gpsw_encrypt,
    decrypt as gpsw_decrypt,
};

// Re-export AC17 CP-ABE types
pub use ac17::{
    Mpk as Ac17Mpk,
    Msk as Ac17Msk,
    SecretKey as Ac17SecretKey,
    Ciphertext as Ac17Ciphertext,
    FullCiphertext as Ac17FullCiphertext,
    setup as ac17_setup,
    keygen as ac17_keygen,
    encrypt as ac17_encrypt,
    decrypt as ac17_decrypt,
};

// Re-export DABE (Decentralized Multi-Authority ABE) types
pub use dabe::{
    GlobalParams as DabeGlobalParams,
    AuthorityPk as DabeAuthorityPk,
    AuthoritySk as DabeAuthoritySk,
    UserKeyComponent as DabeUserKeyComponent,
    UserSecretKey as DabeUserSecretKey,
    Ciphertext as DabeCiphertext,
    FullCiphertext as DabeFullCiphertext,
    global_setup as dabe_global_setup,
    authority_setup as dabe_authority_setup,
    authority_keygen as dabe_authority_keygen,
    aggregate_user_keys as dabe_aggregate_user_keys,
    encrypt as dabe_encrypt,
    decrypt as dabe_decrypt,
};

// Re-export PolicyNode from lsss (via crate root)
pub use crate::lsss::PolicyNode;
