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
//!
//! ## Proxy Re-Encryption (PRE)
//!
//! - `waters_pre`: Proxy Re-Encryption for Waters '11 CP-ABE (key rotation/recovery)
//! - `dabe_pre`: Proxy Re-Encryption for DABE (multi-authority key rotation)
//! - `ac17_pre`: Proxy Re-Encryption for AC17 CP-ABE (key rotation/recovery)
//!
//! ## User-to-User Proxy Re-Encryption (U2U-PRE)
//!
//! - `waters_u2u_pre`: User-to-User PRE for Waters '11 (delegate to different user)
//! - `dabe_u2u_pre`: User-to-User PRE for DABE (multi-authority delegation)
//! - `ac17_u2u_pre`: User-to-User PRE for AC17 (delegate to different user)
//!
//! ## Advanced PRE Schemes
//!
//! - `conditional_pre`: Time-based and policy-based conditional PRE (Waters)
//! - `multihop_pre`: Multi-hop PRE allowing delegation chains (Waters)
//! - `ac17_conditional_pre`: Time-based conditional PRE for AC17
//! - `ac17_multihop_pre`: Multi-hop PRE for AC17
//! - `dabe_conditional_pre`: Time-based conditional PRE for DABE with trusted timestamps
//! - `dabe_multihop_pre`: Multi-hop PRE for DABE

pub mod bsw;
pub mod waters;
pub mod waters_cca;
pub mod gpsw;
pub mod ac17;
pub mod dabe;
pub mod waters_pre;
pub mod dabe_pre;
pub mod waters_u2u_pre;
pub mod dabe_u2u_pre;
pub mod ac17_pre;
pub mod ac17_u2u_pre;
pub mod conditional_pre;
pub mod multihop_pre;
pub mod ac17_conditional_pre;
pub mod ac17_multihop_pre;
pub mod dabe_conditional_pre;
pub mod dabe_multihop_pre;

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

// Re-export Waters PRE types
pub use waters_pre::{
    ReEncryptionKey as WatersReKey,
    ReEncryptedCiphertext as WatersReEncryptedCiphertext,
    FullReEncryptedCiphertext as WatersFullReEncryptedCiphertext,
    generate_rekey as waters_pre_generate_rekey,
    re_encrypt as waters_pre_re_encrypt,
    re_encrypt_full as waters_pre_re_encrypt_full,
    decrypt_reencrypted as waters_pre_decrypt_reencrypted,
    decrypt_reencrypted_kem as waters_pre_decrypt_reencrypted_kem,
};

// Re-export DABE PRE types
pub use dabe_pre::{
    AuthorityReKeyComponent as DabeAuthorityReKeyComponent,
    DabeReEncryptionKey,
    DabeReEncryptedCiphertext,
    FullDabeReEncryptedCiphertext,
    generate_rekey as dabe_pre_generate_rekey,
    re_encrypt as dabe_pre_re_encrypt,
    re_encrypt_full as dabe_pre_re_encrypt_full,
    decrypt_reencrypted as dabe_pre_decrypt_reencrypted,
    decrypt_reencrypted_kem as dabe_pre_decrypt_reencrypted_kem,
};

// Re-export Waters U2U PRE types
pub use waters_u2u_pre::{
    DelegationKeyPair,
    TargetPublicKey,
    TargetSecret,
    U2UReEncryptionKey,
    U2UReEncryptedCiphertext,
    FullU2UReEncryptedCiphertext,
    generate_delegation_keypair,
    abe_key_to_target_pk,
    generate_u2u_rekey as waters_u2u_generate_rekey,
    u2u_re_encrypt as waters_u2u_re_encrypt,
    u2u_re_encrypt_full as waters_u2u_re_encrypt_full,
    u2u_decrypt_reencrypted as waters_u2u_decrypt,
    u2u_decrypt_reencrypted_kem as waters_u2u_decrypt_kem,
};

// Re-export DABE U2U PRE types
pub use dabe_u2u_pre::{
    U2UAuthorityReKeyComponent as DabeU2UAuthorityReKeyComponent,
    DabeU2UReEncryptionKey,
    DabeU2UReEncryptedCiphertext,
    FullDabeU2UReEncryptedCiphertext,
    generate_u2u_rekey as dabe_u2u_generate_rekey,
    u2u_re_encrypt as dabe_u2u_re_encrypt,
    u2u_re_encrypt_full as dabe_u2u_re_encrypt_full,
    u2u_decrypt_reencrypted as dabe_u2u_decrypt,
    u2u_decrypt_reencrypted_kem as dabe_u2u_decrypt_kem,
};

// Re-export AC17 PRE types
pub use ac17_pre::{
    ReEncryptionKey as Ac17ReKey,
    ReEncryptedCiphertext as Ac17ReEncryptedCiphertext,
    FullReEncryptedCiphertext as Ac17FullReEncryptedCiphertext,
    generate_rekey as ac17_pre_generate_rekey,
    re_encrypt as ac17_pre_re_encrypt,
    re_encrypt_full as ac17_pre_re_encrypt_full,
    decrypt_reencrypted as ac17_pre_decrypt_reencrypted,
    decrypt_reencrypted_kem as ac17_pre_decrypt_reencrypted_kem,
};

// Re-export AC17 U2U PRE types
pub use ac17_u2u_pre::{
    U2UReEncryptionKey as Ac17U2UReEncryptionKey,
    U2UReEncryptedCiphertext as Ac17U2UReEncryptedCiphertext,
    FullU2UReEncryptedCiphertext as Ac17FullU2UReEncryptedCiphertext,
    generate_delegation_keypair as ac17_generate_delegation_keypair,
    abe_key_to_target_pk as ac17_abe_key_to_target_pk,
    generate_u2u_rekey as ac17_u2u_generate_rekey,
    u2u_re_encrypt as ac17_u2u_re_encrypt,
    u2u_re_encrypt_full as ac17_u2u_re_encrypt_full,
    u2u_decrypt_reencrypted as ac17_u2u_decrypt,
    u2u_decrypt_reencrypted_kem as ac17_u2u_decrypt_kem,
};

// Re-export Conditional PRE types
pub use conditional_pre::{
    TimeCondition,
    PolicyCondition,
    ConditionalReEncryptionKey,
    ConditionalReEncryptedCiphertext,
    FullConditionalReEncryptedCiphertext,
    PolicyConditionalReEncryptionKey,
    generate_conditional_rekey,
    conditional_re_encrypt,
    conditional_re_encrypt_full,
    decrypt_conditional_reencrypted as conditional_pre_decrypt,
    decrypt_conditional_reencrypted_kem as conditional_pre_decrypt_kem,
    generate_policy_conditional_rekey,
    verify_proxy_token,
};

// Re-export Multi-hop PRE types
pub use multihop_pre::{
    HopInfo,
    MultiHopReEncryptionKey,
    MultiHopReEncryptedCiphertext,
    FullMultiHopReEncryptedCiphertext,
    generate_first_hop_rekey as multihop_generate_first_rekey,
    first_hop_re_encrypt as multihop_first_re_encrypt,
    first_hop_re_encrypt_full as multihop_first_re_encrypt_full,
    next_hop_re_encrypt as multihop_next_re_encrypt,
    decrypt_multihop as multihop_decrypt,
    decrypt_multihop_kem as multihop_decrypt_kem,
};

// Re-export AC17 Conditional PRE types
pub use ac17_conditional_pre::{
    TimeCondition as Ac17TimeCondition,
    Ac17ConditionalReEncryptionKey,
    Ac17ConditionalReEncryptedCiphertext,
    FullAc17ConditionalReEncryptedCiphertext,
    generate_conditional_rekey as ac17_conditional_generate_rekey,
    conditional_re_encrypt as ac17_conditional_re_encrypt,
    conditional_re_encrypt_full as ac17_conditional_re_encrypt_full,
    decrypt_conditional_reencrypted as ac17_conditional_decrypt,
    decrypt_conditional_reencrypted_kem as ac17_conditional_decrypt_kem,
};

// Re-export AC17 Multi-hop PRE types
pub use ac17_multihop_pre::{
    Ac17HopInfo,
    Ac17MultiHopReEncryptionKey,
    Ac17MultiHopReEncryptedCiphertext,
    FullAc17MultiHopReEncryptedCiphertext,
    generate_first_hop_rekey as ac17_multihop_generate_first_rekey,
    first_hop_re_encrypt as ac17_multihop_first_re_encrypt,
    first_hop_re_encrypt_full as ac17_multihop_first_re_encrypt_full,
    next_hop_re_encrypt as ac17_multihop_next_re_encrypt,
    decrypt_multihop as ac17_multihop_decrypt,
    decrypt_multihop_kem as ac17_multihop_decrypt_kem,
};

// Re-export DABE Conditional PRE types
pub use dabe_conditional_pre::{
    TimeCondition as DabeTimeCondition,
    TrustedTimestamp,
    ConditionalAuthorityReKeyComponent as DabeConditionalAuthorityReKeyComponent,
    DabeConditionalReEncryptionKey,
    DabeConditionalReEncryptedCiphertext,
    FullDabeConditionalReEncryptedCiphertext,
    generate_conditional_rekey as dabe_conditional_generate_rekey,
    generate_conditional_rekey_with_trusted_time as dabe_conditional_generate_rekey_trusted,
    conditional_re_encrypt as dabe_conditional_re_encrypt,
    conditional_re_encrypt_with_timestamp as dabe_conditional_re_encrypt_trusted,
    conditional_re_encrypt_full as dabe_conditional_re_encrypt_full,
    conditional_re_encrypt_full_with_timestamp as dabe_conditional_re_encrypt_full_trusted,
    decrypt_conditional_reencrypted as dabe_conditional_decrypt,
    decrypt_conditional_reencrypted_kem as dabe_conditional_decrypt_kem,
};

// Re-export DABE Multi-hop PRE types
pub use dabe_multihop_pre::{
    DabeHopInfo,
    MultiHopAuthorityReKeyComponent as DabeMultiHopAuthorityReKeyComponent,
    DabeMultiHopReEncryptionKey,
    DabeMultiHopReEncryptedCiphertext,
    FullDabeMultiHopReEncryptedCiphertext,
    generate_delegation_keypair as dabe_multihop_generate_keypair,
    generate_first_hop_rekey as dabe_multihop_generate_first_rekey,
    first_hop_re_encrypt as dabe_multihop_first_re_encrypt,
    first_hop_re_encrypt_full as dabe_multihop_first_re_encrypt_full,
    next_hop_re_encrypt as dabe_multihop_next_re_encrypt,
    next_hop_re_encrypt_full as dabe_multihop_next_re_encrypt_full,
    decrypt_multihop as dabe_multihop_decrypt,
    decrypt_multihop_kem as dabe_multihop_decrypt_kem,
};
