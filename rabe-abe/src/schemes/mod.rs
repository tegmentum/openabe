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
//!
//! ## Traitor Tracing Schemes
//!
//! - `waters_traceable`: Waters '11 with white-box traitor tracing
//! - `ac17_traceable`: AC17 with white-box traitor tracing
//! - `dabe_traceable`: DABE with multi-authority white-box traitor tracing
//!
//! ## Trace-and-Revoke ABE
//!
//! - `waters_trace_revoke`: Waters '11 with integrated tracing and revocation
//! - `ac17_trace_revoke`: AC17 with integrated tracing and revocation
//! - `dabe_trace_revoke`: DABE with integrated tracing and revocation
//!
//! ## Accountable ABE
//!
//! - `accountable`: Accountable ABE with non-repudiable traitor tracing
//!
//! ## Revocation Schemes
//!
//! - `time_revocation`: Time-based revocation (BGM) - keys require periodic updates
//! - `direct_revocation`: Direct revocation using identity attributes in policy
//! - `mediated_abe`: Mediator-based revocation (SEM) - requires online mediator assistance
//! - `split_key_abe`: Server-aided revocation with split keys - cacheable server shares
//! - `attribute_expiration`: Attributes with validity periods, auto-expire unless renewed
//! - `revocable_hibe`: Revocable Hierarchical IBE with tree-based revocation
//! - `binary_tree_encryption`: Forward-secure encryption with evolving keys

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
pub mod waters_traceable;
pub mod ac17_traceable;
pub mod dabe_traceable;
pub mod waters_trace_revoke;
pub mod ac17_trace_revoke;
pub mod dabe_trace_revoke;
pub mod accountable;
pub mod time_revocation;
pub mod direct_revocation;
pub mod mediated_abe;
pub mod split_key_abe;
pub mod attribute_expiration;
pub mod revocable_hibe;
pub mod binary_tree_encryption;

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

// Re-export Waters Traceable types
pub use waters_traceable::{
    TraceableMpk as WatersTraceableMpk,
    TraceableMsk as WatersTraceableMsk,
    TracingKey as WatersTracingKey,
    TraceableSecretKey as WatersTraceableSecretKey,
    IdentityProof as WatersIdentityProof,
    traceable_setup as waters_traceable_setup,
    traceable_keygen as waters_traceable_keygen,
    trace_key as waters_trace_key,
    verify_key_origin as waters_verify_key_origin,
    encrypt as waters_traceable_encrypt,
    decrypt as waters_traceable_decrypt,
};

// Re-export AC17 Traceable types
pub use ac17_traceable::{
    Ac17TraceableMpk,
    Ac17TraceableMsk,
    Ac17TracingKey,
    Ac17TraceableSecretKey,
    Ac17IdentityProof,
    traceable_setup as ac17_traceable_setup,
    traceable_keygen as ac17_traceable_keygen,
    trace_key as ac17_trace_key,
    verify_key_origin as ac17_verify_key_origin,
    encrypt as ac17_traceable_encrypt,
    decrypt as ac17_traceable_decrypt,
};

// Re-export DABE Traceable types
pub use dabe_traceable::{
    DabeTraceableAuthoritySk,
    DabeAuthorityTracingKey,
    DabeIdentityProof,
    DabeTraceableKeyComponent,
    DabeTraceableUserSecretKey,
    global_setup as dabe_traceable_global_setup,
    traceable_authority_setup as dabe_traceable_authority_setup,
    traceable_authority_keygen as dabe_traceable_authority_keygen,
    aggregate_traceable_keys as dabe_aggregate_traceable_keys,
    trace_key as dabe_trace_key,
    trace_key_component as dabe_trace_key_component,
    verify_key_origin as dabe_verify_key_origin,
    encrypt as dabe_traceable_encrypt,
    decrypt as dabe_traceable_decrypt,
};

// Re-export Waters Trace-and-Revoke types
pub use waters_trace_revoke::{
    TraceRevokeMpk as WatersTraceRevokeMpk,
    TraceRevokeMsk as WatersTraceRevokeMsk,
    TraceRevokeTracingKey as WatersTraceRevokeTracingKey,
    TraceRevokeSecretKey as WatersTraceRevokeSecretKey,
    UserIdentityToken as WatersUserIdentityToken,
    RevocationHeader as WatersRevocationHeader,
    TraceRevokeCiphertext as WatersTraceRevokeCiphertext,
    TraceRevokeFullCiphertext as WatersTraceRevokeFullCiphertext,
    setup as waters_trace_revoke_setup,
    keygen as waters_trace_revoke_keygen,
    encrypt as waters_trace_revoke_encrypt,
    decrypt as waters_trace_revoke_decrypt,
    trace_key as waters_trace_revoke_trace_key,
    add_revocation as waters_add_revocation,
    encrypt_with_revocation_list as waters_encrypt_with_revocation_list,
};

// Re-export AC17 Trace-and-Revoke types
pub use ac17_trace_revoke::{
    Ac17TraceRevokeMpk,
    Ac17TraceRevokeMsk,
    Ac17TraceRevokeTracingKey,
    Ac17TraceRevokeSecretKey,
    Ac17UserIdentityToken,
    Ac17RevocationHeader,
    Ac17TraceRevokeCiphertext,
    Ac17TraceRevokeFullCiphertext,
    setup as ac17_trace_revoke_setup,
    keygen as ac17_trace_revoke_keygen,
    encrypt as ac17_trace_revoke_encrypt,
    decrypt as ac17_trace_revoke_decrypt,
    trace_key as ac17_trace_revoke_trace_key,
    add_revocation as ac17_add_revocation,
    encrypt_with_revocation_list as ac17_encrypt_with_revocation_list,
};

// Re-export DABE Trace-and-Revoke types
pub use dabe_trace_revoke::{
    DabeTraceRevokeMpk,
    DabeTraceRevokeMsk,
    DabeTraceRevokeTracingKey,
    DabeTraceRevokeSecretKey,
    DabeUserIdentityToken,
    DabeRevocationHeader,
    DabeTraceRevokeCiphertext,
    DabeTraceRevokeFullCiphertext,
    setup as dabe_trace_revoke_setup,
    keygen as dabe_trace_revoke_keygen,
    encrypt as dabe_trace_revoke_encrypt,
    decrypt as dabe_trace_revoke_decrypt,
    trace_key as dabe_trace_revoke_trace_key,
    add_revocation as dabe_add_revocation,
    encrypt_with_revocation_list as dabe_encrypt_with_revocation_list,
};

// Re-export Accountable ABE types
pub use accountable::{
    UserSigningKey,
    UserVerificationKey,
    SignedKeyRequest,
    IssuanceCertificate,
    AccountableMpk,
    AccountableMsk,
    AccountableTracingKey,
    AccountableSecretKey,
    TraceEvidence as AccountableTraceEvidence,
    UserRegistry,
    setup as accountable_setup,
    generate_user_signing_key,
    create_key_request,
    verify_key_request,
    keygen as accountable_keygen,
    encrypt as accountable_encrypt,
    decrypt as accountable_decrypt,
    trace_key as accountable_trace_key,
    verify_trace_evidence,
};

// Re-export Time-Based Revocation types
pub use time_revocation::{
    TimePeriod,
    TimeBasedMpk,
    TimeBasedMsk,
    TimeBasedSecretKey,
    KeyUpdate,
    TimeBasedCiphertext,
    FullTimeBasedCiphertext,
    RevocationManager,
    UserId as TimeRevocationUserId,
    setup as time_revocation_setup,
    keygen as time_revocation_keygen,
    encrypt as time_revocation_encrypt,
    decrypt as time_revocation_decrypt,
    generate_key_update,
    apply_key_update,
    batch_key_updates,
};

// Re-export Direct Revocation types
pub use direct_revocation::{
    Mpk as DirectRevocationMpk,
    Msk as DirectRevocationMsk,
    SecretKey as DirectRevocationSecretKey,
    Ciphertext as DirectRevocationCiphertext,
    FullCiphertext as DirectRevocationFullCiphertext,
    RevocationSet,
    setup as direct_revocation_setup,
    keygen as direct_revocation_keygen,
    keygen_revoked as direct_revocation_keygen_revoked,
    revoke_key as direct_revocation_revoke_key,
    encrypt as direct_revocation_encrypt,
    encrypt_with_revocation as direct_revocation_encrypt_with_revocation,
    decrypt as direct_revocation_decrypt,
    policy_with_revocation,
    can_decrypt as direct_revocation_can_decrypt,
    user_to_attribute,
    user_to_not_revoked_attribute,
};

// Re-export Mediated ABE (SEM) types
pub use mediated_abe::{
    MediatorId,
    Mpk as MediatedMpk,
    Msk as MediatedMsk,
    MediatorSecretKey,
    UserPartialKey,
    MediatorUserShare,
    MediatorProof,
    Ciphertext as MediatedCiphertext,
    FullCiphertext as MediatedFullCiphertext,
    MediatorDecryptionShare,
    setup as mediated_setup,
    keygen as mediated_keygen,
    generate_mediator_share,
    encrypt as mediated_encrypt,
    mediator_assist,
    decrypt_with_mediator,
    revoke_user as mediated_revoke_user,
    can_user_decrypt,
};

// Re-export Split Key ABE types
pub use split_key_abe::{
    ShareEpoch,
    Mpk as SplitKeyMpk,
    Msk as SplitKeyMsk,
    ServerMasterKey,
    UserKeyShare,
    ServerKeyShare,
    CombinedKey,
    Ciphertext as SplitKeyCiphertext,
    FullCiphertext as SplitKeyFullCiphertext,
    KeyServer,
    setup as split_key_setup,
    keygen as split_key_keygen,
    combine_keys,
    encrypt as split_key_encrypt,
    encrypt_with_epoch,
    decrypt as split_key_decrypt,
    can_decrypt as split_key_can_decrypt,
};

// Re-export Attribute Expiration types
pub use attribute_expiration::{
    Timestamp,
    TimedAttribute,
    Mpk as AttrExpMpk,
    Msk as AttrExpMsk,
    SecretKey as AttrExpSecretKey,
    AttributeKeyComponent,
    RenewalToken,
    Ciphertext as AttrExpCiphertext,
    FullCiphertext as AttrExpFullCiphertext,
    setup as attr_exp_setup,
    keygen as attr_exp_keygen,
    keygen_simple as attr_exp_keygen_simple,
    generate_renewal as attr_exp_generate_renewal,
    apply_renewal as attr_exp_apply_renewal,
    encrypt as attr_exp_encrypt,
    encrypt_now as attr_exp_encrypt_now,
    decrypt as attr_exp_decrypt,
    can_decrypt as attr_exp_can_decrypt,
};

// Re-export Revocable HIBE types
pub use revocable_hibe::{
    TimePeriod as HibePeriod,
    Identity,
    TreeNode as HibeTreeNode,
    Mpk as HibeMpk,
    Msk as HibeMsk,
    SecretKey as HibeSecretKey,
    KeyUpdate as HibeKeyUpdate,
    DecryptionKey as HibeDecryptionKey,
    Ciphertext as HibeCiphertext,
    FullCiphertext as HibeFullCiphertext,
    RevocationState,
    setup as hibe_setup,
    keygen as hibe_keygen,
    delegate as hibe_delegate,
    generate_key_update as hibe_generate_key_update,
    derive_decryption_key as hibe_derive_decryption_key,
    encrypt as hibe_encrypt,
    decrypt as hibe_decrypt,
};

// Re-export Binary Tree Encryption types
pub use binary_tree_encryption::{
    Period,
    NodeId,
    PublicKey as BtePk,
    SecretKey as BteSk,
    NodeSecretKey,
    Ciphertext as BteCiphertext,
    FullCiphertext as BteFullCiphertext,
    setup as bte_setup,
    evolve as bte_evolve,
    evolve_to as bte_evolve_to,
    encrypt as bte_encrypt,
    decrypt as bte_decrypt,
    current_period as bte_current_period,
    remaining_periods as bte_remaining_periods,
};
