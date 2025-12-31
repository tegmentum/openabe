//! Traitor Tracing Module
//!
//! This module provides infrastructure for traitor tracing in ABE systems.
//! Traitor tracing allows identification of users who leak their decryption keys.
//!
//! # Approaches Supported
//!
//! ## White-Box Tracing
//!
//! When a leaked key is available for inspection, the embedded identity commitment
//! can be used to trace it back to the original user. This is implemented in the
//! scheme-specific traceable modules (e.g., `waters_traceable`, `ac17_traceable`).
//!
//! ## Black-Box Tracing
//!
//! When only a "pirate decoder" (black-box) is available, tracing uses oracle
//! queries to identify traitors through binary search or fingerprinting strategies.
//!
//! ## Fingerprinting
//!
//! Content-level fingerprinting embeds user-specific marks in ciphertexts using
//! Boneh-Shaw codes. When leaked content is found, the marks identify the traitor.
//!
//! # Optional Revocation
//!
//! The `revocation` submodule provides an optional system to revoke traced traitors,
//! preventing them from decrypting future ciphertexts.
//!
//! # Example
//!
//! ```rust,ignore
//! use rabe_abe::tracing::{UserId, TraceResult, RevocationList, RevocationReason};
//!
//! // After tracing identifies a traitor
//! let traitor = UserId::new("alice");
//!
//! // Add to revocation list
//! let mut revocation_list = RevocationList::new();
//! revocation_list.revoke_user(traitor, RevocationReason::TraitorTraced);
//!
//! // Check during decryption
//! if revocation_list.is_revoked(&user_id) {
//!     return Err(AbeError::DecryptError("User revoked".into()));
//! }
//! ```

pub mod types;
pub mod revocation;
pub mod fingerprint_codes;
pub mod black_box;
pub mod broadcast;
pub mod dynamic;
pub mod group_testing;
pub mod subset_difference;
pub mod accumulator;

// Re-export commonly used types
pub use types::{
    UserId,
    TraceResult,
    TracingMetadata,
    TraceEvidence,
    BlackBoxTraceResult,
    BlackBoxConfig,
};

pub use revocation::{
    RevocationReason,
    RevocationEntry,
    RevocationList,
    RevocationCheckResult,
    check_revocation,
};

pub use fingerprint_codes::{
    FingerprintCodeParams,
    FingerprintCode,
    UserFingerprint,
    ExtractedFingerprint,
    trace_fingerprint,
    simulate_collusion,
    // Tardos codes
    TardosCodeParams,
    TardosCode,
    TardosAccusation,
    trace_tardos,
    trace_tardos_simple,
    // Collusion strategies
    CollusionStrategy,
    simulate_collusion_strategy,
};

pub use black_box::{
    PirateDecoder,
    TracingEncryptor,
    QueryResult,
    TracingStats,
    black_box_trace,
    adaptive_trace,
};

pub use broadcast::{
    CompleteSubtreeParams,
    NodeKey,
    BroadcastUserKey,
    CoverSubset,
    BroadcastHeader,
    BroadcastCiphertext,
    BroadcastMasterKey,
    generate_user_key as broadcast_generate_user_key,
    compute_cover,
    broadcast_encrypt,
    broadcast_decrypt,
    trace_broadcast_key,
};

pub use dynamic::{
    SuspectState,
    SuspectEvidence,
    DynamicTracingState,
    TracingPhase,
    DynamicConfig,
    DynamicTraceResult,
    dynamic_trace,
    sequential_elimination,
};

pub use group_testing::{
    TestResult as GroupTestResult,
    GroupTestOracle,
    TestMatrix,
    GroupTestParams,
    GroupTestResult as GroupTestingResult,
    non_adaptive_group_test,
    binary_splitting,
    generalized_binary_splitting,
    hwang_algorithm,
    group_test_trace,
};

pub use subset_difference::{
    SubsetDiffParams,
    SubsetDiff,
    SubsetDiffKey,
    SDUserKey,
    SDCover,
    SDMasterKey,
    SDHeader,
    SDCiphertext,
    generate_sd_user_key,
    compute_sd_cover,
    sd_encrypt,
    sd_decrypt,
};

pub use accumulator::{
    UserId as AccumulatorUserId,
    AccumulatorPublicKey,
    AccumulatorSecretKey,
    Accumulator,
    MembershipWitness,
    NonMembershipWitness,
    AccumulatorUpdate,
    accumulator_setup,
    add_to_accumulator,
    revoke_user as accumulator_revoke_user,
    generate_membership_witness,
    verify_membership,
    generate_non_membership_witness,
    verify_non_membership,
    update_non_membership_witness,
    batch_update_witnesses,
    register_user as accumulator_register_user,
    check_user_status as accumulator_check_user_status,
};
