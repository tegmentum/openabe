//! Threshold Authority Tracing
//!
//! This module implements threshold tracing where multiple authorities must
//! cooperate (t-of-n threshold) to trace a leaked key. This prevents single
//! authority abuse of tracing capabilities.
//!
//! # Motivation
//!
//! In standard traceable ABE, a single authority holds the tracing key.
//! This creates a single point of abuse - a malicious authority could
//! trace keys without oversight. Threshold tracing splits the tracing
//! key among multiple authorities.
//!
//! # Construction
//!
//! - Setup: Generate tracing secret τ, share it using Shamir's secret sharing
//! - Each authority receives a share of τ
//! - Tracing: Each authority computes a partial trace using their share
//! - Combining: t partial traces are combined to identify the user
//!
//! # Security Properties
//!
//! - No single authority can trace alone (requires t authorities)
//! - Collusion of up to t-1 authorities reveals nothing
//! - Verifiable partial traces ensure authorities behave honestly

use crate::error::AbeError;
use crate::tracing::{UserId, TraceResult};
use crate::utils::hash_to_g1;
use rabe_bls12381::{Fr, G1, G2, pairing};
use rand::{RngCore, CryptoRng};
use std::collections::HashMap;

/// Configuration for threshold tracing
#[derive(Clone, Debug)]
pub struct ThresholdConfig {
    /// Number of authorities required to trace (t)
    pub threshold: usize,
    /// Total number of authorities (n)
    pub total_authorities: usize,
}

impl ThresholdConfig {
    /// Create a new threshold configuration
    pub fn new(threshold: usize, total_authorities: usize) -> Result<Self, AbeError> {
        if threshold == 0 {
            return Err(AbeError::InvalidPolicy("Threshold must be at least 1".into()));
        }
        if threshold > total_authorities {
            return Err(AbeError::InvalidPolicy(
                "Threshold cannot exceed total authorities".into(),
            ));
        }
        Ok(Self {
            threshold,
            total_authorities,
        })
    }
}

/// Public parameters for threshold tracing
#[derive(Clone, Debug)]
pub struct ThresholdTracingParams {
    /// Configuration
    pub config: ThresholdConfig,
    /// Combined verification key: g2^τ
    pub combined_vk: G2,
    /// Per-authority verification keys for partial trace verification
    pub authority_vks: Vec<AuthorityVerificationKey>,
}

/// Verification key for an authority's share
#[derive(Clone, Debug)]
pub struct AuthorityVerificationKey {
    /// Authority identifier
    pub authority_id: String,
    /// Authority index (1-based for Lagrange interpolation)
    pub index: usize,
    /// Verification commitment: g2^share_i
    pub vk: G2,
}

/// A tracing key share held by one authority
#[derive(Clone, Debug)]
pub struct TracingKeyShare {
    /// Authority identifier
    pub authority_id: String,
    /// Authority index (1-based)
    pub index: usize,
    /// Share of the tracing secret: τ_i
    pub share: Fr,
    /// Verification commitment: g2^τ_i
    pub verification: G2,
}

impl Drop for TracingKeyShare {
    fn drop(&mut self) {
        self.share = Fr::zero();
    }
}

/// Combined tracing key (for non-threshold operations)
/// Only used when all shares are combined
#[derive(Clone, Debug)]
pub struct CombinedTracingKey {
    /// Full tracing secret τ
    pub trace_sk: Fr,
    /// Verification key g2^τ
    pub trace_vk: G2,
}

impl Drop for CombinedTracingKey {
    fn drop(&mut self) {
        self.trace_sk = Fr::zero();
    }
}

/// Partial trace result from one authority
#[derive(Clone, Debug)]
pub struct PartialTraceResult {
    /// Authority that computed this partial trace
    pub authority_id: String,
    /// Authority index
    pub index: usize,
    /// Partial verification: H(candidate_user_id)^share_i
    pub partial_verification: G1,
    /// The candidate user ID being tested
    pub candidate_user_id: UserId,
}

/// Identity commitment embedded in traceable keys
#[derive(Clone, Debug)]
pub struct ThresholdIdentityCommitment {
    /// H(user_id)^τ
    pub commitment: G1,
}

impl ThresholdIdentityCommitment {
    /// Create a new identity commitment
    pub fn new<R: RngCore + CryptoRng>(
        _rng: &mut R,
        user_id: &UserId,
        combined_key: &CombinedTracingKey,
    ) -> Self {
        let h_id = hash_to_g1(user_id.as_str());
        let commitment = h_id * combined_key.trace_sk;
        Self { commitment }
    }

    /// Verify commitment against the combined verification key
    pub fn verify(&self, user_id: &UserId, combined_vk: &G2) -> bool {
        let h_id = hash_to_g1(user_id.as_str());
        let lhs = pairing(self.commitment, G2::one());
        let rhs = pairing(h_id, *combined_vk);
        lhs == rhs
    }
}

/// Setup threshold tracing
///
/// Generates the tracing secret and distributes shares to authorities.
/// Returns the public parameters and the shares for each authority.
pub fn threshold_setup<R: RngCore + CryptoRng>(
    rng: &mut R,
    config: ThresholdConfig,
    authority_ids: &[String],
) -> Result<(ThresholdTracingParams, Vec<TracingKeyShare>), AbeError> {
    if authority_ids.len() != config.total_authorities {
        return Err(AbeError::InvalidPolicy(
            "Number of authority IDs must match total_authorities".into(),
        ));
    }

    // Generate the master tracing secret
    let trace_sk = Fr::random(rng);
    let combined_vk = G2::one() * trace_sk;

    // Generate random polynomial coefficients for Shamir's secret sharing
    // f(x) = trace_sk + a_1*x + a_2*x^2 + ... + a_{t-1}*x^{t-1}
    let mut coefficients = vec![trace_sk];
    for _ in 1..config.threshold {
        coefficients.push(Fr::random(rng));
    }

    // Evaluate polynomial at points 1, 2, ..., n to get shares
    let mut shares = Vec::with_capacity(config.total_authorities);
    let mut authority_vks = Vec::with_capacity(config.total_authorities);

    for (i, authority_id) in authority_ids.iter().enumerate() {
        let x = Fr::from_u64((i + 1) as u64); // 1-based index

        // Evaluate f(x) = sum(coefficients[j] * x^j)
        let mut share = Fr::zero();
        let mut x_power = Fr::one();
        for coeff in &coefficients {
            share = share + (*coeff * x_power);
            x_power = x_power * x;
        }

        let verification = G2::one() * share;

        shares.push(TracingKeyShare {
            authority_id: authority_id.clone(),
            index: i + 1,
            share,
            verification,
        });

        authority_vks.push(AuthorityVerificationKey {
            authority_id: authority_id.clone(),
            index: i + 1,
            vk: verification,
        });
    }

    let params = ThresholdTracingParams {
        config,
        combined_vk,
        authority_vks,
    };

    Ok((params, shares))
}

/// Compute a partial trace for a candidate user
///
/// Each authority computes this using their share.
pub fn compute_partial_trace(
    share: &TracingKeyShare,
    candidate_user_id: &UserId,
) -> PartialTraceResult {
    let h_id = hash_to_g1(candidate_user_id.as_str());
    let partial_verification = h_id * share.share;

    PartialTraceResult {
        authority_id: share.authority_id.clone(),
        index: share.index,
        partial_verification,
        candidate_user_id: candidate_user_id.clone(),
    }
}

/// Verify a partial trace result
///
/// Ensures the authority computed the partial trace correctly.
pub fn verify_partial_trace(
    params: &ThresholdTracingParams,
    partial: &PartialTraceResult,
) -> bool {
    // Find the authority's verification key
    let authority_vk = params
        .authority_vks
        .iter()
        .find(|vk| vk.authority_id == partial.authority_id);

    let authority_vk = match authority_vk {
        Some(vk) => vk,
        None => return false,
    };

    // Verify: e(partial_verification, g2) == e(H(user_id), authority_vk)
    let h_id = hash_to_g1(partial.candidate_user_id.as_str());
    let lhs = pairing(partial.partial_verification, G2::one());
    let rhs = pairing(h_id, authority_vk.vk);

    lhs == rhs
}

/// Combine partial traces to complete the trace
///
/// Requires at least `threshold` valid partial traces.
/// Uses Lagrange interpolation to reconstruct H(user_id)^τ.
pub fn combine_partial_traces(
    params: &ThresholdTracingParams,
    partial_traces: &[PartialTraceResult],
    commitment: &ThresholdIdentityCommitment,
) -> Result<TraceResult, AbeError> {
    if partial_traces.len() < params.config.threshold {
        return Err(AbeError::DecryptError(format!(
            "Need at least {} partial traces, got {}",
            params.config.threshold,
            partial_traces.len()
        )));
    }

    // Verify all partial traces are for the same candidate
    let candidate_user_id = &partial_traces[0].candidate_user_id;
    for partial in partial_traces {
        if &partial.candidate_user_id != candidate_user_id {
            return Err(AbeError::DecryptError(
                "All partial traces must be for the same candidate".into(),
            ));
        }
        // Verify each partial trace
        if !verify_partial_trace(params, partial) {
            return Err(AbeError::DecryptError(format!(
                "Invalid partial trace from authority {}",
                partial.authority_id
            )));
        }
    }

    // Use Lagrange interpolation to reconstruct H(user_id)^τ
    // H(user_id)^τ = ∏_i (partial_i)^(λ_i) where λ_i are Lagrange coefficients

    let indices: Vec<usize> = partial_traces.iter().map(|p| p.index).collect();
    let lagrange_coeffs = compute_lagrange_coefficients(&indices, params.config.threshold)?;

    // Combine: ∏_i partial_i^λ_i = H(user_id)^(∑ share_i * λ_i) = H(user_id)^τ
    let mut combined = G1::zero();
    for (partial, coeff) in partial_traces.iter().zip(lagrange_coeffs.iter()) {
        combined = combined + partial.partial_verification * *coeff;
    }

    // Verify against the commitment
    if combined == commitment.commitment {
        Ok(TraceResult::Traced(vec![candidate_user_id.clone()]))
    } else {
        Ok(TraceResult::Inconclusive)
    }
}

/// Threshold trace: full workflow to trace a commitment
///
/// Given partial traces from authorities and a list of candidates,
/// determine which user's commitment matches.
pub fn threshold_trace(
    params: &ThresholdTracingParams,
    partial_traces_by_candidate: &HashMap<UserId, Vec<PartialTraceResult>>,
    commitment: &ThresholdIdentityCommitment,
) -> TraceResult {
    for (candidate, partials) in partial_traces_by_candidate {
        if partials.len() >= params.config.threshold {
            if let Ok(result) = combine_partial_traces(params, partials, commitment) {
                if result.is_traced() {
                    return result;
                }
            }
        }
    }

    TraceResult::Inconclusive
}

/// Compute Lagrange coefficients for interpolation
fn compute_lagrange_coefficients(
    indices: &[usize],
    count: usize,
) -> Result<Vec<Fr>, AbeError> {
    if indices.len() < count {
        return Err(AbeError::DecryptError("Not enough indices".into()));
    }

    let indices_to_use = &indices[..count];
    let mut coefficients = Vec::with_capacity(count);

    for (i, &xi) in indices_to_use.iter().enumerate() {
        let xi_fr = Fr::from_u64(xi as u64);
        let mut coeff = Fr::one();

        for (j, &xj) in indices_to_use.iter().enumerate() {
            if i != j {
                let xj_fr = Fr::from_u64(xj as u64);
                // λ_i = ∏_{j≠i} (0 - x_j) / (x_i - x_j) = ∏_{j≠i} (-x_j) / (x_i - x_j)
                let numerator = Fr::zero() - xj_fr;
                let denominator = xi_fr - xj_fr;

                if denominator == Fr::zero() {
                    return Err(AbeError::DecryptError("Duplicate indices".into()));
                }

                // Safe to unwrap: we checked denominator != 0 above
                let inv = denominator.inverse().expect("non-zero has inverse");
                coeff = coeff * numerator * inv;
            }
        }

        coefficients.push(coeff);
    }

    Ok(coefficients)
}

/// Convenience function: combine shares to create full tracing key
/// Use only when threshold security is not needed (e.g., initial setup)
pub fn combine_shares(
    shares: &[TracingKeyShare],
    threshold: usize,
) -> Result<CombinedTracingKey, AbeError> {
    if shares.len() < threshold {
        return Err(AbeError::DecryptError(format!(
            "Need at least {} shares, got {}",
            threshold,
            shares.len()
        )));
    }

    let indices: Vec<usize> = shares.iter().map(|s| s.index).collect();
    let lagrange_coeffs = compute_lagrange_coefficients(&indices, threshold)?;

    // Reconstruct: τ = ∑ share_i * λ_i
    let mut trace_sk = Fr::zero();
    for (share, coeff) in shares.iter().zip(lagrange_coeffs.iter()) {
        trace_sk = trace_sk + share.share * *coeff;
    }

    let trace_vk = G2::one() * trace_sk;

    Ok(CombinedTracingKey { trace_sk, trace_vk })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::thread_rng;

    #[test]
    fn test_threshold_setup() {
        let mut rng = thread_rng();
        let config = ThresholdConfig::new(2, 3).unwrap();
        let authority_ids = vec![
            "authority_a".to_string(),
            "authority_b".to_string(),
            "authority_c".to_string(),
        ];

        let (params, shares) = threshold_setup(&mut rng, config, &authority_ids).unwrap();

        assert_eq!(shares.len(), 3);
        assert_eq!(params.authority_vks.len(), 3);
        assert_eq!(params.config.threshold, 2);
        assert_eq!(params.config.total_authorities, 3);
    }

    #[test]
    fn test_share_reconstruction() {
        let mut rng = thread_rng();
        let config = ThresholdConfig::new(2, 3).unwrap();
        let authority_ids = vec![
            "authority_a".to_string(),
            "authority_b".to_string(),
            "authority_c".to_string(),
        ];

        let (params, shares) = threshold_setup(&mut rng, config, &authority_ids).unwrap();

        // Reconstruct from first 2 shares
        let combined = combine_shares(&shares[..2], 2).unwrap();
        assert_eq!(combined.trace_vk, params.combined_vk);

        // Reconstruct from last 2 shares - should get same key
        let combined2 = combine_shares(&shares[1..], 2).unwrap();
        assert_eq!(combined2.trace_vk, params.combined_vk);

        // Reconstruct from shares 0 and 2
        let combined3 = combine_shares(&[shares[0].clone(), shares[2].clone()], 2).unwrap();
        assert_eq!(combined3.trace_vk, params.combined_vk);
    }

    #[test]
    fn test_partial_trace_verification() {
        let mut rng = thread_rng();
        let config = ThresholdConfig::new(2, 3).unwrap();
        let authority_ids = vec![
            "authority_a".to_string(),
            "authority_b".to_string(),
            "authority_c".to_string(),
        ];

        let (params, shares) = threshold_setup(&mut rng, config, &authority_ids).unwrap();

        let candidate = UserId::new("alice");

        // Compute partial trace from authority A
        let partial = compute_partial_trace(&shares[0], &candidate);

        // Verify it
        assert!(verify_partial_trace(&params, &partial));

        // Verify wrong authority fails
        let mut bad_partial = partial.clone();
        bad_partial.authority_id = "authority_x".to_string();
        assert!(!verify_partial_trace(&params, &bad_partial));
    }

    #[test]
    fn test_threshold_trace_success() {
        let mut rng = thread_rng();
        let config = ThresholdConfig::new(2, 3).unwrap();
        let authority_ids = vec![
            "authority_a".to_string(),
            "authority_b".to_string(),
            "authority_c".to_string(),
        ];

        let (params, shares) = threshold_setup(&mut rng, config, &authority_ids).unwrap();

        // Create commitment for alice
        let combined_key = combine_shares(&shares, 2).unwrap();
        let alice = UserId::new("alice");
        let commitment = ThresholdIdentityCommitment::new(&mut rng, &alice, &combined_key);

        // Authorities compute partial traces for alice
        let partial_a = compute_partial_trace(&shares[0], &alice);
        let partial_b = compute_partial_trace(&shares[1], &alice);

        // Combine partial traces
        let result = combine_partial_traces(&params, &[partial_a, partial_b], &commitment).unwrap();

        assert!(result.is_traced());
        let traitors = result.traitors().unwrap();
        assert_eq!(traitors.len(), 1);
        assert_eq!(traitors[0].as_str(), "alice");
    }

    #[test]
    fn test_threshold_trace_wrong_user() {
        let mut rng = thread_rng();
        let config = ThresholdConfig::new(2, 3).unwrap();
        let authority_ids = vec![
            "authority_a".to_string(),
            "authority_b".to_string(),
            "authority_c".to_string(),
        ];

        let (params, shares) = threshold_setup(&mut rng, config, &authority_ids).unwrap();

        // Create commitment for alice
        let combined_key = combine_shares(&shares, 2).unwrap();
        let alice = UserId::new("alice");
        let commitment = ThresholdIdentityCommitment::new(&mut rng, &alice, &combined_key);

        // Authorities compute partial traces for bob (wrong user)
        let bob = UserId::new("bob");
        let partial_a = compute_partial_trace(&shares[0], &bob);
        let partial_b = compute_partial_trace(&shares[1], &bob);

        // Combine - should not match
        let result = combine_partial_traces(&params, &[partial_a, partial_b], &commitment).unwrap();

        assert!(!result.is_traced());
    }

    #[test]
    fn test_insufficient_threshold() {
        let mut rng = thread_rng();
        let config = ThresholdConfig::new(2, 3).unwrap();
        let authority_ids = vec![
            "authority_a".to_string(),
            "authority_b".to_string(),
            "authority_c".to_string(),
        ];

        let (params, shares) = threshold_setup(&mut rng, config, &authority_ids).unwrap();

        // Create commitment for alice
        let combined_key = combine_shares(&shares, 2).unwrap();
        let alice = UserId::new("alice");
        let commitment = ThresholdIdentityCommitment::new(&mut rng, &alice, &combined_key);

        // Only one partial trace (below threshold)
        let partial_a = compute_partial_trace(&shares[0], &alice);

        // Should fail - not enough partial traces
        let result = combine_partial_traces(&params, &[partial_a], &commitment);
        assert!(result.is_err());
    }

    #[test]
    fn test_commitment_verification() {
        let mut rng = thread_rng();
        let config = ThresholdConfig::new(2, 3).unwrap();
        let authority_ids = vec![
            "authority_a".to_string(),
            "authority_b".to_string(),
            "authority_c".to_string(),
        ];

        let (params, shares) = threshold_setup(&mut rng, config, &authority_ids).unwrap();

        let combined_key = combine_shares(&shares, 2).unwrap();
        let alice = UserId::new("alice");
        let commitment = ThresholdIdentityCommitment::new(&mut rng, &alice, &combined_key);

        // Verify commitment against combined vk
        assert!(commitment.verify(&alice, &params.combined_vk));

        // Should not verify for wrong user
        let bob = UserId::new("bob");
        assert!(!commitment.verify(&bob, &params.combined_vk));
    }

    #[test]
    fn test_three_of_five_threshold() {
        let mut rng = thread_rng();
        let config = ThresholdConfig::new(3, 5).unwrap();
        let authority_ids: Vec<String> = (1..=5).map(|i| format!("auth_{}", i)).collect();

        let (params, shares) = threshold_setup(&mut rng, config, &authority_ids).unwrap();

        // Combine any 3 shares - should work
        let combined1 = combine_shares(&[shares[0].clone(), shares[1].clone(), shares[2].clone()], 3).unwrap();
        let combined2 = combine_shares(&[shares[2].clone(), shares[3].clone(), shares[4].clone()], 3).unwrap();
        let combined3 = combine_shares(&[shares[0].clone(), shares[2].clone(), shares[4].clone()], 3).unwrap();

        // All should produce the same combined_vk
        assert_eq!(combined1.trace_vk, params.combined_vk);
        assert_eq!(combined2.trace_vk, params.combined_vk);
        assert_eq!(combined3.trace_vk, params.combined_vk);

        // 2 shares should not be enough
        let result = combine_shares(&[shares[0].clone(), shares[1].clone()], 3);
        assert!(result.is_err());
    }
}
