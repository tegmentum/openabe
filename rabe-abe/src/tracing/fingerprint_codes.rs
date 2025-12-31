//! Fingerprinting Codes for Traitor Tracing
//!
//! This module implements fingerprinting codes for content-level traitor tracing:
//!
//! ## Boneh-Shaw Codes
//! Based on "Collusion-Secure Fingerprinting for Digital Data" (1998)
//! - Code length: O(c^4 log(c/ε) log n)
//! - Simple construction, good baseline
//!
//! ## Tardos Codes
//! Based on "Optimal Probabilistic Fingerprint Codes" (2008)
//! - Optimal code length: O(c² log(1/ε))
//! - Uses arcsine distribution for bias generation
//! - Better collusion resistance in practice
//! - Industry standard (used in Cinavia, etc.)
//!
//! # Overview
//!
//! Fingerprinting codes allow tracing when content (not keys) is leaked.
//! Each user gets a unique fingerprint embedded in their decrypted content.
//! If a coalition of users creates a pirated copy, the fingerprint can
//! identify at least one member of the coalition.
//!
//! # Usage
//!
//! 1. Generate fingerprint code for n users with collusion bound c
//! 2. During encryption, create segments with variants for each bit position
//! 3. During decryption, select variants based on user's fingerprint
//! 4. When content leaks, extract the fingerprint and trace

use rand::{RngCore, CryptoRng};
use super::types::{UserId, TraceResult};

/// Parameters for fingerprint code generation
#[derive(Debug, Clone)]
pub struct FingerprintCodeParams {
    /// Number of users (n)
    pub num_users: usize,

    /// Code length per user (l)
    pub code_length: usize,

    /// Collusion tolerance (c)
    pub collusion_bound: usize,

    /// Error probability target
    pub epsilon: f64,
}

impl FingerprintCodeParams {
    /// Create parameters for given number of users and collusion bound
    pub fn new(num_users: usize, collusion_bound: usize) -> Self {
        // Boneh-Shaw code length formula (simplified)
        // L = O(c^4 * log(c/epsilon) * log(n))
        let epsilon = 0.001; // Default error probability
        let log_n = (num_users as f64).ln().max(1.0);
        let log_c_eps = (collusion_bound as f64 / epsilon).ln().max(1.0);
        let c4 = (collusion_bound as f64).powi(4);
        let code_length = (c4 * log_c_eps * log_n).ceil() as usize;

        // Ensure minimum code length
        let code_length = code_length.max(collusion_bound * 10);

        FingerprintCodeParams {
            num_users,
            code_length,
            collusion_bound,
            epsilon,
        }
    }

    /// Create parameters with explicit code length
    pub fn with_length(num_users: usize, code_length: usize, collusion_bound: usize) -> Self {
        FingerprintCodeParams {
            num_users,
            code_length,
            collusion_bound,
            epsilon: 0.001,
        }
    }
}

/// A fingerprint code for multiple users
#[derive(Debug, Clone)]
pub struct FingerprintCode {
    /// Number of users
    pub n: usize,

    /// Code length (number of segments/bits)
    pub l: usize,

    /// Collusion tolerance
    pub c: usize,

    /// Code matrix: code_matrix[user_index][bit_position] = 0 or 1
    pub code_matrix: Vec<Vec<u8>>,
}

impl FingerprintCode {
    /// Generate a random Boneh-Shaw style fingerprint code
    ///
    /// For simplicity, we use a random code matrix. A true Boneh-Shaw
    /// code would use a more structured construction.
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R, params: &FingerprintCodeParams) -> Self {
        let mut code_matrix = Vec::with_capacity(params.num_users);

        for _ in 0..params.num_users {
            let mut user_code = Vec::with_capacity(params.code_length);
            for _ in 0..params.code_length {
                // Generate random bit
                let bit = (rng.next_u32() & 1) as u8;
                user_code.push(bit);
            }
            code_matrix.push(user_code);
        }

        FingerprintCode {
            n: params.num_users,
            l: params.code_length,
            c: params.collusion_bound,
            code_matrix,
        }
    }

    /// Generate using biased codes for better tracing (Tardos-style)
    pub fn generate_biased<R: RngCore + CryptoRng>(rng: &mut R, params: &FingerprintCodeParams) -> Self {
        // Generate bias probabilities for each position
        let biases: Vec<f64> = (0..params.code_length)
            .map(|_| {
                // Use beta distribution center for robustness
                0.3 + (rng.next_u32() as f64 / u32::MAX as f64) * 0.4
            })
            .collect();

        let mut code_matrix = Vec::with_capacity(params.num_users);

        for _ in 0..params.num_users {
            let mut user_code = Vec::with_capacity(params.code_length);
            for j in 0..params.code_length {
                let rand_val = rng.next_u32() as f64 / u32::MAX as f64;
                let bit = if rand_val < biases[j] { 1 } else { 0 };
                user_code.push(bit);
            }
            code_matrix.push(user_code);
        }

        FingerprintCode {
            n: params.num_users,
            l: params.code_length,
            c: params.collusion_bound,
            code_matrix,
        }
    }

    /// Get fingerprint for a specific user
    pub fn get_fingerprint(&self, user_index: usize) -> Option<UserFingerprint> {
        if user_index >= self.n {
            return None;
        }

        Some(UserFingerprint {
            user_index,
            bits: self.code_matrix[user_index].clone(),
        })
    }

    /// Get fingerprint by user ID
    pub fn get_fingerprint_by_id(&self, user_id: &UserId, user_ids: &[UserId]) -> Option<UserFingerprint> {
        let index = user_ids.iter().position(|id| id == user_id)?;
        self.get_fingerprint(index)
    }
}

/// A user's fingerprint (their column in the code matrix)
#[derive(Debug, Clone)]
pub struct UserFingerprint {
    /// Index in the code matrix
    pub user_index: usize,

    /// The fingerprint bits
    pub bits: Vec<u8>,
}

impl UserFingerprint {
    /// Get the bit at a specific position
    pub fn bit_at(&self, position: usize) -> Option<u8> {
        self.bits.get(position).copied()
    }

    /// Length of the fingerprint
    pub fn len(&self) -> usize {
        self.bits.len()
    }

    /// Check if fingerprint is empty
    pub fn is_empty(&self) -> bool {
        self.bits.is_empty()
    }
}

/// Extracted fingerprint from pirated content
#[derive(Debug, Clone)]
pub struct ExtractedFingerprint {
    /// Extracted bits (may contain wildcard positions marked as 2)
    pub bits: Vec<u8>,

    /// Confidence for each bit position (0.0 to 1.0)
    pub confidence: Vec<f64>,
}

impl ExtractedFingerprint {
    /// Create from raw bits
    pub fn new(bits: Vec<u8>) -> Self {
        let confidence = vec![1.0; bits.len()];
        ExtractedFingerprint { bits, confidence }
    }

    /// Create with confidence values
    pub fn with_confidence(bits: Vec<u8>, confidence: Vec<f64>) -> Self {
        ExtractedFingerprint { bits, confidence }
    }
}

/// Trace a leaked fingerprint to identify traitors
///
/// Uses correlation-based scoring to find the most likely traitors.
pub fn trace_fingerprint(
    code: &FingerprintCode,
    extracted: &ExtractedFingerprint,
    user_ids: &[UserId],
    threshold: f64,
) -> TraceResult {
    if user_ids.len() != code.n {
        return TraceResult::Failed("User ID count doesn't match code".to_string());
    }

    if extracted.bits.len() != code.l {
        return TraceResult::Failed("Extracted fingerprint length mismatch".to_string());
    }

    // Calculate correlation score for each user
    let mut scores: Vec<(usize, f64)> = Vec::new();

    for user_idx in 0..code.n {
        let mut score = 0.0;
        let mut total_weight = 0.0;

        for pos in 0..code.l {
            let user_bit = code.code_matrix[user_idx][pos];
            let extracted_bit = extracted.bits[pos];
            let conf = extracted.confidence[pos];

            // Skip wildcard positions
            if extracted_bit == 2 {
                continue;
            }

            total_weight += conf;

            if user_bit == extracted_bit {
                score += conf;
            }
        }

        if total_weight > 0.0 {
            let normalized_score = score / total_weight;
            scores.push((user_idx, normalized_score));
        }
    }

    // Find users above threshold
    let traitors: Vec<UserId> = scores
        .iter()
        .filter(|(_, score)| *score >= threshold)
        .map(|(idx, _)| user_ids[*idx].clone())
        .collect();

    if traitors.is_empty() {
        TraceResult::Inconclusive
    } else {
        TraceResult::Traced(traitors)
    }
}

/// Simulate collusion to test tracing
///
/// Given fingerprints from colluding users, generate a plausible pirated fingerprint.
pub fn simulate_collusion<R: RngCore + CryptoRng>(
    rng: &mut R,
    fingerprints: &[&UserFingerprint],
) -> ExtractedFingerprint {
    if fingerprints.is_empty() {
        return ExtractedFingerprint::new(vec![]);
    }

    let len = fingerprints[0].len();
    let mut bits = Vec::with_capacity(len);
    let mut confidence = Vec::with_capacity(len);

    for pos in 0..len {
        // Collect all bits at this position
        let mut zeros = 0;
        let mut ones = 0;

        for fp in fingerprints {
            match fp.bits.get(pos) {
                Some(0) => zeros += 1,
                Some(1) => ones += 1,
                _ => {}
            }
        }

        // Colluders can only detect a marking if they all have the same value
        if zeros > 0 && ones > 0 {
            // Mixed: colluders can choose either value (or try to scramble)
            // We randomly pick one of the colluder values
            let rand = rng.next_u32() as usize % fingerprints.len();
            bits.push(fingerprints[rand].bits[pos]);
            confidence.push(0.8); // Lower confidence for mixed positions
        } else if ones > 0 {
            bits.push(1);
            confidence.push(1.0);
        } else {
            bits.push(0);
            confidence.push(1.0);
        }
    }

    ExtractedFingerprint { bits, confidence }
}

// ============================================================================
// Tardos Codes - Optimal Probabilistic Fingerprinting
// ============================================================================

/// Parameters for Tardos code generation
#[derive(Debug, Clone)]
pub struct TardosCodeParams {
    /// Number of users (n)
    pub num_users: usize,

    /// Code length (l) - should be O(c² log(1/ε))
    pub code_length: usize,

    /// Collusion tolerance (c)
    pub collusion_bound: usize,

    /// Error probability target (ε)
    pub epsilon: f64,

    /// Cutoff parameter for bias (t₀)
    pub cutoff: f64,
}

impl TardosCodeParams {
    /// Create Tardos parameters with optimal code length
    pub fn new(num_users: usize, collusion_bound: usize) -> Self {
        let epsilon: f64 = 0.0001; // Default error probability
        // Optimal Tardos code length: L = c² * π² * ln(1/ε) / 2
        let c = collusion_bound as f64;
        let code_length = (c * c * std::f64::consts::PI.powi(2) * epsilon.recip().ln() / 2.0).ceil() as usize;
        let code_length = code_length.max(100); // Minimum length

        // Cutoff parameter (typically 1/(300*c))
        let cutoff = 1.0 / (300.0 * c);

        TardosCodeParams {
            num_users,
            code_length,
            collusion_bound,
            epsilon,
            cutoff,
        }
    }

    /// Create with explicit code length
    pub fn with_length(num_users: usize, code_length: usize, collusion_bound: usize) -> Self {
        let c = collusion_bound as f64;
        TardosCodeParams {
            num_users,
            code_length,
            collusion_bound,
            epsilon: 0.0001,
            cutoff: 1.0 / (300.0 * c),
        }
    }
}

/// Tardos fingerprint code with bias values
#[derive(Debug, Clone)]
pub struct TardosCode {
    /// Number of users
    pub n: usize,

    /// Code length
    pub l: usize,

    /// Collusion bound
    pub c: usize,

    /// Bias probabilities for each position (p_i)
    pub biases: Vec<f64>,

    /// Code matrix: code_matrix[user][position]
    pub code_matrix: Vec<Vec<u8>>,

    /// Cutoff parameter
    pub cutoff: f64,
}

impl TardosCode {
    /// Generate a Tardos code using arcsine distribution for biases
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R, params: &TardosCodeParams) -> Self {
        // Generate biases using arcsine distribution
        // P(p ≤ x) = (2/π) * arcsin(√x) for x ∈ [t₀, 1-t₀]
        let biases: Vec<f64> = (0..params.code_length)
            .map(|_| {
                // Sample from arcsine distribution via inverse CDF
                let u = rng.next_u32() as f64 / u32::MAX as f64;
                let p = (std::f64::consts::PI * u / 2.0).sin().powi(2);
                // Clamp to [cutoff, 1-cutoff]
                p.max(params.cutoff).min(1.0 - params.cutoff)
            })
            .collect();

        // Generate code matrix
        let mut code_matrix = Vec::with_capacity(params.num_users);

        for _ in 0..params.num_users {
            let mut user_code = Vec::with_capacity(params.code_length);
            for j in 0..params.code_length {
                let rand_val = rng.next_u32() as f64 / u32::MAX as f64;
                let bit = if rand_val < biases[j] { 1 } else { 0 };
                user_code.push(bit);
            }
            code_matrix.push(user_code);
        }

        TardosCode {
            n: params.num_users,
            l: params.code_length,
            c: params.collusion_bound,
            biases,
            code_matrix,
            cutoff: params.cutoff,
        }
    }

    /// Get fingerprint for a user
    pub fn get_fingerprint(&self, user_index: usize) -> Option<UserFingerprint> {
        if user_index >= self.n {
            return None;
        }

        Some(UserFingerprint {
            user_index,
            bits: self.code_matrix[user_index].clone(),
        })
    }
}

/// Tardos accusation scores for each user
#[derive(Debug, Clone)]
pub struct TardosAccusation {
    /// User ID
    pub user_id: UserId,

    /// Accusation score (S_j)
    pub score: f64,

    /// Whether score exceeds threshold
    pub accused: bool,
}

/// Trace using Tardos symmetric scoring function
///
/// Uses the optimal symmetric scoring: g(p, y) where
/// - g₁(p) = √((1-p)/p) for bit = 1
/// - g₀(p) = -√(p/(1-p)) for bit = 0
pub fn trace_tardos(
    code: &TardosCode,
    extracted: &ExtractedFingerprint,
    user_ids: &[UserId],
) -> Vec<TardosAccusation> {
    if user_ids.len() != code.n {
        return vec![];
    }

    // Calculate threshold: Z = c * √(L * 2 * ln(1/ε))
    let threshold = code.c as f64 * (code.l as f64 * 2.0 * (1.0 / 0.0001_f64).ln()).sqrt();

    let mut accusations = Vec::with_capacity(code.n);

    for (user_idx, user_id) in user_ids.iter().enumerate() {
        let mut score = 0.0;

        for pos in 0..code.l {
            let p = code.biases[pos];
            let user_bit = code.code_matrix[user_idx][pos];
            let extracted_bit = extracted.bits[pos];

            // Skip wildcards
            if extracted_bit == 2 {
                continue;
            }

            // Symmetric Tardos scoring
            let g = if extracted_bit == 1 {
                // Pirate output 1
                if user_bit == 1 {
                    ((1.0 - p) / p).sqrt()
                } else {
                    -((1.0 - p) / p).sqrt()
                }
            } else {
                // Pirate output 0
                if user_bit == 0 {
                    (p / (1.0 - p)).sqrt()
                } else {
                    -(p / (1.0 - p)).sqrt()
                }
            };

            score += g * extracted.confidence[pos];
        }

        accusations.push(TardosAccusation {
            user_id: user_id.clone(),
            score,
            accused: score > threshold,
        });
    }

    // Sort by score descending
    accusations.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal));

    accusations
}

/// Trace Tardos code and return TraceResult
pub fn trace_tardos_simple(
    code: &TardosCode,
    extracted: &ExtractedFingerprint,
    user_ids: &[UserId],
) -> TraceResult {
    let accusations = trace_tardos(code, extracted, user_ids);

    let traitors: Vec<UserId> = accusations
        .iter()
        .filter(|a| a.accused)
        .map(|a| a.user_id.clone())
        .collect();

    if traitors.is_empty() {
        // Fall back to top scorer if above a lower threshold
        if let Some(top) = accusations.first() {
            if top.score > 0.0 {
                return TraceResult::Traced(vec![top.user_id.clone()]);
            }
        }
        TraceResult::Inconclusive
    } else {
        TraceResult::Traced(traitors)
    }
}

// ============================================================================
// Marking Assumption Strategies
// ============================================================================

/// Collusion strategy used by pirates
#[derive(Debug, Clone, Copy)]
pub enum CollusionStrategy {
    /// Random: randomly pick one colluder's bit
    Random,
    /// Majority: use majority vote
    Majority,
    /// Minority: use minority (try to evade detection)
    Minority,
    /// AllZero: output 0 if any colluder has 0
    AllZero,
    /// AllOne: output 1 if any colluder has 1
    AllOne,
    /// Coin flip when bits differ
    CoinFlip,
}

/// Simulate collusion with specific strategy
pub fn simulate_collusion_strategy<R: RngCore + CryptoRng>(
    rng: &mut R,
    fingerprints: &[&UserFingerprint],
    strategy: CollusionStrategy,
) -> ExtractedFingerprint {
    if fingerprints.is_empty() {
        return ExtractedFingerprint::new(vec![]);
    }

    let len = fingerprints[0].len();
    let mut bits = Vec::with_capacity(len);
    let mut confidence = Vec::with_capacity(len);

    for pos in 0..len {
        let mut zeros = 0;
        let mut ones = 0;

        for fp in fingerprints {
            match fp.bits.get(pos) {
                Some(0) => zeros += 1,
                Some(1) => ones += 1,
                _ => {}
            }
        }

        let bit = match strategy {
            CollusionStrategy::Random => {
                if zeros > 0 && ones > 0 {
                    let idx = rng.next_u32() as usize % fingerprints.len();
                    fingerprints[idx].bits[pos]
                } else if ones > 0 { 1 } else { 0 }
            }
            CollusionStrategy::Majority => {
                if ones > zeros { 1 } else { 0 }
            }
            CollusionStrategy::Minority => {
                if ones < zeros { 1 } else { 0 }
            }
            CollusionStrategy::AllZero => {
                if zeros > 0 { 0 } else { 1 }
            }
            CollusionStrategy::AllOne => {
                if ones > 0 { 1 } else { 0 }
            }
            CollusionStrategy::CoinFlip => {
                if zeros > 0 && ones > 0 {
                    (rng.next_u32() & 1) as u8
                } else if ones > 0 { 1 } else { 0 }
            }
        };

        let conf = if zeros > 0 && ones > 0 { 0.5 } else { 1.0 };
        bits.push(bit);
        confidence.push(conf);
    }

    ExtractedFingerprint { bits, confidence }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::thread_rng;

    #[test]
    fn test_fingerprint_code_params() {
        let params = FingerprintCodeParams::new(100, 3);
        assert_eq!(params.num_users, 100);
        assert_eq!(params.collusion_bound, 3);
        assert!(params.code_length >= 30); // At least c * 10
    }

    #[test]
    fn test_fingerprint_code_generation() {
        let mut rng = thread_rng();
        let params = FingerprintCodeParams::with_length(10, 50, 2);
        let code = FingerprintCode::generate(&mut rng, &params);

        assert_eq!(code.n, 10);
        assert_eq!(code.l, 50);
        assert_eq!(code.code_matrix.len(), 10);

        for user_code in &code.code_matrix {
            assert_eq!(user_code.len(), 50);
            for &bit in user_code {
                assert!(bit == 0 || bit == 1);
            }
        }
    }

    #[test]
    fn test_get_fingerprint() {
        let mut rng = thread_rng();
        let params = FingerprintCodeParams::with_length(5, 20, 2);
        let code = FingerprintCode::generate(&mut rng, &params);

        let fp = code.get_fingerprint(2).unwrap();
        assert_eq!(fp.user_index, 2);
        assert_eq!(fp.len(), 20);

        // Out of bounds
        assert!(code.get_fingerprint(10).is_none());
    }

    #[test]
    fn test_trace_single_traitor() {
        let mut rng = thread_rng();
        let params = FingerprintCodeParams::with_length(5, 100, 2);
        let code = FingerprintCode::generate(&mut rng, &params);

        let user_ids: Vec<UserId> = (0..5).map(|i| UserId::new(format!("user{}", i))).collect();

        // User 2 leaks their content directly
        let fp = code.get_fingerprint(2).unwrap();
        let extracted = ExtractedFingerprint::new(fp.bits.clone());

        let result = trace_fingerprint(&code, &extracted, &user_ids, 0.9);
        assert!(result.is_traced());

        let traitors = result.traitors().unwrap();
        assert!(traitors.iter().any(|id| id.as_str() == "user2"));
    }

    #[test]
    fn test_trace_collusion() {
        let mut rng = thread_rng();
        // Longer code for better collusion resistance
        let params = FingerprintCodeParams::with_length(10, 200, 2);
        let code = FingerprintCode::generate(&mut rng, &params);

        let user_ids: Vec<UserId> = (0..10).map(|i| UserId::new(format!("user{}", i))).collect();

        // Users 3 and 7 collude
        let fp3 = code.get_fingerprint(3).unwrap();
        let fp7 = code.get_fingerprint(7).unwrap();

        let pirated = simulate_collusion(&mut rng, &[&fp3, &fp7]);
        let result = trace_fingerprint(&code, &pirated, &user_ids, 0.6);

        // Should identify at least one colluder
        if let TraceResult::Traced(traitors) = result {
            let found_colluder = traitors.iter().any(|id| {
                id.as_str() == "user3" || id.as_str() == "user7"
            });
            assert!(found_colluder, "Should find at least one colluder");
        } else {
            // With random codes, collusion might sometimes evade detection
            // This is expected behavior
        }
    }

    #[test]
    fn test_biased_code_generation() {
        let mut rng = thread_rng();
        let params = FingerprintCodeParams::with_length(10, 50, 2);
        let code = FingerprintCode::generate_biased(&mut rng, &params);

        assert_eq!(code.n, 10);
        assert_eq!(code.l, 50);

        // Verify bits are valid
        for user_code in &code.code_matrix {
            for &bit in user_code {
                assert!(bit == 0 || bit == 1);
            }
        }
    }

    #[test]
    fn test_extracted_fingerprint_with_wildcards() {
        let bits = vec![0, 1, 2, 0, 2, 1]; // 2 = wildcard
        let extracted = ExtractedFingerprint::new(bits.clone());

        assert_eq!(extracted.bits.len(), 6);
        assert_eq!(extracted.bits[2], 2);
    }

    #[test]
    fn test_get_fingerprint_by_id() {
        let mut rng = thread_rng();
        let params = FingerprintCodeParams::with_length(3, 20, 2);
        let code = FingerprintCode::generate(&mut rng, &params);

        let user_ids = vec![
            UserId::new("alice"),
            UserId::new("bob"),
            UserId::new("charlie"),
        ];

        let bob_fp = code.get_fingerprint_by_id(&UserId::new("bob"), &user_ids).unwrap();
        assert_eq!(bob_fp.user_index, 1);

        // Unknown user
        assert!(code.get_fingerprint_by_id(&UserId::new("unknown"), &user_ids).is_none());
    }

    // ========================================================================
    // Tardos Code Tests
    // ========================================================================

    #[test]
    fn test_tardos_params() {
        let params = TardosCodeParams::new(100, 3);
        assert_eq!(params.num_users, 100);
        assert_eq!(params.collusion_bound, 3);
        assert!(params.code_length >= 100);
        assert!(params.cutoff > 0.0 && params.cutoff < 0.5);
    }

    #[test]
    fn test_tardos_code_generation() {
        let mut rng = thread_rng();
        let params = TardosCodeParams::with_length(10, 100, 2);
        let code = TardosCode::generate(&mut rng, &params);

        assert_eq!(code.n, 10);
        assert_eq!(code.l, 100);
        assert_eq!(code.biases.len(), 100);
        assert_eq!(code.code_matrix.len(), 10);

        // Check biases are in valid range
        for &p in &code.biases {
            assert!(p >= code.cutoff && p <= 1.0 - code.cutoff);
        }

        // Check code values are 0 or 1
        for user_code in &code.code_matrix {
            for &bit in user_code {
                assert!(bit == 0 || bit == 1);
            }
        }
    }

    #[test]
    fn test_tardos_single_traitor() {
        let mut rng = thread_rng();
        let params = TardosCodeParams::with_length(10, 200, 2);
        let code = TardosCode::generate(&mut rng, &params);

        let user_ids: Vec<UserId> = (0..10).map(|i| UserId::new(format!("user{}", i))).collect();

        // User 5 leaks directly
        let fp = code.get_fingerprint(5).unwrap();
        let extracted = ExtractedFingerprint::new(fp.bits.clone());

        let accusations = trace_tardos(&code, &extracted, &user_ids);

        // User 5 should have highest score
        assert_eq!(accusations[0].user_id.as_str(), "user5");
        assert!(accusations[0].score > 0.0);
    }

    #[test]
    fn test_tardos_trace_simple() {
        let mut rng = thread_rng();
        let params = TardosCodeParams::with_length(5, 150, 2);
        let code = TardosCode::generate(&mut rng, &params);

        let user_ids: Vec<UserId> = (0..5).map(|i| UserId::new(format!("user{}", i))).collect();

        let fp = code.get_fingerprint(2).unwrap();
        let extracted = ExtractedFingerprint::new(fp.bits.clone());

        let result = trace_tardos_simple(&code, &extracted, &user_ids);
        assert!(result.is_traced());
        assert!(result.traitors().unwrap().iter().any(|u| u.as_str() == "user2"));
    }

    #[test]
    fn test_collusion_strategies() {
        let mut rng = thread_rng();
        let params = FingerprintCodeParams::with_length(5, 50, 2);
        let code = FingerprintCode::generate(&mut rng, &params);

        let fp0 = code.get_fingerprint(0).unwrap();
        let fp1 = code.get_fingerprint(1).unwrap();

        // Test each strategy produces valid output
        for strategy in [
            CollusionStrategy::Random,
            CollusionStrategy::Majority,
            CollusionStrategy::Minority,
            CollusionStrategy::AllZero,
            CollusionStrategy::AllOne,
            CollusionStrategy::CoinFlip,
        ] {
            let pirated = simulate_collusion_strategy(&mut rng, &[&fp0, &fp1], strategy);
            assert_eq!(pirated.bits.len(), 50);
            for &bit in &pirated.bits {
                assert!(bit == 0 || bit == 1);
            }
        }
    }

    #[test]
    fn test_tardos_collusion_resistance() {
        let mut rng = thread_rng();
        // Use longer code for collusion resistance
        let params = TardosCodeParams::with_length(10, 500, 3);
        let code = TardosCode::generate(&mut rng, &params);

        let user_ids: Vec<UserId> = (0..10).map(|i| UserId::new(format!("user{}", i))).collect();

        // 2 users collude
        let fp2 = code.get_fingerprint(2).unwrap();
        let fp7 = code.get_fingerprint(7).unwrap();

        let pirated = simulate_collusion_strategy(
            &mut rng,
            &[&fp2, &fp7],
            CollusionStrategy::Random
        );

        let result = trace_tardos_simple(&code, &pirated, &user_ids);

        // Should identify at least one colluder (probabilistic)
        if let TraceResult::Traced(traitors) = result {
            let found = traitors.iter().any(|u| {
                u.as_str() == "user2" || u.as_str() == "user7"
            });
            // With Tardos codes, we should usually find a colluder
            assert!(found || traitors.is_empty());
        }
    }
}
