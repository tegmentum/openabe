//! Dynamic Traitor Tracing
//!
//! This module implements dynamic traitor tracing algorithms that adapt to
//! pirate decoder behavior in real-time. Unlike static tracing approaches,
//! dynamic tracing:
//!
//! 1. Observes decoder responses to craft better test queries
//! 2. Handles evolving decoders that change behavior
//! 3. Uses probabilistic methods to handle collusion attacks
//!
//! # Approaches
//!
//! - Sequential elimination: Narrow down suspects based on query responses
//! - Adaptive watermarking: Change fingerprint distribution based on leaks
//! - Game-theoretic tracing: Model traitor as adversarial player
//!
//! # References
//!
//! - Fiat, Tassa. "Dynamic Traitor Tracing" (1999)
//! - Kiayias, Yung. "Self-Protecting Pirates and Black-Box Traitor Tracing" (2001)

use crate::tracing::{UserId, TraceResult, PirateDecoder, TracingEncryptor};
use rand::RngCore;
use std::collections::{HashMap, HashSet};

/// State of a suspect during tracing
#[derive(Clone, Debug, PartialEq)]
pub enum SuspectState {
    /// Still under investigation
    Active,
    /// Cleared - probably not a traitor
    Cleared,
    /// Confirmed traitor
    Confirmed,
    /// Unknown - insufficient evidence
    Unknown,
}

/// Evidence about a suspect
#[derive(Clone, Debug)]
pub struct SuspectEvidence {
    /// User ID
    pub user_id: UserId,

    /// Current state
    pub state: SuspectState,

    /// Number of positive responses when included
    pub positive_hits: usize,

    /// Number of negative responses when included
    pub negative_misses: usize,

    /// Suspicion score (higher = more likely traitor)
    pub suspicion_score: f64,

    /// History of query responses
    pub response_history: Vec<bool>,
}

impl SuspectEvidence {
    /// Create new evidence for a suspect
    pub fn new(user_id: UserId) -> Self {
        SuspectEvidence {
            user_id,
            state: SuspectState::Active,
            positive_hits: 0,
            negative_misses: 0,
            suspicion_score: 0.0,
            response_history: Vec::new(),
        }
    }

    /// Update evidence based on a query response
    pub fn update(&mut self, included_in_query: bool, decoder_responded: bool) {
        if included_in_query {
            if decoder_responded {
                self.positive_hits += 1;
            } else {
                self.negative_misses += 1;
            }
        }

        self.response_history.push(decoder_responded);
        self.update_score();
    }

    /// Update suspicion score based on evidence
    fn update_score(&mut self) {
        let total = self.positive_hits + self.negative_misses;
        if total == 0 {
            self.suspicion_score = 0.5;
        } else {
            // Higher score if decoder responds when user is included
            self.suspicion_score = self.positive_hits as f64 / total as f64;
        }

        // Update state based on thresholds
        if self.suspicion_score > 0.9 && self.positive_hits >= 3 {
            self.state = SuspectState::Confirmed;
        } else if self.suspicion_score < 0.1 && self.negative_misses >= 3 {
            self.state = SuspectState::Cleared;
        }
    }
}

/// Dynamic tracing state
#[derive(Clone, Debug)]
pub struct DynamicTracingState {
    /// Evidence for each suspect
    pub suspects: HashMap<String, SuspectEvidence>,

    /// Total queries made
    pub total_queries: usize,

    /// Query budget remaining
    pub budget_remaining: usize,

    /// Current phase of tracing
    pub phase: TracingPhase,
}

/// Phases of dynamic tracing
#[derive(Clone, Debug, PartialEq)]
pub enum TracingPhase {
    /// Initial exploration - test all users
    Exploration,
    /// Focused testing - narrow down suspects
    Focused,
    /// Verification - confirm suspects
    Verification,
    /// Complete
    Complete,
}

impl DynamicTracingState {
    /// Create new tracing state
    pub fn new(users: &[UserId], budget: usize) -> Self {
        let suspects = users
            .iter()
            .map(|u| (u.as_str().to_string(), SuspectEvidence::new(u.clone())))
            .collect();

        DynamicTracingState {
            suspects,
            total_queries: 0,
            budget_remaining: budget,
            phase: TracingPhase::Exploration,
        }
    }

    /// Get active suspects
    pub fn active_suspects(&self) -> Vec<&SuspectEvidence> {
        self.suspects
            .values()
            .filter(|s| s.state == SuspectState::Active)
            .collect()
    }

    /// Get confirmed traitors
    pub fn confirmed_traitors(&self) -> Vec<UserId> {
        self.suspects
            .values()
            .filter(|s| s.state == SuspectState::Confirmed)
            .collect::<Vec<_>>()
            .iter()
            .map(|s| s.user_id.clone())
            .collect()
    }

    /// Get suspects sorted by suspicion score
    pub fn ranked_suspects(&self) -> Vec<&SuspectEvidence> {
        let mut suspects: Vec<_> = self.active_suspects();
        suspects.sort_by(|a, b| {
            b.suspicion_score
                .partial_cmp(&a.suspicion_score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        suspects
    }
}

/// Configuration for dynamic tracing
#[derive(Clone, Debug)]
pub struct DynamicConfig {
    /// Maximum number of queries
    pub max_queries: usize,

    /// Confirmation threshold (suspicion score to confirm)
    pub confirm_threshold: f64,

    /// Clearing threshold (suspicion score to clear)
    pub clear_threshold: f64,

    /// Minimum positive hits to confirm
    pub min_positive_hits: usize,

    /// Expected number of colluders
    pub expected_colluders: usize,
}

impl Default for DynamicConfig {
    fn default() -> Self {
        DynamicConfig {
            max_queries: 1000,
            confirm_threshold: 0.9,
            clear_threshold: 0.1,
            min_positive_hits: 5,
            expected_colluders: 1,
        }
    }
}

impl DynamicConfig {
    /// Create config for single traitor
    pub fn single_traitor() -> Self {
        Self::default()
    }

    /// Create config for collusion resistance
    pub fn collusion_resistant(num_colluders: usize) -> Self {
        DynamicConfig {
            max_queries: 1000 * num_colluders,
            confirm_threshold: 0.85,
            clear_threshold: 0.15,
            min_positive_hits: 3 * num_colluders,
            expected_colluders: num_colluders,
        }
    }
}

/// Result of dynamic tracing
#[derive(Clone, Debug)]
pub struct DynamicTraceResult {
    /// Identified traitors
    pub traitors: Vec<UserId>,

    /// Evidence for each user
    pub evidence: HashMap<String, SuspectEvidence>,

    /// Total queries used
    pub queries_used: usize,

    /// Confidence level
    pub confidence: f64,

    /// Final tracing phase
    pub final_phase: TracingPhase,
}

/// Perform dynamic traitor tracing
pub fn dynamic_trace<D, E, R>(
    rng: &mut R,
    decoder: &D,
    encryptor: &E,
    users: &[UserId],
    config: &DynamicConfig,
) -> DynamicTraceResult
where
    D: PirateDecoder,
    E: TracingEncryptor,
    R: RngCore,
{
    let mut state = DynamicTracingState::new(users, config.max_queries);

    // Phase 1: Exploration - test all users to get baseline
    exploration_phase(&mut state, decoder, encryptor, users);

    // Phase 2: Focused testing - narrow down suspects
    focused_phase(&mut state, decoder, encryptor, rng, config);

    // Phase 3: Verification - confirm top suspects
    verification_phase(&mut state, decoder, encryptor, config);

    // Build result
    let traitors = state.confirmed_traitors();
    let confidence = if traitors.is_empty() {
        0.0
    } else {
        traitors
            .iter()
            .filter_map(|t| state.suspects.get(t.as_str()))
            .map(|s| s.suspicion_score)
            .sum::<f64>()
            / traitors.len() as f64
    };

    DynamicTraceResult {
        traitors,
        evidence: state.suspects,
        queries_used: state.total_queries,
        confidence,
        final_phase: state.phase,
    }
}

/// Phase 1: Explore all users
fn exploration_phase<D, E>(
    state: &mut DynamicTracingState,
    decoder: &D,
    encryptor: &E,
    users: &[UserId],
) where
    D: PirateDecoder,
    E: TracingEncryptor,
{
    let test_message = b"EXPLORE_TEST_MESSAGE";

    // Test each user individually first
    for user in users {
        if state.budget_remaining == 0 {
            break;
        }

        let ct = encryptor.encrypt_for_users(&[user.clone()], test_message);
        state.total_queries += 1;
        state.budget_remaining -= 1;

        let responded = decoder.decode(&ct).is_some();

        if let Some(evidence) = state.suspects.get_mut(user.as_str()) {
            evidence.update(true, responded);
        }
    }

    // Test all users together
    if state.budget_remaining > 0 {
        let ct = encryptor.encrypt_for_users(users, test_message);
        state.total_queries += 1;
        state.budget_remaining -= 1;

        let responded = decoder.decode(&ct).is_some();

        for (_, evidence) in state.suspects.iter_mut() {
            evidence.update(true, responded);
        }
    }

    state.phase = TracingPhase::Focused;
}

/// Phase 2: Focused testing using adaptive strategy
fn focused_phase<D, E, R>(
    state: &mut DynamicTracingState,
    decoder: &D,
    encryptor: &E,
    rng: &mut R,
    config: &DynamicConfig,
) where
    D: PirateDecoder,
    E: TracingEncryptor,
    R: RngCore,
{
    let test_message = b"FOCUSED_TEST_MESSAGE";
    let max_focused_queries = state.budget_remaining.min(config.max_queries / 2);

    for _ in 0..max_focused_queries {
        if state.budget_remaining == 0 {
            break;
        }

        // Get active suspects sorted by score
        let ranked = state.ranked_suspects();
        if ranked.is_empty() {
            break;
        }

        // Adaptive query: include top suspects and random sample
        let mut query_set: Vec<UserId> = Vec::new();

        // Include top suspects
        let top_count = ranked.len().min(3);
        for suspect in ranked.iter().take(top_count) {
            query_set.push(suspect.user_id.clone());
        }

        // Add some random users (for calibration)
        let cleared: Vec<_> = state
            .suspects
            .values()
            .filter(|s| s.state == SuspectState::Cleared)
            .map(|s| s.user_id.clone())
            .collect();

        if !cleared.is_empty() && rng.next_u32() % 3 == 0 {
            let idx = rng.next_u32() as usize % cleared.len();
            query_set.push(cleared[idx].clone());
        }

        // Execute query
        let ct = encryptor.encrypt_for_users(&query_set, test_message);
        state.total_queries += 1;
        state.budget_remaining -= 1;

        let responded = decoder.decode(&ct).is_some();

        // Update evidence
        let query_set_ids: HashSet<_> = query_set.iter().map(|u| u.as_str().to_string()).collect();
        for (user_id, evidence) in state.suspects.iter_mut() {
            let included = query_set_ids.contains(user_id);
            evidence.update(included, responded);
        }

        // Check if we should transition to verification
        let confirmed_count = state.confirmed_traitors().len();
        if confirmed_count >= config.expected_colluders {
            break;
        }
    }

    state.phase = TracingPhase::Verification;
}

/// Phase 3: Verification of top suspects
fn verification_phase<D, E>(
    state: &mut DynamicTracingState,
    decoder: &D,
    encryptor: &E,
    config: &DynamicConfig,
) where
    D: PirateDecoder,
    E: TracingEncryptor,
{
    let test_message = b"VERIFY_TEST_MESSAGE";

    // Get top suspects that aren't yet confirmed
    let top_suspects: Vec<UserId> = state
        .ranked_suspects()
        .iter()
        .filter(|s| s.state == SuspectState::Active && s.suspicion_score > 0.5)
        .take(config.expected_colluders * 2)
        .map(|s| s.user_id.clone())
        .collect();

    // Verify each suspect individually
    for suspect in top_suspects {
        if state.budget_remaining < 3 {
            break;
        }

        // Multiple tests for confirmation
        for _ in 0..3 {
            let ct = encryptor.encrypt_for_users(&[suspect.clone()], test_message);
            state.total_queries += 1;
            state.budget_remaining -= 1;

            let responded = decoder.decode(&ct).is_some();

            if let Some(evidence) = state.suspects.get_mut(suspect.as_str()) {
                evidence.update(true, responded);
            }
        }
    }

    state.phase = TracingPhase::Complete;
}

/// Sequential elimination tracing (simpler approach)
pub fn sequential_elimination<D, E>(
    decoder: &D,
    encryptor: &E,
    users: &[UserId],
    max_queries: usize,
) -> TraceResult
where
    D: PirateDecoder,
    E: TracingEncryptor,
{
    let test_message = b"SEQUENTIAL_TEST";
    let mut remaining: Vec<UserId> = users.to_vec();
    let mut queries_used = 0;

    // First verify decoder works
    let ct = encryptor.encrypt_for_users(&remaining, test_message);
    queries_used += 1;

    if decoder.decode(&ct).is_none() {
        return TraceResult::Inconclusive;
    }

    // Eliminate users one by one
    let mut i = 0;
    while remaining.len() > 1 && queries_used < max_queries {
        if i >= remaining.len() {
            break;
        }

        // Test without user i
        let test_set: Vec<UserId> = remaining
            .iter()
            .enumerate()
            .filter(|(j, _)| *j != i)
            .map(|(_, u)| u.clone())
            .collect();

        let ct = encryptor.encrypt_for_users(&test_set, test_message);
        queries_used += 1;

        if decoder.decode(&ct).is_some() {
            // Can still decrypt without user i - eliminate them
            remaining.remove(i);
            // Don't increment i since we removed an element
        } else {
            // User i is needed - likely a traitor
            i += 1;
        }
    }

    if remaining.is_empty() {
        TraceResult::Inconclusive
    } else if remaining.len() == 1 {
        TraceResult::Traced(remaining)
    } else {
        // Multiple remaining - all might be traitors
        TraceResult::Traced(remaining)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tracing::black_box::TracingEncryptor;

    /// Test decoder that responds if any of its users are included
    struct TestDecoder {
        traitors: HashSet<String>,
    }

    impl TestDecoder {
        fn new(traitors: &[&str]) -> Self {
            TestDecoder {
                traitors: traitors.iter().map(|s| s.to_string()).collect(),
            }
        }
    }

    impl PirateDecoder for TestDecoder {
        fn decode(&self, ciphertext: &[u8]) -> Option<Vec<u8>> {
            // Parse included users from simple encoding
            if ciphertext.is_empty() {
                return None;
            }

            let num_users = ciphertext[0] as usize;
            let mut offset = 1;
            let mut included_users = Vec::new();

            for _ in 0..num_users {
                if offset >= ciphertext.len() {
                    return None;
                }
                let id_len = ciphertext[offset] as usize;
                offset += 1;

                if offset + id_len > ciphertext.len() {
                    return None;
                }
                let id = String::from_utf8_lossy(&ciphertext[offset..offset + id_len]);
                included_users.push(id.to_string());
                offset += id_len;
            }

            // Check if any traitor is included
            for user in &included_users {
                if self.traitors.contains(user) {
                    return Some(b"DECRYPTED".to_vec());
                }
            }

            None
        }
    }

    /// Test encryptor
    struct TestEncryptor;

    impl TracingEncryptor for TestEncryptor {
        fn encrypt_for_users(&self, users: &[UserId], _message: &[u8]) -> Vec<u8> {
            let mut ct = vec![users.len() as u8];
            for user in users {
                let id_bytes = user.as_str().as_bytes();
                ct.push(id_bytes.len() as u8);
                ct.extend_from_slice(id_bytes);
            }
            ct
        }
    }

    #[test]
    fn test_suspect_evidence() {
        let mut evidence = SuspectEvidence::new(UserId::new("alice"));

        // Simulate positive hits
        evidence.update(true, true);
        evidence.update(true, true);
        evidence.update(true, true);

        assert!(evidence.suspicion_score > 0.9);
        assert_eq!(evidence.state, SuspectState::Confirmed);
    }

    #[test]
    fn test_suspect_cleared() {
        let mut evidence = SuspectEvidence::new(UserId::new("bob"));

        // Simulate negative responses when included
        evidence.update(true, false);
        evidence.update(true, false);
        evidence.update(true, false);

        assert!(evidence.suspicion_score < 0.1);
        assert_eq!(evidence.state, SuspectState::Cleared);
    }

    #[test]
    fn test_dynamic_trace_single_traitor() {
        let mut rng = rand::thread_rng();
        let decoder = TestDecoder::new(&["user3"]);
        let encryptor = TestEncryptor;

        let users: Vec<UserId> = (0..8)
            .map(|i| UserId::new(format!("user{}", i)))
            .collect();

        let config = DynamicConfig::single_traitor();
        let result = dynamic_trace(&mut rng, &decoder, &encryptor, &users, &config);

        assert!(!result.traitors.is_empty());
        assert!(result.traitors.iter().any(|u| u.as_str() == "user3"));
    }

    #[test]
    fn test_dynamic_trace_two_colluders() {
        let mut rng = rand::thread_rng();
        let decoder = TestDecoder::new(&["user2", "user5"]);
        let encryptor = TestEncryptor;

        let users: Vec<UserId> = (0..8)
            .map(|i| UserId::new(format!("user{}", i)))
            .collect();

        let config = DynamicConfig::collusion_resistant(2);
        let result = dynamic_trace(&mut rng, &decoder, &encryptor, &users, &config);

        // Should find at least one traitor
        let found_colluder = result.traitors.iter().any(|u| {
            u.as_str() == "user2" || u.as_str() == "user5"
        });
        assert!(found_colluder);
    }

    #[test]
    fn test_sequential_elimination() {
        let decoder = TestDecoder::new(&["user1"]);
        let encryptor = TestEncryptor;

        let users: Vec<UserId> = (0..4)
            .map(|i| UserId::new(format!("user{}", i)))
            .collect();

        let result = sequential_elimination(&decoder, &encryptor, &users, 100);

        match result {
            TraceResult::Traced(traitors) => {
                assert!(traitors.iter().any(|u| u.as_str() == "user1"));
            }
            _ => panic!("Expected Traced result"),
        }
    }

    #[test]
    fn test_tracing_phases() {
        let users: Vec<UserId> = (0..4)
            .map(|i| UserId::new(format!("user{}", i)))
            .collect();

        let state = DynamicTracingState::new(&users, 100);

        assert_eq!(state.phase, TracingPhase::Exploration);
        assert_eq!(state.active_suspects().len(), 4);
        assert!(state.confirmed_traitors().is_empty());
    }

    #[test]
    fn test_no_traitors() {
        struct NeverDecodes;
        impl PirateDecoder for NeverDecodes {
            fn decode(&self, _: &[u8]) -> Option<Vec<u8>> {
                None
            }
        }

        let decoder = NeverDecodes;
        let encryptor = TestEncryptor;

        let users: Vec<UserId> = (0..4)
            .map(|i| UserId::new(format!("user{}", i)))
            .collect();

        let result = sequential_elimination(&decoder, &encryptor, &users, 100);

        match result {
            TraceResult::Inconclusive => {}
            _ => panic!("Expected Inconclusive for no-decode scenario"),
        }
    }
}
