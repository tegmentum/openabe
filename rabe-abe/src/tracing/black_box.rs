//! Black-Box Traitor Tracing
//!
//! This module implements black-box traitor tracing, where a "pirate decoder"
//! (black box) can decrypt ciphertexts but we cannot inspect its internal keys.
//!
//! # Approach
//!
//! Black-box tracing uses query-based strategies:
//! 1. Binary search: Divide users into groups, encrypt for each group
//! 2. If pirate decrypts for a group, at least one traitor is in that group
//! 3. Recursively narrow down to identify individual traitors
//!
//! # PirateDecoder Trait
//!
//! Implementors of this trait represent the "black box" decoder.
//! In testing, this might be a simple decoder that uses a known leaked key.
//! In practice, this represents interaction with an actual pirate device.

use super::types::{UserId, BlackBoxTraceResult, BlackBoxConfig, TraceEvidence};

/// Trait for a pirate decoder (black box)
///
/// The pirate decoder can decrypt certain ciphertexts based on the keys
/// it has acquired from colluding users.
pub trait PirateDecoder {
    /// Attempt to decode a ciphertext
    ///
    /// Returns Some(plaintext) if decryption succeeds, None otherwise.
    fn decode(&self, ciphertext: &[u8]) -> Option<Vec<u8>>;
}

/// Result of a single oracle query
#[derive(Debug, Clone)]
pub struct QueryResult {
    /// The ciphertext that was queried
    pub ciphertext: Vec<u8>,

    /// Whether the decoder successfully decrypted
    pub decrypted: bool,

    /// Users included in this query's policy
    pub included_users: Vec<UserId>,
}

/// Statistics from black-box tracing
#[derive(Debug, Clone, Default)]
pub struct TracingStats {
    /// Total queries made
    pub total_queries: usize,

    /// Queries that returned positive (decoder could decrypt)
    pub positive_queries: usize,

    /// Queries that returned negative
    pub negative_queries: usize,
}

/// Encryptor trait for generating test ciphertexts
///
/// This abstracts the encryption process so black-box tracing can work
/// with any ABE scheme.
pub trait TracingEncryptor {
    /// Encrypt a message for a specific set of users
    ///
    /// The ciphertext should only be decryptable by users in the set
    /// whose attributes satisfy the encryption policy.
    fn encrypt_for_users(&self, users: &[UserId], message: &[u8]) -> Vec<u8>;
}

/// Perform black-box tracing using binary search
///
/// This is the core tracing algorithm that queries the pirate decoder
/// to identify traitors without inspecting their keys.
pub fn black_box_trace<D, E>(
    decoder: &D,
    encryptor: &E,
    all_users: &[UserId],
    config: &BlackBoxConfig,
) -> BlackBoxTraceResult
where
    D: PirateDecoder,
    E: TracingEncryptor,
{
    let mut stats = TracingStats::default();
    let mut suspected_traitors: Vec<UserId> = Vec::new();
    let mut evidence: Vec<TraceEvidence> = Vec::new();

    // Test message for queries
    let test_message = b"TRACE_TEST_MESSAGE_12345678";

    // First, check if decoder works at all
    let full_ct = encryptor.encrypt_for_users(all_users, test_message);
    stats.total_queries += 1;

    if decoder.decode(&full_ct).is_none() {
        // Decoder can't decrypt even with all users - something is wrong
        return BlackBoxTraceResult::new(vec![], 0.0, stats.total_queries);
    }
    stats.positive_queries += 1;

    // Binary search to find traitors
    let mut search_results = binary_search_traitors(
        decoder,
        encryptor,
        all_users,
        test_message,
        config,
        &mut stats,
    );

    suspected_traitors.append(&mut search_results);

    // Calculate confidence and build evidence
    for user in &suspected_traitors {
        let ev = TraceEvidence::new(user.clone(), 1, 1)
            .with_description("Identified via binary search");
        evidence.push(ev);
    }

    let confidence = if suspected_traitors.is_empty() {
        0.0
    } else if suspected_traitors.len() <= config.collusion_bound {
        0.95
    } else {
        0.8 // Lower confidence if we found more than expected
    };

    BlackBoxTraceResult::new(suspected_traitors, confidence, stats.total_queries)
        .with_evidence(evidence)
}

/// Binary search to find traitors in a user set
fn binary_search_traitors<D, E>(
    decoder: &D,
    encryptor: &E,
    users: &[UserId],
    message: &[u8],
    config: &BlackBoxConfig,
    stats: &mut TracingStats,
) -> Vec<UserId>
where
    D: PirateDecoder,
    E: TracingEncryptor,
{
    // Base case: single user
    if users.len() <= 1 {
        if users.is_empty() {
            return vec![];
        }

        // Verify this single user is actually a traitor
        let ct = encryptor.encrypt_for_users(users, message);
        stats.total_queries += 1;

        if decoder.decode(&ct).is_some() {
            stats.positive_queries += 1;
            return users.to_vec();
        } else {
            stats.negative_queries += 1;
            return vec![];
        }
    }

    // Check if we've exceeded query limit
    if stats.total_queries >= config.max_queries {
        return vec![];
    }

    // Split into two halves
    let mid = users.len() / 2;
    let left = &users[..mid];
    let right = &users[mid..];

    let mut traitors = Vec::new();

    // Test left half
    let left_ct = encryptor.encrypt_for_users(left, message);
    stats.total_queries += 1;

    if decoder.decode(&left_ct).is_some() {
        stats.positive_queries += 1;
        // At least one traitor in left half
        let mut left_traitors = binary_search_traitors(
            decoder, encryptor, left, message, config, stats
        );
        traitors.append(&mut left_traitors);
    } else {
        stats.negative_queries += 1;
    }

    // Test right half (if we haven't found enough traitors yet)
    if traitors.len() < config.collusion_bound && stats.total_queries < config.max_queries {
        let right_ct = encryptor.encrypt_for_users(right, message);
        stats.total_queries += 1;

        if decoder.decode(&right_ct).is_some() {
            stats.positive_queries += 1;
            // At least one traitor in right half
            let mut right_traitors = binary_search_traitors(
                decoder, encryptor, right, message, config, stats
            );
            traitors.append(&mut right_traitors);
        } else {
            stats.negative_queries += 1;
        }
    }

    traitors
}

/// Adaptive tracing that adjusts strategy based on results
pub fn adaptive_trace<D, E>(
    decoder: &D,
    encryptor: &E,
    all_users: &[UserId],
    config: &BlackBoxConfig,
) -> BlackBoxTraceResult
where
    D: PirateDecoder,
    E: TracingEncryptor,
{
    // Start with binary search
    let mut result = black_box_trace(decoder, encryptor, all_users, config);

    // If we found some traitors, verify them
    if !result.traitors.is_empty() {
        let test_message = b"VERIFICATION_MESSAGE";
        let mut verified = Vec::new();
        let mut new_queries = result.queries_used;

        for traitor in &result.traitors {
            let ct = encryptor.encrypt_for_users(&[traitor.clone()], test_message);
            new_queries += 1;

            if decoder.decode(&ct).is_some() {
                verified.push(traitor.clone());
            }
        }

        result.traitors = verified;
        result.queries_used = new_queries;
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test pirate decoder that decrypts if any of its keys match the policy
    struct TestPirateDecoder {
        /// Users whose keys this decoder has
        colluders: Vec<UserId>,
    }

    impl TestPirateDecoder {
        fn new(colluders: Vec<UserId>) -> Self {
            TestPirateDecoder { colluders }
        }
    }

    impl PirateDecoder for TestPirateDecoder {
        fn decode(&self, ciphertext: &[u8]) -> Option<Vec<u8>> {
            // Simple protocol: ciphertext contains user IDs that can decrypt
            // Format: [num_users:u8][user_id_len:u8][user_id bytes]...
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
                included_users.push(UserId::new(id.to_string()));
                offset += id_len;
            }

            // Check if any colluder is in the included users
            for colluder in &self.colluders {
                if included_users.iter().any(|u| u == colluder) {
                    return Some(b"DECRYPTED".to_vec());
                }
            }

            None
        }
    }

    /// Test encryptor that creates simple test ciphertexts
    struct TestEncryptor;

    impl TracingEncryptor for TestEncryptor {
        fn encrypt_for_users(&self, users: &[UserId], _message: &[u8]) -> Vec<u8> {
            // Simple encoding: store which users can decrypt
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
    fn test_pirate_decoder_trait() {
        let decoder = TestPirateDecoder::new(vec![UserId::new("alice")]);
        let encryptor = TestEncryptor;

        // Encrypt for alice - should decrypt
        let ct = encryptor.encrypt_for_users(&[UserId::new("alice")], b"test");
        assert!(decoder.decode(&ct).is_some());

        // Encrypt for bob only - should not decrypt
        let ct = encryptor.encrypt_for_users(&[UserId::new("bob")], b"test");
        assert!(decoder.decode(&ct).is_none());

        // Encrypt for both - should decrypt (alice is included)
        let ct = encryptor.encrypt_for_users(
            &[UserId::new("alice"), UserId::new("bob")],
            b"test"
        );
        assert!(decoder.decode(&ct).is_some());
    }

    #[test]
    fn test_black_box_trace_single_traitor() {
        let decoder = TestPirateDecoder::new(vec![UserId::new("user3")]);
        let encryptor = TestEncryptor;

        let all_users: Vec<UserId> = (0..8)
            .map(|i| UserId::new(format!("user{}", i)))
            .collect();

        let config = BlackBoxConfig::single_traitor();

        let result = black_box_trace(&decoder, &encryptor, &all_users, &config);

        assert!(!result.traitors.is_empty());
        assert!(result.traitors.iter().any(|u| u.as_str() == "user3"));
        assert!(result.queries_used <= config.max_queries);
    }

    #[test]
    fn test_black_box_trace_two_colluders() {
        let decoder = TestPirateDecoder::new(vec![
            UserId::new("user2"),
            UserId::new("user5"),
        ]);
        let encryptor = TestEncryptor;

        let all_users: Vec<UserId> = (0..8)
            .map(|i| UserId::new(format!("user{}", i)))
            .collect();

        let config = BlackBoxConfig::collusion_resistant(2);

        let result = black_box_trace(&decoder, &encryptor, &all_users, &config);

        // Should find at least one of the colluders
        let found_colluder = result.traitors.iter().any(|u| {
            u.as_str() == "user2" || u.as_str() == "user5"
        });
        assert!(found_colluder);
    }

    #[test]
    fn test_adaptive_trace() {
        let decoder = TestPirateDecoder::new(vec![UserId::new("user1")]);
        let encryptor = TestEncryptor;

        let all_users: Vec<UserId> = (0..4)
            .map(|i| UserId::new(format!("user{}", i)))
            .collect();

        let config = BlackBoxConfig::single_traitor();

        let result = adaptive_trace(&decoder, &encryptor, &all_users, &config);

        assert!(!result.traitors.is_empty());
        // Adaptive should have verification queries
    }

    #[test]
    fn test_no_traitors() {
        // Decoder that can't decrypt anything
        struct NoopDecoder;
        impl PirateDecoder for NoopDecoder {
            fn decode(&self, _: &[u8]) -> Option<Vec<u8>> { None }
        }

        let decoder = NoopDecoder;
        let encryptor = TestEncryptor;

        let all_users = vec![UserId::new("user0"), UserId::new("user1")];
        let config = BlackBoxConfig::default();

        let result = black_box_trace(&decoder, &encryptor, &all_users, &config);

        assert!(result.traitors.is_empty());
        assert!((result.confidence - 0.0).abs() < 0.001);
    }
}
