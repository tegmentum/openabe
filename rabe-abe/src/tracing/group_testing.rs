//! Group Testing for Traitor Tracing
//!
//! This module implements group testing approaches for identifying traitors
//! in a population. Group testing pools multiple users in each test and
//! uses combinatorial techniques to identify defectives efficiently.
//!
//! # Approaches
//!
//! 1. **Non-Adaptive**: All tests predefined using combinatorial designs
//!    - Disjunct matrices
//!    - Cover-free families
//!    - Concatenated codes
//!
//! 2. **Adaptive**: Tests designed based on previous results
//!    - Binary splitting
//!    - Generalized binary splitting
//!    - Hwang's generalized algorithm
//!
//! 3. **Probabilistic**: Random test matrices with guaranteed success probability
//!
//! # Complexity
//!
//! For n users and at most d traitors:
//! - Non-adaptive: O(d² log n) tests
//! - Adaptive: O(d log(n/d)) tests
//!
//! # References
//!
//! - Du, Hwang. "Combinatorial Group Testing and Its Applications" (2000)
//! - Stinson. "Combinatorial Designs and Applications" (1992)

use crate::tracing::UserId;
use rand::{RngCore, CryptoRng};
use std::collections::HashSet;

/// Result of a group test
#[derive(Clone, Debug, PartialEq)]
pub enum TestResult {
    /// At least one positive (traitor) in the group
    Positive,
    /// No positives in the group
    Negative,
}

/// Trait for a group testing oracle
pub trait GroupTestOracle {
    /// Test a group of users. Returns Positive if any are traitors.
    fn test(&self, users: &[UserId]) -> TestResult;
}

/// Test matrix for non-adaptive group testing
#[derive(Clone, Debug)]
pub struct TestMatrix {
    /// Number of users (columns)
    pub num_users: usize,

    /// Number of tests (rows)
    pub num_tests: usize,

    /// Matrix: tests[t][u] = true if user u is in test t
    pub tests: Vec<Vec<bool>>,
}

impl TestMatrix {
    /// Create an empty test matrix
    pub fn new(num_users: usize, num_tests: usize) -> Self {
        TestMatrix {
            num_users,
            num_tests,
            tests: vec![vec![false; num_users]; num_tests],
        }
    }

    /// Create a random test matrix (probabilistic method)
    pub fn random<R: RngCore + CryptoRng>(rng: &mut R, num_users: usize, max_defectives: usize) -> Self {
        // Optimal probability for each user in each test
        let p = 1.0 / (max_defectives as f64 + 1.0);

        // Number of tests needed (with safety margin)
        let num_tests = ((max_defectives * max_defectives) as f64 * (num_users as f64).ln() * 2.0)
            .ceil() as usize;
        let num_tests = num_tests.max(max_defectives * 4);

        let mut tests = vec![vec![false; num_users]; num_tests];

        for t in 0..num_tests {
            for u in 0..num_users {
                // Include user with probability p
                let rand_val = (rng.next_u32() as f64) / (u32::MAX as f64);
                tests[t][u] = rand_val < p;
            }
        }

        TestMatrix {
            num_users,
            num_tests,
            tests,
        }
    }

    /// Create a d-disjunct matrix using concatenated codes
    pub fn disjunct(num_users: usize, max_defectives: usize) -> Self {
        // Simplified construction using binary representation
        let d = max_defectives;

        // Number of bits needed to represent users
        let bits_per_user = (num_users as f64).log2().ceil() as usize;

        // We need d * log(n) tests for d-disjunctness
        let num_tests = (d + 1) * bits_per_user;

        let mut tests = vec![vec![false; num_users]; num_tests];

        for u in 0..num_users {
            // Include user in tests based on binary representation
            for level in 0..=d {
                let shifted = u >> level;
                for bit in 0..bits_per_user {
                    if bit < num_tests / (d + 1) {
                        let test_idx = level * bits_per_user + bit;
                        if test_idx < num_tests {
                            tests[test_idx][u] = ((shifted >> bit) & 1) == 1;
                        }
                    }
                }
            }
        }

        TestMatrix {
            num_users,
            num_tests,
            tests,
        }
    }

    /// Get users included in a specific test
    pub fn users_in_test(&self, test_idx: usize) -> Vec<usize> {
        self.tests[test_idx]
            .iter()
            .enumerate()
            .filter(|(_, &included)| included)
            .map(|(idx, _)| idx)
            .collect()
    }

    /// Get tests that include a specific user
    pub fn tests_for_user(&self, user_idx: usize) -> Vec<usize> {
        self.tests
            .iter()
            .enumerate()
            .filter(|(_, test)| test[user_idx])
            .map(|(idx, _)| idx)
            .collect()
    }
}

/// Parameters for group testing
#[derive(Clone, Debug)]
pub struct GroupTestParams {
    /// Maximum number of defectives (traitors)
    pub max_defectives: usize,

    /// Use adaptive testing
    pub adaptive: bool,

    /// Random seed for probabilistic methods
    pub seed: Option<u64>,
}

impl Default for GroupTestParams {
    fn default() -> Self {
        GroupTestParams {
            max_defectives: 1,
            adaptive: true,
            seed: None,
        }
    }
}

impl GroupTestParams {
    /// Create parameters for single defective
    pub fn single() -> Self {
        Self::default()
    }

    /// Create parameters for multiple defectives
    pub fn multiple(max_defectives: usize) -> Self {
        GroupTestParams {
            max_defectives,
            adaptive: true,
            seed: None,
        }
    }

    /// Create parameters for non-adaptive testing
    pub fn non_adaptive(max_defectives: usize) -> Self {
        GroupTestParams {
            max_defectives,
            adaptive: false,
            seed: None,
        }
    }
}

/// Result of group testing
#[derive(Clone, Debug)]
pub struct GroupTestResult {
    /// Identified defectives
    pub defectives: Vec<UserId>,

    /// Number of tests used
    pub tests_used: usize,

    /// Test results (for non-adaptive)
    pub test_results: Vec<TestResult>,
}

/// Non-adaptive group testing using a test matrix
pub fn non_adaptive_group_test<O: GroupTestOracle>(
    oracle: &O,
    users: &[UserId],
    params: &GroupTestParams,
) -> GroupTestResult {
    let num_users = users.len();
    let matrix = TestMatrix::disjunct(num_users, params.max_defectives);

    // Execute all tests
    let mut test_results = Vec::with_capacity(matrix.num_tests);
    for t in 0..matrix.num_tests {
        let test_users: Vec<UserId> = matrix
            .users_in_test(t)
            .iter()
            .filter_map(|&idx| users.get(idx).cloned())
            .collect();

        if test_users.is_empty() {
            test_results.push(TestResult::Negative);
        } else {
            test_results.push(oracle.test(&test_users));
        }
    }

    // Decode: user is defective if they appear in no negative tests
    let mut defectives = Vec::new();
    for (u, user) in users.iter().enumerate() {
        let user_tests = matrix.tests_for_user(u);
        let in_negative_test = user_tests
            .iter()
            .any(|&t| test_results[t] == TestResult::Negative);

        if !in_negative_test && !user_tests.is_empty() {
            defectives.push(user.clone());
        }
    }

    GroupTestResult {
        defectives,
        tests_used: matrix.num_tests,
        test_results,
    }
}

/// Adaptive binary splitting for group testing
pub fn binary_splitting<O: GroupTestOracle>(
    oracle: &O,
    users: &[UserId],
    max_tests: usize,
) -> GroupTestResult {
    let mut tests_used = 0;
    let mut defectives = Vec::new();
    let remaining: Vec<UserId> = users.to_vec();

    // First test: check if any defectives exist
    if remaining.is_empty() {
        return GroupTestResult {
            defectives: vec![],
            tests_used: 0,
            test_results: vec![],
        };
    }

    let result = oracle.test(&remaining);
    tests_used += 1;

    if result == TestResult::Negative {
        return GroupTestResult {
            defectives: vec![],
            tests_used,
            test_results: vec![result],
        };
    }

    // Binary search to find defectives
    fn find_defectives<O: GroupTestOracle>(
        oracle: &O,
        candidates: &[UserId],
        tests_used: &mut usize,
        max_tests: usize,
    ) -> Vec<UserId> {
        if candidates.is_empty() || *tests_used >= max_tests {
            return vec![];
        }

        if candidates.len() == 1 {
            // Verify single candidate
            let result = oracle.test(candidates);
            *tests_used += 1;
            if result == TestResult::Positive {
                return candidates.to_vec();
            }
            return vec![];
        }

        // Split and test first half
        let mid = candidates.len() / 2;
        let (left, right) = candidates.split_at(mid);

        let mut found = Vec::new();

        // Test left half
        let left_result = oracle.test(left);
        *tests_used += 1;

        if left_result == TestResult::Positive {
            found.extend(find_defectives(oracle, left, tests_used, max_tests));
        }

        if *tests_used >= max_tests {
            return found;
        }

        // Test right half
        let right_result = oracle.test(right);
        *tests_used += 1;

        if right_result == TestResult::Positive {
            found.extend(find_defectives(oracle, right, tests_used, max_tests));
        }

        found
    }

    defectives = find_defectives(oracle, &remaining, &mut tests_used, max_tests);

    GroupTestResult {
        defectives,
        tests_used,
        test_results: vec![], // Not tracked in adaptive mode
    }
}

/// Generalized binary splitting (handles multiple defectives)
pub fn generalized_binary_splitting<O: GroupTestOracle>(
    oracle: &O,
    users: &[UserId],
    params: &GroupTestParams,
) -> GroupTestResult {
    let max_tests = users.len() * params.max_defectives * 2;

    if params.max_defectives == 1 {
        return binary_splitting(oracle, users, max_tests);
    }

    let mut tests_used = 0;
    let mut defectives = Vec::new();
    let cleared: HashSet<String> = HashSet::new();

    // Iteratively find and remove defectives
    let mut iterations = 0;
    while iterations < params.max_defectives && tests_used < max_tests {
        // Get remaining candidates
        let candidates: Vec<UserId> = users
            .iter()
            .filter(|u| !cleared.contains(u.as_str()) && !defectives.iter().any(|d: &UserId| d.as_str() == u.as_str()))
            .cloned()
            .collect();

        if candidates.is_empty() {
            break;
        }

        // Test remaining candidates
        let result = oracle.test(&candidates);
        tests_used += 1;

        if result == TestResult::Negative {
            // No more defectives
            break;
        }

        // Find one defective using binary search
        let found = binary_splitting(oracle, &candidates, max_tests - tests_used);
        tests_used += found.tests_used;

        if found.defectives.is_empty() {
            break;
        }

        // Add found defectives
        defectives.extend(found.defectives);
        iterations += 1;
    }

    GroupTestResult {
        defectives,
        tests_used,
        test_results: vec![],
    }
}

/// Hwang's generalized binary splitting algorithm
///
/// More efficient than basic binary splitting when the number of
/// defectives is known or bounded.
pub fn hwang_algorithm<O: GroupTestOracle>(
    oracle: &O,
    users: &[UserId],
    expected_defectives: usize,
) -> GroupTestResult {
    let n = users.len();
    let d = expected_defectives;

    if d == 0 || n == 0 {
        return GroupTestResult {
            defectives: vec![],
            tests_used: 0,
            test_results: vec![],
        };
    }

    // Use generalized splitting with optimized group sizes
    // Group size should be approximately n/(d+1) for optimal efficiency
    let group_size = (n / (d + 1)).max(1);

    let mut tests_used = 0;
    let mut defectives = Vec::new();
    let mut index = 0;

    while index < n && tests_used < n {
        let end = (index + group_size).min(n);
        let group: Vec<UserId> = users[index..end].to_vec();

        if group.is_empty() {
            break;
        }

        let result = oracle.test(&group);
        tests_used += 1;

        if result == TestResult::Positive {
            // Binary search within this group
            let found = binary_splitting(oracle, &group, n - tests_used);
            tests_used += found.tests_used;
            defectives.extend(found.defectives);
        }

        index = end;
    }

    GroupTestResult {
        defectives,
        tests_used,
        test_results: vec![],
    }
}

/// Group testing using traitor tracing oracles
pub fn group_test_trace<O: GroupTestOracle>(
    oracle: &O,
    users: &[UserId],
    params: &GroupTestParams,
) -> GroupTestResult {
    if params.adaptive {
        if params.max_defectives == 1 {
            binary_splitting(oracle, users, users.len() * 2)
        } else {
            generalized_binary_splitting(oracle, users, params)
        }
    } else {
        non_adaptive_group_test(oracle, users, params)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test oracle that responds positive if any traitors are in the group
    struct TestOracle {
        traitors: HashSet<String>,
    }

    impl TestOracle {
        fn new(traitors: &[&str]) -> Self {
            TestOracle {
                traitors: traitors.iter().map(|s| s.to_string()).collect(),
            }
        }
    }

    impl GroupTestOracle for TestOracle {
        fn test(&self, users: &[UserId]) -> TestResult {
            for user in users {
                if self.traitors.contains(user.as_str()) {
                    return TestResult::Positive;
                }
            }
            TestResult::Negative
        }
    }

    #[test]
    fn test_test_matrix_creation() {
        let matrix = TestMatrix::new(10, 5);
        assert_eq!(matrix.num_users, 10);
        assert_eq!(matrix.num_tests, 5);
    }

    #[test]
    fn test_disjunct_matrix() {
        let matrix = TestMatrix::disjunct(16, 2);
        assert!(matrix.num_tests >= 4); // At least some tests
        assert_eq!(matrix.num_users, 16);
    }

    #[test]
    fn test_binary_splitting_single_traitor() {
        let oracle = TestOracle::new(&["user3"]);
        let users: Vec<UserId> = (0..8)
            .map(|i| UserId::new(format!("user{}", i)))
            .collect();

        let result = binary_splitting(&oracle, &users, 100);

        assert_eq!(result.defectives.len(), 1);
        assert_eq!(result.defectives[0].as_str(), "user3");
        assert!(result.tests_used <= 10); // Should be O(log n)
    }

    #[test]
    fn test_binary_splitting_no_traitors() {
        let oracle = TestOracle::new(&[]);
        let users: Vec<UserId> = (0..8)
            .map(|i| UserId::new(format!("user{}", i)))
            .collect();

        let result = binary_splitting(&oracle, &users, 100);

        assert!(result.defectives.is_empty());
        assert_eq!(result.tests_used, 1); // Only one test needed
    }

    #[test]
    fn test_generalized_splitting_two_traitors() {
        let oracle = TestOracle::new(&["user2", "user5"]);
        let users: Vec<UserId> = (0..8)
            .map(|i| UserId::new(format!("user{}", i)))
            .collect();

        let params = GroupTestParams::multiple(2);
        let result = generalized_binary_splitting(&oracle, &users, &params);

        assert!(result.defectives.len() >= 1);
        let found: HashSet<_> = result.defectives.iter().map(|u| u.as_str()).collect();
        assert!(found.contains("user2") || found.contains("user5"));
    }

    #[test]
    fn test_hwang_algorithm() {
        let oracle = TestOracle::new(&["user1"]);
        let users: Vec<UserId> = (0..16)
            .map(|i| UserId::new(format!("user{}", i)))
            .collect();

        let result = hwang_algorithm(&oracle, &users, 1);

        assert_eq!(result.defectives.len(), 1);
        assert_eq!(result.defectives[0].as_str(), "user1");
    }

    #[test]
    fn test_non_adaptive_group_test() {
        let oracle = TestOracle::new(&["user3"]);
        let users: Vec<UserId> = (0..8)
            .map(|i| UserId::new(format!("user{}", i)))
            .collect();

        let params = GroupTestParams::non_adaptive(2);
        let result = non_adaptive_group_test(&oracle, &users, &params);

        // Non-adaptive may find false positives but should find the traitor
        let found: HashSet<_> = result.defectives.iter().map(|u| u.as_str()).collect();
        assert!(found.contains("user3"));
    }

    #[test]
    fn test_group_test_trace() {
        let oracle = TestOracle::new(&["user4"]);
        let users: Vec<UserId> = (0..16)
            .map(|i| UserId::new(format!("user{}", i)))
            .collect();

        let params = GroupTestParams::single();
        let result = group_test_trace(&oracle, &users, &params);

        assert_eq!(result.defectives.len(), 1);
        assert_eq!(result.defectives[0].as_str(), "user4");
    }

    #[test]
    fn test_random_matrix() {
        let mut rng = rand::thread_rng();
        let matrix = TestMatrix::random(&mut rng, 100, 3);

        assert_eq!(matrix.num_users, 100);
        assert!(matrix.num_tests > 0);
    }

    #[test]
    fn test_matrix_queries() {
        let matrix = TestMatrix::disjunct(8, 1);

        // Check users_in_test
        for t in 0..matrix.num_tests {
            let users = matrix.users_in_test(t);
            for &u in &users {
                assert!(matrix.tests[t][u]);
            }
        }

        // Check tests_for_user
        for u in 0..matrix.num_users {
            let tests = matrix.tests_for_user(u);
            for &t in &tests {
                assert!(matrix.tests[t][u]);
            }
        }
    }
}
