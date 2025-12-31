//! Core types for traitor tracing
//!
//! This module defines the common types used across all traitor tracing approaches:
//! - White-box tracing (key inspection)
//! - Black-box tracing (oracle queries)
//! - Fingerprinting (content marking)

use std::fmt;

/// Unique identifier for a user in the traitor tracing system
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct UserId(pub String);

impl UserId {
    /// Create a new user ID
    pub fn new(id: impl Into<String>) -> Self {
        UserId(id.into())
    }

    /// Get the ID as a string slice
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for UserId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<&str> for UserId {
    fn from(s: &str) -> Self {
        UserId(s.to_string())
    }
}

impl From<String> for UserId {
    fn from(s: String) -> Self {
        UserId(s)
    }
}

/// Result of a tracing operation
#[derive(Debug, Clone)]
pub enum TraceResult {
    /// Successfully traced one or more traitors
    Traced(Vec<UserId>),

    /// Could not conclusively identify traitors
    /// This may occur in black-box tracing with insufficient queries
    Inconclusive,

    /// Tracing failed with an error message
    Failed(String),
}

impl TraceResult {
    /// Returns true if tracing was successful
    pub fn is_traced(&self) -> bool {
        matches!(self, TraceResult::Traced(_))
    }

    /// Returns the traced users if successful
    pub fn traitors(&self) -> Option<&[UserId]> {
        match self {
            TraceResult::Traced(users) => Some(users),
            _ => None,
        }
    }

    /// Returns true if the result is inconclusive
    pub fn is_inconclusive(&self) -> bool {
        matches!(self, TraceResult::Inconclusive)
    }

    /// Returns true if tracing failed
    pub fn is_failed(&self) -> bool {
        matches!(self, TraceResult::Failed(_))
    }

    /// Returns the error message if tracing failed
    pub fn error_message(&self) -> Option<&str> {
        match self {
            TraceResult::Failed(msg) => Some(msg),
            _ => None,
        }
    }
}

/// Metadata embedded in traceable secret keys
#[derive(Debug, Clone)]
pub struct TracingMetadata {
    /// User ID for the key owner
    pub user_id: UserId,

    /// Timestamp when the key was issued (Unix epoch seconds)
    pub issued_at: u64,

    /// Version number for key revisions
    pub version: u32,
}

impl TracingMetadata {
    /// Create new tracing metadata
    pub fn new(user_id: impl Into<UserId>, issued_at: u64) -> Self {
        TracingMetadata {
            user_id: user_id.into(),
            issued_at,
            version: 1,
        }
    }

    /// Create metadata with a specific version
    pub fn with_version(user_id: impl Into<UserId>, issued_at: u64, version: u32) -> Self {
        TracingMetadata {
            user_id: user_id.into(),
            issued_at,
            version,
        }
    }
}

/// Evidence collected during black-box tracing
#[derive(Debug, Clone)]
pub struct TraceEvidence {
    /// The user ID implicated by this evidence
    pub user_id: UserId,

    /// Confidence score (0.0 to 1.0)
    pub confidence: f64,

    /// Number of queries that implicated this user
    pub positive_queries: usize,

    /// Total queries involving this user
    pub total_queries: usize,

    /// Description of how this evidence was gathered
    pub description: String,
}

impl TraceEvidence {
    /// Create new trace evidence
    pub fn new(user_id: UserId, positive: usize, total: usize) -> Self {
        let confidence = if total > 0 {
            positive as f64 / total as f64
        } else {
            0.0
        };

        TraceEvidence {
            user_id,
            confidence,
            positive_queries: positive,
            total_queries: total,
            description: String::new(),
        }
    }

    /// Add a description to the evidence
    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = desc.into();
        self
    }
}

/// Result of black-box tracing with detailed information
#[derive(Debug, Clone)]
pub struct BlackBoxTraceResult {
    /// Identified traitors
    pub traitors: Vec<UserId>,

    /// Overall confidence in the result (0.0 to 1.0)
    pub confidence: f64,

    /// Number of oracle queries used
    pub queries_used: usize,

    /// Detailed evidence for each suspected traitor
    pub evidence: Vec<TraceEvidence>,
}

impl BlackBoxTraceResult {
    /// Create a new black-box trace result
    pub fn new(traitors: Vec<UserId>, confidence: f64, queries: usize) -> Self {
        BlackBoxTraceResult {
            traitors,
            confidence,
            queries_used: queries,
            evidence: Vec::new(),
        }
    }

    /// Add evidence to the result
    pub fn with_evidence(mut self, evidence: Vec<TraceEvidence>) -> Self {
        self.evidence = evidence;
        self
    }
}

/// Configuration for black-box tracing
#[derive(Debug, Clone)]
pub struct BlackBoxConfig {
    /// Maximum number of oracle queries allowed
    pub max_queries: usize,

    /// Minimum confidence threshold to declare a traitor (0.0 to 1.0)
    pub confidence_threshold: f64,

    /// Whether to use adaptive querying strategies
    pub adaptive: bool,

    /// Number of colluders to tolerate (affects query strategy)
    pub collusion_bound: usize,
}

impl Default for BlackBoxConfig {
    fn default() -> Self {
        BlackBoxConfig {
            max_queries: 1000,
            confidence_threshold: 0.95,
            adaptive: true,
            collusion_bound: 1,
        }
    }
}

impl BlackBoxConfig {
    /// Create config for single traitor detection
    pub fn single_traitor() -> Self {
        BlackBoxConfig {
            max_queries: 100,
            confidence_threshold: 0.99,
            adaptive: true,
            collusion_bound: 1,
        }
    }

    /// Create config for collusion detection
    pub fn collusion_resistant(bound: usize) -> Self {
        BlackBoxConfig {
            max_queries: bound * bound * 100,
            confidence_threshold: 0.95,
            adaptive: true,
            collusion_bound: bound,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_user_id() {
        let id1 = UserId::new("alice");
        let id2: UserId = "alice".into();
        let id3: UserId = String::from("alice").into();

        assert_eq!(id1, id2);
        assert_eq!(id2, id3);
        assert_eq!(id1.as_str(), "alice");
        assert_eq!(format!("{}", id1), "alice");
    }

    #[test]
    fn test_trace_result() {
        let traced = TraceResult::Traced(vec![UserId::new("alice")]);
        assert!(traced.is_traced());
        assert!(!traced.is_inconclusive());
        assert!(!traced.is_failed());
        assert_eq!(traced.traitors().unwrap().len(), 1);

        let inconclusive = TraceResult::Inconclusive;
        assert!(!inconclusive.is_traced());
        assert!(inconclusive.is_inconclusive());
        assert!(inconclusive.traitors().is_none());

        let failed = TraceResult::Failed("test error".to_string());
        assert!(failed.is_failed());
        assert_eq!(failed.error_message(), Some("test error"));
    }

    #[test]
    fn test_tracing_metadata() {
        let meta = TracingMetadata::new("alice", 1234567890);
        assert_eq!(meta.user_id.as_str(), "alice");
        assert_eq!(meta.issued_at, 1234567890);
        assert_eq!(meta.version, 1);

        let meta2 = TracingMetadata::with_version("bob", 1234567890, 5);
        assert_eq!(meta2.version, 5);
    }

    #[test]
    fn test_trace_evidence() {
        let evidence = TraceEvidence::new(UserId::new("alice"), 8, 10)
            .with_description("Binary search implicated user");

        assert_eq!(evidence.user_id.as_str(), "alice");
        assert!((evidence.confidence - 0.8).abs() < 0.001);
        assert_eq!(evidence.positive_queries, 8);
        assert_eq!(evidence.total_queries, 10);
        assert!(!evidence.description.is_empty());
    }

    #[test]
    fn test_black_box_config() {
        let default_config = BlackBoxConfig::default();
        assert_eq!(default_config.max_queries, 1000);
        assert!(default_config.adaptive);

        let single = BlackBoxConfig::single_traitor();
        assert_eq!(single.collusion_bound, 1);

        let collusion = BlackBoxConfig::collusion_resistant(3);
        assert_eq!(collusion.collusion_bound, 3);
        assert!(collusion.max_queries > single.max_queries);
    }

    #[test]
    fn test_black_box_result() {
        let evidence = vec![
            TraceEvidence::new(UserId::new("alice"), 9, 10),
        ];

        let result = BlackBoxTraceResult::new(
            vec![UserId::new("alice")],
            0.9,
            50,
        ).with_evidence(evidence);

        assert_eq!(result.traitors.len(), 1);
        assert_eq!(result.queries_used, 50);
        assert_eq!(result.evidence.len(), 1);
    }
}
