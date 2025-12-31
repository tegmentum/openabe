//! Revocation system for traitor tracing
//!
//! This module provides optional revocation functionality that can be used
//! with any traitor tracing approach. Once a traitor is identified, their
//! user ID can be added to a revocation list to prevent future decryption.

use std::collections::HashSet;
use super::types::UserId;

/// Reason for revoking a user's keys
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RevocationReason {
    /// User was identified as a traitor through tracing
    TraitorTraced,

    /// User's key was compromised (e.g., stolen device)
    KeyCompromised,

    /// Administrative revocation (e.g., user left organization)
    Administrative,

    /// Key has expired based on time limits
    Expired,

    /// Custom revocation reason
    Other(String),
}

impl RevocationReason {
    /// Returns a human-readable description of the revocation reason
    pub fn description(&self) -> String {
        match self {
            RevocationReason::TraitorTraced => "Traced as traitor".to_string(),
            RevocationReason::KeyCompromised => "Key compromised".to_string(),
            RevocationReason::Administrative => "Administrative action".to_string(),
            RevocationReason::Expired => "Key expired".to_string(),
            RevocationReason::Other(msg) => msg.clone(),
        }
    }
}

/// Entry in the revocation list with metadata
#[derive(Debug, Clone)]
pub struct RevocationEntry {
    /// The revoked user ID
    pub user_id: UserId,

    /// Reason for revocation
    pub reason: RevocationReason,

    /// Timestamp when revocation occurred (Unix epoch seconds)
    pub revoked_at: u64,

    /// Optional key version that was revoked (if applicable)
    pub key_version: Option<u32>,

    /// Optional notes about the revocation
    pub notes: Option<String>,
}

impl RevocationEntry {
    /// Create a new revocation entry
    pub fn new(user_id: UserId, reason: RevocationReason, revoked_at: u64) -> Self {
        RevocationEntry {
            user_id,
            reason,
            revoked_at,
            key_version: None,
            notes: None,
        }
    }

    /// Add key version to the entry
    pub fn with_key_version(mut self, version: u32) -> Self {
        self.key_version = Some(version);
        self
    }

    /// Add notes to the entry
    pub fn with_notes(mut self, notes: impl Into<String>) -> Self {
        self.notes = Some(notes.into());
        self
    }
}

/// Revocation list for tracking revoked users
///
/// This is a simple in-memory revocation list. In production, this would
/// typically be backed by a database or distributed ledger.
#[derive(Debug, Clone, Default)]
pub struct RevocationList {
    /// Set of revoked user IDs for O(1) lookup
    revoked_users: HashSet<UserId>,

    /// Full entries with metadata
    entries: Vec<RevocationEntry>,

    /// Version number for the list (incremented on each change)
    version: u64,
}

impl RevocationList {
    /// Create a new empty revocation list
    pub fn new() -> Self {
        RevocationList {
            revoked_users: HashSet::new(),
            entries: Vec::new(),
            version: 0,
        }
    }

    /// Revoke a user with the given reason
    pub fn revoke_user(&mut self, user_id: UserId, reason: RevocationReason) {
        self.revoke_user_at(user_id, reason, current_timestamp())
    }

    /// Revoke a user at a specific timestamp
    pub fn revoke_user_at(&mut self, user_id: UserId, reason: RevocationReason, timestamp: u64) {
        if !self.revoked_users.contains(&user_id) {
            self.revoked_users.insert(user_id.clone());
            self.entries.push(RevocationEntry::new(user_id, reason, timestamp));
            self.version += 1;
        }
    }

    /// Revoke a user with a full entry
    pub fn revoke_with_entry(&mut self, entry: RevocationEntry) {
        if !self.revoked_users.contains(&entry.user_id) {
            self.revoked_users.insert(entry.user_id.clone());
            self.entries.push(entry);
            self.version += 1;
        }
    }

    /// Check if a user is revoked
    pub fn is_revoked(&self, user_id: &UserId) -> bool {
        self.revoked_users.contains(user_id)
    }

    /// Get the revocation entry for a user if revoked
    pub fn get_entry(&self, user_id: &UserId) -> Option<&RevocationEntry> {
        self.entries.iter().find(|e| &e.user_id == user_id)
    }

    /// Get all revoked user IDs
    pub fn revoked_users(&self) -> impl Iterator<Item = &UserId> {
        self.revoked_users.iter()
    }

    /// Get all revocation entries
    pub fn entries(&self) -> &[RevocationEntry] {
        &self.entries
    }

    /// Get the current version of the list
    pub fn version(&self) -> u64 {
        self.version
    }

    /// Get the number of revoked users
    pub fn len(&self) -> usize {
        self.revoked_users.len()
    }

    /// Check if the list is empty
    pub fn is_empty(&self) -> bool {
        self.revoked_users.is_empty()
    }

    /// Remove a user from the revocation list (e.g., after re-keying)
    /// Returns true if the user was previously revoked
    pub fn unrevoke(&mut self, user_id: &UserId) -> bool {
        if self.revoked_users.remove(user_id) {
            self.entries.retain(|e| &e.user_id != user_id);
            self.version += 1;
            true
        } else {
            false
        }
    }

    /// Get all users revoked for a specific reason
    pub fn users_by_reason(&self, reason: &RevocationReason) -> Vec<&UserId> {
        self.entries
            .iter()
            .filter(|e| &e.reason == reason)
            .map(|e| &e.user_id)
            .collect()
    }

    /// Get all users revoked after a specific timestamp
    pub fn users_revoked_after(&self, timestamp: u64) -> Vec<&UserId> {
        self.entries
            .iter()
            .filter(|e| e.revoked_at > timestamp)
            .map(|e| &e.user_id)
            .collect()
    }

    /// Merge another revocation list into this one
    pub fn merge(&mut self, other: &RevocationList) {
        for entry in &other.entries {
            if !self.revoked_users.contains(&entry.user_id) {
                self.revoked_users.insert(entry.user_id.clone());
                self.entries.push(entry.clone());
                self.version += 1;
            }
        }
    }
}

/// Get current timestamp (Unix epoch seconds)
fn current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Result type for revocation checks
#[derive(Debug, Clone)]
pub enum RevocationCheckResult {
    /// User is not revoked and can proceed
    Allowed,

    /// User is revoked
    Revoked(RevocationEntry),
}

impl RevocationCheckResult {
    /// Returns true if the user is allowed (not revoked)
    pub fn is_allowed(&self) -> bool {
        matches!(self, RevocationCheckResult::Allowed)
    }

    /// Returns the revocation entry if revoked
    pub fn revocation_entry(&self) -> Option<&RevocationEntry> {
        match self {
            RevocationCheckResult::Revoked(entry) => Some(entry),
            RevocationCheckResult::Allowed => None,
        }
    }
}

/// Check a user against a revocation list
pub fn check_revocation(list: &RevocationList, user_id: &UserId) -> RevocationCheckResult {
    match list.get_entry(user_id) {
        Some(entry) => RevocationCheckResult::Revoked(entry.clone()),
        None => RevocationCheckResult::Allowed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_revocation_reason() {
        assert_eq!(
            RevocationReason::TraitorTraced.description(),
            "Traced as traitor"
        );
        assert_eq!(
            RevocationReason::Other("custom".to_string()).description(),
            "custom"
        );
    }

    #[test]
    fn test_revocation_entry() {
        let entry = RevocationEntry::new(
            UserId::new("alice"),
            RevocationReason::TraitorTraced,
            1234567890,
        )
        .with_key_version(3)
        .with_notes("Leaked key found on dark web");

        assert_eq!(entry.user_id.as_str(), "alice");
        assert_eq!(entry.reason, RevocationReason::TraitorTraced);
        assert_eq!(entry.key_version, Some(3));
        assert!(entry.notes.is_some());
    }

    #[test]
    fn test_revocation_list_basic() {
        let mut list = RevocationList::new();
        assert!(list.is_empty());
        assert_eq!(list.version(), 0);

        let alice = UserId::new("alice");
        list.revoke_user(alice.clone(), RevocationReason::TraitorTraced);

        assert!(!list.is_empty());
        assert_eq!(list.len(), 1);
        assert!(list.is_revoked(&alice));
        assert!(!list.is_revoked(&UserId::new("bob")));
        assert_eq!(list.version(), 1);
    }

    #[test]
    fn test_revocation_list_duplicate() {
        let mut list = RevocationList::new();
        let alice = UserId::new("alice");

        list.revoke_user(alice.clone(), RevocationReason::TraitorTraced);
        list.revoke_user(alice.clone(), RevocationReason::Administrative);

        // Should not add duplicate
        assert_eq!(list.len(), 1);
        assert_eq!(list.version(), 1);
    }

    #[test]
    fn test_revocation_list_unrevoke() {
        let mut list = RevocationList::new();
        let alice = UserId::new("alice");

        list.revoke_user(alice.clone(), RevocationReason::KeyCompromised);
        assert!(list.is_revoked(&alice));

        let result = list.unrevoke(&alice);
        assert!(result);
        assert!(!list.is_revoked(&alice));
        assert!(list.is_empty());

        // Unrevoking non-existent user returns false
        assert!(!list.unrevoke(&alice));
    }

    #[test]
    fn test_users_by_reason() {
        let mut list = RevocationList::new();

        list.revoke_user(UserId::new("alice"), RevocationReason::TraitorTraced);
        list.revoke_user(UserId::new("bob"), RevocationReason::KeyCompromised);
        list.revoke_user(UserId::new("charlie"), RevocationReason::TraitorTraced);

        let traitors = list.users_by_reason(&RevocationReason::TraitorTraced);
        assert_eq!(traitors.len(), 2);

        let compromised = list.users_by_reason(&RevocationReason::KeyCompromised);
        assert_eq!(compromised.len(), 1);
    }

    #[test]
    fn test_revocation_list_merge() {
        let mut list1 = RevocationList::new();
        list1.revoke_user(UserId::new("alice"), RevocationReason::TraitorTraced);

        let mut list2 = RevocationList::new();
        list2.revoke_user(UserId::new("bob"), RevocationReason::KeyCompromised);
        list2.revoke_user(UserId::new("alice"), RevocationReason::Administrative); // duplicate

        list1.merge(&list2);

        assert_eq!(list1.len(), 2);
        assert!(list1.is_revoked(&UserId::new("alice")));
        assert!(list1.is_revoked(&UserId::new("bob")));
    }

    #[test]
    fn test_check_revocation() {
        let mut list = RevocationList::new();
        list.revoke_user(UserId::new("alice"), RevocationReason::TraitorTraced);

        let alice_check = check_revocation(&list, &UserId::new("alice"));
        assert!(!alice_check.is_allowed());
        assert!(alice_check.revocation_entry().is_some());

        let bob_check = check_revocation(&list, &UserId::new("bob"));
        assert!(bob_check.is_allowed());
        assert!(bob_check.revocation_entry().is_none());
    }

    #[test]
    fn test_get_entry() {
        let mut list = RevocationList::new();
        let alice = UserId::new("alice");

        list.revoke_with_entry(
            RevocationEntry::new(alice.clone(), RevocationReason::TraitorTraced, 1234567890)
                .with_key_version(2)
        );

        let entry = list.get_entry(&alice).unwrap();
        assert_eq!(entry.key_version, Some(2));
        assert_eq!(entry.revoked_at, 1234567890);
    }

    #[test]
    fn test_users_revoked_after() {
        let mut list = RevocationList::new();

        list.revoke_user_at(UserId::new("alice"), RevocationReason::TraitorTraced, 100);
        list.revoke_user_at(UserId::new("bob"), RevocationReason::TraitorTraced, 200);
        list.revoke_user_at(UserId::new("charlie"), RevocationReason::TraitorTraced, 300);

        let after_150 = list.users_revoked_after(150);
        assert_eq!(after_150.len(), 2);

        let after_300 = list.users_revoked_after(300);
        assert_eq!(after_300.len(), 0);
    }
}
