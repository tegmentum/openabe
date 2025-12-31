//! Security audit logging utilities
//!
//! Provides structured logging for security-relevant events.
//! Uses the `log` crate with a "security" target for filtering.

use log::{info, warn, error};

/// Log a key generation event
pub fn log_keygen(scheme: &str, user_id: &str, num_attrs: usize) {
    info!(
        target: "security",
        "keygen: scheme={}, user={}, attributes={}",
        scheme, user_id, num_attrs
    );
}

/// Log a successful decryption
pub fn log_decrypt_success(scheme: &str) {
    info!(
        target: "security",
        "decrypt: scheme={}, status=success",
        scheme
    );
}

/// Log a failed decryption due to policy
pub fn log_decrypt_policy_failed(scheme: &str) {
    warn!(
        target: "security",
        "decrypt: scheme={}, status=policy_not_satisfied",
        scheme
    );
}

/// Log a failed decryption due to revocation
pub fn log_decrypt_revoked(scheme: &str, user_id: &str) {
    warn!(
        target: "security",
        "decrypt: scheme={}, status=revoked, user={}",
        scheme, user_id
    );
}

/// Log a decryption error
pub fn log_decrypt_error(scheme: &str, reason: &str) {
    error!(
        target: "security",
        "decrypt: scheme={}, status=error, reason={}",
        scheme, reason
    );
}

/// Log a key revocation event
pub fn log_revocation(user_id: &str, reason: &str) {
    warn!(
        target: "security",
        "revocation: user={}, reason={}",
        user_id, reason
    );
}

/// Log a traitor tracing event
pub fn log_traitor_traced(user_id: &str, scheme: &str) {
    warn!(
        target: "security",
        "traitor_traced: user={}, scheme={}",
        user_id, scheme
    );
}

/// Log invalid input detection
pub fn log_invalid_input(context: &str, reason: &str) {
    warn!(
        target: "security",
        "invalid_input: context={}, reason={}",
        context, reason
    );
}

/// Log a potential attack detection
pub fn log_potential_attack(attack_type: &str, details: &str) {
    error!(
        target: "security",
        "potential_attack: type={}, details={}",
        attack_type, details
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_logging_functions_dont_panic() {
        // Just verify the logging functions don't panic
        log_keygen("waters", "alice", 5);
        log_decrypt_success("waters");
        log_decrypt_policy_failed("waters");
        log_decrypt_revoked("waters", "bob");
        log_decrypt_error("waters", "test error");
        log_revocation("charlie", "key_compromise");
        log_traitor_traced("eve", "waters");
        log_invalid_input("encrypt", "empty plaintext");
        log_potential_attack("replay", "duplicate message id");
    }
}
