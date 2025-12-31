//! Security hardening module
//!
//! This module provides security utilities for the ABE library:
//! - Constant-time operations to prevent timing attacks
//! - Input validation to prevent malformed data attacks
//! - Bounds checking to prevent integer overflow
//! - Memory protection for sensitive data
//! - Audit logging for security events

pub mod constant_time;
pub mod validation;
pub mod bounds;

#[cfg(feature = "memory-protection")]
pub mod memory;

pub mod audit;

// Re-exports
pub use constant_time::{secure_compare, ct_select};
pub use validation::{validate_policy, validate_plaintext, validate_attributes};
pub use bounds::{CheckedArithmetic, safe_index};
