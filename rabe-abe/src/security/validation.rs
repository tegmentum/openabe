//! Input validation utilities to prevent malformed data attacks

use crate::error::AbeError;
use crate::lsss::PolicyNode;

/// Maximum number of attributes in a policy
pub const MAX_POLICY_ATTRIBUTES: usize = 1000;

/// Maximum length of an attribute name
pub const MAX_ATTRIBUTE_LENGTH: usize = 256;

/// Maximum plaintext size (16 MB)
pub const MAX_PLAINTEXT_SIZE: usize = 16 * 1024 * 1024;

/// Maximum number of attributes a user can have
pub const MAX_USER_ATTRIBUTES: usize = 500;

/// Validate a policy tree
///
/// Checks that:
/// - Policy doesn't exceed attribute limits
/// - All attribute names are valid
/// - Threshold values are valid
pub fn validate_policy(policy: &PolicyNode) -> Result<(), AbeError> {
    let count = count_policy_attributes(policy);
    if count > MAX_POLICY_ATTRIBUTES {
        return Err(AbeError::InvalidPolicy(format!(
            "Policy has {} attributes, maximum is {}",
            count, MAX_POLICY_ATTRIBUTES
        )));
    }
    validate_policy_node(policy)
}

fn count_policy_attributes(node: &PolicyNode) -> usize {
    match node {
        PolicyNode::Attr(_) => 1,
        PolicyNode::And(children) | PolicyNode::Or(children) => {
            children.iter().map(count_policy_attributes).sum()
        }
        PolicyNode::Threshold(_, children) => {
            children.iter().map(count_policy_attributes).sum()
        }
    }
}

fn validate_policy_node(node: &PolicyNode) -> Result<(), AbeError> {
    match node {
        PolicyNode::Attr(name) => {
            if name.is_empty() {
                return Err(AbeError::InvalidPolicy("Empty attribute name".into()));
            }
            if name.len() > MAX_ATTRIBUTE_LENGTH {
                return Err(AbeError::InvalidPolicy(format!(
                    "Attribute name too long: {} bytes (max {})",
                    name.len(),
                    MAX_ATTRIBUTE_LENGTH
                )));
            }
            // Check for invalid characters
            if name.contains('\0') {
                return Err(AbeError::InvalidPolicy(
                    "Attribute name contains null byte".into(),
                ));
            }
            Ok(())
        }
        PolicyNode::And(children) | PolicyNode::Or(children) => {
            if children.is_empty() {
                return Err(AbeError::InvalidPolicy("Empty AND/OR node".into()));
            }
            for child in children {
                validate_policy_node(child)?;
            }
            Ok(())
        }
        PolicyNode::Threshold(k, children) => {
            if *k == 0 {
                return Err(AbeError::InvalidPolicy("Threshold cannot be zero".into()));
            }
            if children.is_empty() {
                return Err(AbeError::InvalidPolicy("Empty threshold node".into()));
            }
            if *k > children.len() {
                return Err(AbeError::InvalidPolicy(format!(
                    "Threshold {} exceeds number of children {}",
                    k,
                    children.len()
                )));
            }
            for child in children {
                validate_policy_node(child)?;
            }
            Ok(())
        }
    }
}

/// Validate plaintext data
///
/// Checks that plaintext is not empty and within size limits.
pub fn validate_plaintext(data: &[u8]) -> Result<(), AbeError> {
    if data.is_empty() {
        return Err(AbeError::EncryptError("Empty plaintext".into()));
    }
    if data.len() > MAX_PLAINTEXT_SIZE {
        return Err(AbeError::EncryptError(format!(
            "Plaintext too large: {} bytes (max {})",
            data.len(),
            MAX_PLAINTEXT_SIZE
        )));
    }
    Ok(())
}

/// Validate a set of attributes
///
/// Checks that:
/// - At least one attribute is provided
/// - Attribute count is within limits
/// - All attribute names are valid
pub fn validate_attributes(attrs: &[String]) -> Result<(), AbeError> {
    if attrs.is_empty() {
        return Err(AbeError::KeygenError("No attributes provided".into()));
    }
    if attrs.len() > MAX_USER_ATTRIBUTES {
        return Err(AbeError::KeygenError(format!(
            "Too many attributes: {} (max {})",
            attrs.len(),
            MAX_USER_ATTRIBUTES
        )));
    }
    for attr in attrs {
        if attr.is_empty() {
            return Err(AbeError::KeygenError("Empty attribute name".into()));
        }
        if attr.len() > MAX_ATTRIBUTE_LENGTH {
            return Err(AbeError::KeygenError(format!(
                "Attribute name too long: {} bytes (max {})",
                attr.len(),
                MAX_ATTRIBUTE_LENGTH
            )));
        }
        if attr.contains('\0') {
            return Err(AbeError::KeygenError(
                "Attribute name contains null byte".into(),
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_simple_policy() {
        let policy = PolicyNode::Attr("admin".into());
        assert!(validate_policy(&policy).is_ok());
    }

    #[test]
    fn test_validate_and_policy() {
        let policy = PolicyNode::And(vec![
            PolicyNode::Attr("admin".into()),
            PolicyNode::Attr("active".into()),
        ]);
        assert!(validate_policy(&policy).is_ok());
    }

    #[test]
    fn test_validate_threshold_policy() {
        let policy = PolicyNode::Threshold(
            2,
            vec![
                PolicyNode::Attr("a".into()),
                PolicyNode::Attr("b".into()),
                PolicyNode::Attr("c".into()),
            ],
        );
        assert!(validate_policy(&policy).is_ok());
    }

    #[test]
    fn test_empty_attribute_rejected() {
        let policy = PolicyNode::Attr("".into());
        assert!(validate_policy(&policy).is_err());
    }

    #[test]
    fn test_empty_and_rejected() {
        let policy = PolicyNode::And(vec![]);
        assert!(validate_policy(&policy).is_err());
    }

    #[test]
    fn test_invalid_threshold_rejected() {
        let policy = PolicyNode::Threshold(
            5, // threshold > children count
            vec![
                PolicyNode::Attr("a".into()),
                PolicyNode::Attr("b".into()),
            ],
        );
        assert!(validate_policy(&policy).is_err());
    }

    #[test]
    fn test_zero_threshold_rejected() {
        let policy = PolicyNode::Threshold(0, vec![PolicyNode::Attr("a".into())]);
        assert!(validate_policy(&policy).is_err());
    }

    #[test]
    fn test_validate_plaintext() {
        assert!(validate_plaintext(b"hello").is_ok());
        assert!(validate_plaintext(b"").is_err());
    }

    #[test]
    fn test_validate_attributes() {
        assert!(validate_attributes(&["admin".into(), "user".into()]).is_ok());
        assert!(validate_attributes(&[]).is_err());
        assert!(validate_attributes(&["".into()]).is_err());
    }
}
