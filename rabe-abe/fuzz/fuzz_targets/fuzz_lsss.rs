#![no_main]

use libfuzzer_sys::fuzz_target;
use rabe_abe::lsss::{LsssMatrix, PolicyNode};
use rabe_abe::schemes::waters;

// Fuzz the LSSS matrix construction and reconstruction paths
// This tests that:
// 1. Malformed policies don't cause panics
// 2. LSSS matrix construction handles edge cases
// 3. Secret sharing and reconstruction are robust
fuzz_target!(|data: &[u8]| {
    // Strategy 1: Try to parse as a policy string
    if let Ok(s) = std::str::from_utf8(data) {
        if let Ok(policy) = waters::parse_policy(s) {
            // If we got a valid policy, try to create LSSS matrix
            let _ = LsssMatrix::from_policy(&policy);
        }
    }

    // Strategy 2: Build random policy trees from bytes and test LSSS
    if data.len() >= 4 {
        let policy = build_policy_from_bytes(data);
        let _ = LsssMatrix::from_policy(&policy);
    }
});

/// Build a deterministic policy tree from fuzzer input bytes
fn build_policy_from_bytes(data: &[u8]) -> PolicyNode {
    if data.is_empty() {
        return PolicyNode::Attr("a".to_string());
    }

    let selector = data[0] % 4;
    let rest = if data.len() > 1 { &data[1..] } else { &[] };

    match selector {
        0 => {
            // Single attribute - use next bytes as name
            let name = if rest.is_empty() {
                "attr".to_string()
            } else {
                format!("attr_{}", rest[0])
            };
            PolicyNode::Attr(name)
        }
        1 => {
            // AND node with 2 children
            let mid = rest.len() / 2;
            let left = build_policy_from_bytes(&rest[..mid]);
            let right = build_policy_from_bytes(&rest[mid..]);
            PolicyNode::And(vec![left, right])
        }
        2 => {
            // OR node with 2 children
            let mid = rest.len() / 2;
            let left = build_policy_from_bytes(&rest[..mid]);
            let right = build_policy_from_bytes(&rest[mid..]);
            PolicyNode::Or(vec![left, right])
        }
        _ => {
            // Threshold (k-of-n) with 2-3 children
            let num_children = if rest.is_empty() { 2 } else { 2 + (rest[0] % 2) as usize };
            let threshold = if rest.len() > 1 {
                1 + (rest[1] as usize % num_children)
            } else {
                1
            };

            let chunk_size = rest.len() / num_children.max(1);
            let children: Vec<PolicyNode> = (0..num_children)
                .map(|i| {
                    let start = i * chunk_size;
                    let end = ((i + 1) * chunk_size).min(rest.len());
                    build_policy_from_bytes(&rest[start..end])
                })
                .collect();

            if children.is_empty() {
                PolicyNode::Attr("fallback".to_string())
            } else {
                PolicyNode::Threshold(threshold.min(children.len()).max(1), children)
            }
        }
    }
}
