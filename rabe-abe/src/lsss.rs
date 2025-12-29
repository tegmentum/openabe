//! Linear Secret Sharing Scheme (LSSS) for policy trees
//!
//! This module implements LSSS for threshold policies, converting a policy tree
//! into a matrix form where each row corresponds to an attribute.

use crate::error::AbeError;
use rabe_bls12381::Fr;
use rand::{RngCore, CryptoRng};
use std::collections::HashMap;
use std::sync::RwLock;
use std::num::NonZeroUsize;
use lru::LruCache;

/// Compute inverses of multiple field elements using Montgomery's trick.
///
/// This reduces n field inversions to just 1 inversion + 3n multiplications,
/// which is more efficient when n > 1 since field inversion is ~100x slower
/// than multiplication.
///
/// Returns None if any element is zero.
#[inline]
pub fn batch_inverse(values: &[Fr]) -> Option<Vec<Fr>> {
    let n = values.len();
    if n == 0 {
        return Some(vec![]);
    }
    if n == 1 {
        return values[0].inverse().map(|inv| vec![inv]);
    }

    // Check for zeros first
    for v in values {
        if v.is_zero() {
            return None;
        }
    }

    // Compute prefix products: prefix[i] = values[0] * values[1] * ... * values[i]
    let mut prefix = Vec::with_capacity(n);
    prefix.push(values[0]);
    for i in 1..n {
        prefix.push(prefix[i - 1] * values[i]);
    }

    // Single inversion of the total product
    let mut inv = prefix[n - 1].inverse()?;

    // Compute all inverses by working backwards
    // inv[i] = prefix[i-1] * current_inv, then update current_inv *= values[i]
    let mut result = vec![Fr::zero(); n];
    for i in (1..n).rev() {
        result[i] = prefix[i - 1] * inv;
        inv = inv * values[i];
    }
    result[0] = inv;

    Some(result)
}

/// Default cache size for LSSS matrices
const LSSS_CACHE_SIZE: usize = 256;

/// Thread-safe LRU cache for LSSS matrices
/// Key: canonical policy string
static LSSS_CACHE: std::sync::LazyLock<RwLock<LruCache<String, LsssMatrix>>> =
    std::sync::LazyLock::new(|| {
        RwLock::new(LruCache::new(NonZeroUsize::new(LSSS_CACHE_SIZE).unwrap()))
    });

/// Get or compute an LSSS matrix for a policy, using cache for repeated policies
///
/// This is useful when the same policy is used for multiple encryptions,
/// avoiding repeated LSSS matrix computation.
pub fn get_or_compute_lsss(policy: &PolicyNode) -> Result<LsssMatrix, AbeError> {
    let cache_key = policy.to_canonical_string();

    // Try to get from cache (read lock)
    if let Ok(cache) = LSSS_CACHE.read() {
        if let Some(matrix) = cache.peek(&cache_key) {
            return Ok(matrix.clone());
        }
    }

    // Cache miss - compute the matrix
    let matrix = LsssMatrix::from_policy(policy)
        .map_err(|e| AbeError::InvalidPolicy(e.to_string()))?;

    // Store in cache (write lock)
    if let Ok(mut cache) = LSSS_CACHE.write() {
        cache.put(cache_key, matrix.clone());
    }

    Ok(matrix)
}

/// Clear the LSSS cache (useful for testing or memory management)
pub fn clear_lsss_cache() {
    if let Ok(mut cache) = LSSS_CACHE.write() {
        cache.clear();
    }
}

/// A row in the LSSS matrix
#[derive(Clone, Debug)]
pub struct LsssRow {
    /// The attribute label for this row
    pub attr: String,
    /// The row vector in the LSSS matrix
    pub vector: Vec<Fr>,
}

/// The LSSS matrix representation of a policy
#[derive(Clone, Debug)]
pub struct LsssMatrix {
    /// Rows of the matrix, one per attribute in the policy
    pub rows: Vec<LsssRow>,
    /// Number of columns in the matrix
    pub num_cols: usize,
}

/// A share of the secret for an attribute
#[derive(Clone, Debug)]
pub struct LsssShare {
    /// The attribute this share is for
    pub attr: String,
    /// The share value (dot product of row with secret vector)
    pub share: Fr,
}

/// Policy node type
#[derive(Clone, Debug, PartialEq)]
pub enum PolicyNode {
    /// Leaf node containing an attribute
    Attr(String),
    /// AND gate (all children must be satisfied) - threshold = n
    And(Vec<PolicyNode>),
    /// OR gate (any child must be satisfied) - threshold = 1
    Or(Vec<PolicyNode>),
    /// Threshold gate: k of n children must be satisfied
    Threshold(usize, Vec<PolicyNode>),
}

impl PolicyNode {
    /// Convert policy to canonical string (for hashing)
    pub fn to_canonical_string(&self) -> String {
        match self {
            PolicyNode::Attr(attr) => attr.clone(),
            PolicyNode::And(children) => {
                let mut child_strs: Vec<_> = children.iter()
                    .map(|c| c.to_canonical_string())
                    .collect();
                child_strs.sort();
                format!("({})", child_strs.join(" and "))
            }
            PolicyNode::Or(children) => {
                let mut child_strs: Vec<_> = children.iter()
                    .map(|c| c.to_canonical_string())
                    .collect();
                child_strs.sort();
                format!("({})", child_strs.join(" or "))
            }
            PolicyNode::Threshold(k, children) => {
                let mut child_strs: Vec<_> = children.iter()
                    .map(|c| c.to_canonical_string())
                    .collect();
                child_strs.sort();
                format!("({} of {})", k, child_strs.join(", "))
            }
        }
    }

    /// Canonicalize the policy by sorting children in AND/OR/Threshold gates
    ///
    /// This ensures that the same logical policy always produces the same
    /// LSSS matrix structure, regardless of the input order of children.
    pub fn canonicalize(&self) -> PolicyNode {
        match self {
            PolicyNode::Attr(attr) => PolicyNode::Attr(attr.clone()),
            PolicyNode::And(children) => {
                let mut canonical_children: Vec<_> = children.iter()
                    .map(|c| c.canonicalize())
                    .collect();
                canonical_children.sort_by(|a, b| a.to_canonical_string().cmp(&b.to_canonical_string()));
                PolicyNode::And(canonical_children)
            }
            PolicyNode::Or(children) => {
                let mut canonical_children: Vec<_> = children.iter()
                    .map(|c| c.canonicalize())
                    .collect();
                canonical_children.sort_by(|a, b| a.to_canonical_string().cmp(&b.to_canonical_string()));
                PolicyNode::Or(canonical_children)
            }
            PolicyNode::Threshold(k, children) => {
                let mut canonical_children: Vec<_> = children.iter()
                    .map(|c| c.canonicalize())
                    .collect();
                canonical_children.sort_by(|a, b| a.to_canonical_string().cmp(&b.to_canonical_string()));
                PolicyNode::Threshold(*k, canonical_children)
            }
        }
    }

    /// Count total number of attributes in the policy
    pub fn count_attrs(&self) -> usize {
        match self {
            PolicyNode::Attr(_) => 1,
            PolicyNode::And(children) | PolicyNode::Or(children) | PolicyNode::Threshold(_, children) => {
                children.iter().map(|c| c.count_attrs()).sum()
            }
        }
    }

    /// Get all attribute names in the policy
    pub fn get_attrs(&self) -> Vec<String> {
        match self {
            PolicyNode::Attr(attr) => vec![attr.clone()],
            PolicyNode::And(children) | PolicyNode::Or(children) | PolicyNode::Threshold(_, children) => {
                children.iter().flat_map(|c| c.get_attrs()).collect()
            }
        }
    }

    /// Quick check if policy can possibly be satisfied by given attributes.
    ///
    /// This is a fast O(n) check that should be called before expensive LSSS
    /// computation to short-circuit on policies that cannot be satisfied.
    ///
    /// # Performance
    ///
    /// This method is much faster than building the full LSSS matrix and
    /// attempting reconstruction. Use it to fail fast on unsatisfiable policies.
    ///
    /// # Example
    ///
    /// ```
    /// use rabe_abe::lsss::PolicyNode;
    /// use std::collections::HashSet;
    ///
    /// let policy = PolicyNode::And(vec![
    ///     PolicyNode::Attr("admin".to_string()),
    ///     PolicyNode::Attr("developer".to_string()),
    /// ]);
    ///
    /// let mut attrs = HashSet::new();
    /// attrs.insert("admin".to_string());
    ///
    /// // Quick check - returns false because "developer" is missing
    /// assert!(!policy.can_satisfy(&attrs));
    ///
    /// attrs.insert("developer".to_string());
    /// assert!(policy.can_satisfy(&attrs));
    /// ```
    #[inline]
    pub fn can_satisfy(&self, attributes: &std::collections::HashSet<String>) -> bool {
        match self {
            PolicyNode::Attr(attr) => attributes.contains(attr),
            PolicyNode::And(children) => {
                children.iter().all(|c| c.can_satisfy(attributes))
            }
            PolicyNode::Or(children) => {
                children.iter().any(|c| c.can_satisfy(attributes))
            }
            PolicyNode::Threshold(k, children) => {
                children.iter().filter(|c| c.can_satisfy(attributes)).count() >= *k
            }
        }
    }

    /// Quick check using a slice of attribute strings.
    ///
    /// Convenience method that converts the slice to a HashSet internally.
    /// For repeated checks, prefer `can_satisfy` with a pre-built HashSet.
    #[inline]
    pub fn can_satisfy_attrs(&self, attributes: &[String]) -> bool {
        let attr_set: std::collections::HashSet<String> = attributes.iter().cloned().collect();
        self.can_satisfy(&attr_set)
    }
}

impl LsssMatrix {
    /// Create an LSSS matrix from a policy tree
    ///
    /// The policy is canonicalized first to ensure that the same logical policy
    /// always produces the same LSSS matrix structure (important for serialization).
    ///
    /// # Errors
    ///
    /// Returns an error if the policy contains invalid threshold gates (e.g., 0-of-n or k-of-n where k > n).
    pub fn from_policy(policy: &PolicyNode) -> Result<Self, crate::error::AbeError> {
        // Canonicalize the policy to ensure consistent LSSS structure
        let canonical_policy = policy.canonicalize();

        let mut rows = Vec::new();
        let mut counter = 1usize;

        // Start with the root receiving the unit vector [1]
        Self::expand_node(&canonical_policy, vec![Fr::one()], &mut rows, &mut counter)?;

        let num_cols = rows.iter().map(|r| r.vector.len()).max().unwrap_or(1);

        // Pad all rows to have the same number of columns
        for row in &mut rows {
            while row.vector.len() < num_cols {
                row.vector.push(Fr::zero());
            }
        }

        Ok(LsssMatrix { rows, num_cols })
    }

    /// Recursively expand a policy node into LSSS rows
    fn expand_node(
        node: &PolicyNode,
        parent_vector: Vec<Fr>,
        rows: &mut Vec<LsssRow>,
        counter: &mut usize,
    ) -> Result<(), crate::error::AbeError> {
        match node {
            PolicyNode::Attr(attr) => {
                // Leaf node: add a row with the parent's vector
                rows.push(LsssRow {
                    attr: attr.clone(),
                    vector: parent_vector,
                });
                Ok(())
            }
            PolicyNode::And(children) => {
                // AND gate: threshold = n (all children)
                let threshold = children.len();
                Self::expand_threshold(threshold, children, parent_vector, rows, counter)
            }
            PolicyNode::Or(children) => {
                // OR gate: threshold = 1
                Self::expand_threshold(1, children, parent_vector, rows, counter)
            }
            PolicyNode::Threshold(k, children) => {
                Self::expand_threshold(*k, children, parent_vector, rows, counter)
            }
        }
    }

    /// Expand a threshold gate using Shamir secret sharing structure
    fn expand_threshold(
        threshold: usize,
        children: &[PolicyNode],
        parent_vector: Vec<Fr>,
        rows: &mut Vec<LsssRow>,
        counter: &mut usize,
    ) -> Result<(), crate::error::AbeError> {
        let n = children.len();

        if threshold == 0 || threshold > n {
            return Err(crate::error::AbeError::InvalidPolicy(
                format!("Invalid threshold: {} of {} (threshold must be 1 to {})", threshold, n, n)
            ));
        }

        if threshold == 1 {
            // OR gate (1-of-n): all children get the same vector
            for child in children {
                Self::expand_node(child, parent_vector.clone(), rows, counter)?;
            }
        } else {
            // General k-of-n threshold (including AND which is n-of-n):
            // Use Shamir-style polynomial evaluation
            // Each child gets row [parent, x, x^2, ..., x^(t-1)] evaluated at point x_i
            // where x_i = i+1 (using 1, 2, 3, ... as evaluation points)
            let _col_start = parent_vector.len();
            *counter += threshold - 1;

            for (i, child) in children.iter().enumerate() {
                // Evaluation point for this child: x = i + 1 (so we use 1, 2, 3, ...)
                let x = Fr::from_u64((i + 1) as u64);

                let mut child_vector = parent_vector.clone();

                // Extend with x, x^2, ..., x^(t-1) for the new columns
                let mut x_power = x;
                for _ in 0..(threshold - 1) {
                    child_vector.push(x_power);
                    x_power = x_power * x;
                }

                Self::expand_node(child, child_vector, rows, counter)?;
            }
        }
        Ok(())
    }

    /// Share a secret using this LSSS matrix
    pub fn share_secret<R: RngCore + CryptoRng>(&self, rng: &mut R, secret: Fr) -> Vec<LsssShare> {
        // Generate random coefficients for the secret vector
        // v = (s, r_2, r_3, ..., r_c) where s is the secret
        let mut v = vec![secret];
        for _ in 1..self.num_cols {
            v.push(Fr::random(rng));
        }

        // Compute shares as dot products
        self.rows
            .iter()
            .map(|row| {
                let share = row.vector.iter().zip(&v).fold(Fr::zero(), |acc, (a, b)| {
                    acc + (*a * *b)
                });
                LsssShare {
                    attr: row.attr.clone(),
                    share,
                }
            })
            .collect()
    }

    /// Recover coefficients for reconstruction given satisfied attributes
    ///
    /// Returns a map from attribute to coefficient for reconstruction.
    /// The secret can be recovered as: s = sum(coeff_i * share_i) for all i in subset
    pub fn recover_coefficients(
        &self,
        satisfied_attrs: &[String],
    ) -> Result<HashMap<String, Fr>, &'static str> {
        // Find rows that are satisfied
        let satisfied_set: std::collections::HashSet<_> = satisfied_attrs.iter().collect();
        let satisfied_rows: Vec<_> = self.rows.iter()
            .filter(|r| satisfied_set.contains(&r.attr))
            .collect();

        if satisfied_rows.is_empty() {
            return Err("No satisfied attributes");
        }

        // We need to find coefficients c_i such that sum(c_i * row_i) = (1, 0, 0, ...)
        // This is solving a linear system

        // For now, use a simplified approach for common cases
        // TODO: Implement full Gaussian elimination for general threshold

        let mut coeffs = HashMap::new();

        // Special case: if we only need one attribute (OR gate or single attr)
        // This only works if the row is [c, 0, 0, ...] (all other columns are zero)
        if satisfied_rows.len() == 1 {
            let row = &satisfied_rows[0];
            // Check if first element is non-zero AND all other elements are zero
            if !row.vector[0].is_zero() {
                let all_others_zero = row.vector.iter().skip(1).all(|x| x.is_zero());
                if all_others_zero {
                    if let Some(inv) = row.vector[0].inverse() {
                        coeffs.insert(row.attr.clone(), inv);
                        return Ok(coeffs);
                    }
                }
            }
            // If we only have one row but need more, fail
            return Err("Need more attributes to satisfy policy");
        }

        // General case: use Gaussian elimination
        // Build a matrix of just the satisfied rows
        let matrix: Vec<Vec<Fr>> = satisfied_rows.iter()
            .map(|r| r.vector.clone())
            .collect();

        // Try Gaussian elimination to solve for (1, 0, 0, ...)
        let n = matrix.len();
        let m = self.num_cols;

        if n == 0 || m == 0 {
            return Err("Empty matrix");
        }

        // Augmented matrix: [A | I] to get coefficients
        let mut aug: Vec<Vec<Fr>> = Vec::new();
        for (i, row) in matrix.iter().enumerate() {
            let mut aug_row = row.clone();
            // Add identity matrix columns
            for j in 0..n {
                aug_row.push(if i == j { Fr::one() } else { Fr::zero() });
            }
            aug.push(aug_row);
        }

        // Gaussian elimination to get row echelon form
        let mut pivot_row = 0;
        for col in 0..m {
            if pivot_row >= n {
                break;
            }

            // Find pivot
            let mut pivot_found = false;
            for row in pivot_row..n {
                if !aug[row][col].is_zero() {
                    // Swap rows
                    if row != pivot_row {
                        aug.swap(row, pivot_row);
                    }
                    pivot_found = true;
                    break;
                }
            }

            if !pivot_found {
                continue;
            }

            // Scale pivot row
            if let Some(inv) = aug[pivot_row][col].inverse() {
                for j in 0..(m + n) {
                    aug[pivot_row][j] = aug[pivot_row][j] * inv;
                }
            } else {
                continue;
            }

            // Eliminate other rows
            for row in 0..n {
                if row != pivot_row && !aug[row][col].is_zero() {
                    let factor = aug[row][col];
                    for j in 0..(m + n) {
                        aug[row][j] = aug[row][j] - factor * aug[pivot_row][j];
                    }
                }
            }

            pivot_row += 1;
        }

        // Check if we have a valid solution (first column should have a 1 in exactly one row)
        let mut found_row = None;
        for (i, row) in aug.iter().enumerate() {
            if !row[0].is_zero() {
                if row[0] == Fr::one() && found_row.is_none() {
                    found_row = Some(i);
                } else {
                    // Multiple non-zero entries in first column after elimination
                    return Err("Could not find unique reconstruction");
                }
            }
        }

        match found_row {
            Some(row_idx) => {
                // Verify the solution: check that this row has [1, 0, 0, ...]
                // (all columns after the first should be zero)
                for col in 1..m {
                    if !aug[row_idx][col].is_zero() {
                        return Err("Policy not satisfied - cannot reconstruct");
                    }
                }

                // Extract coefficients from augmented part
                for (i, sat_row) in satisfied_rows.iter().enumerate() {
                    let coeff = aug[row_idx][m + i];
                    if !coeff.is_zero() {
                        coeffs.insert(sat_row.attr.clone(), coeff);
                    }
                }
                Ok(coeffs)
            }
            None => Err("Policy not satisfied"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::thread_rng;

    #[test]
    fn test_single_attr() {
        let policy = PolicyNode::Attr("admin".to_string());
        let matrix = LsssMatrix::from_policy(&policy).unwrap();

        assert_eq!(matrix.rows.len(), 1);
        assert_eq!(matrix.rows[0].attr, "admin");
        assert_eq!(matrix.rows[0].vector[0], Fr::one());
    }

    #[test]
    fn test_or_policy() {
        let policy = PolicyNode::Or(vec![
            PolicyNode::Attr("a".to_string()),
            PolicyNode::Attr("b".to_string()),
        ]);
        let matrix = LsssMatrix::from_policy(&policy).unwrap();

        assert_eq!(matrix.rows.len(), 2);

        // Both should be able to reconstruct independently
        let mut rng = thread_rng();
        let secret = Fr::random(&mut rng);
        let shares = matrix.share_secret(&mut rng, secret);

        // Either attribute alone should work
        let coeffs_a = matrix.recover_coefficients(&["a".to_string()]).unwrap();
        assert!(coeffs_a.contains_key("a"));

        let coeffs_b = matrix.recover_coefficients(&["b".to_string()]).unwrap();
        assert!(coeffs_b.contains_key("b"));
    }

    #[test]
    fn test_and_policy() {
        let policy = PolicyNode::And(vec![
            PolicyNode::Attr("a".to_string()),
            PolicyNode::Attr("b".to_string()),
        ]);
        let matrix = LsssMatrix::from_policy(&policy).unwrap();

        assert_eq!(matrix.rows.len(), 2);

        let mut rng = thread_rng();
        let secret = Fr::random(&mut rng);
        let shares = matrix.share_secret(&mut rng, secret);

        // Both attributes needed
        let coeffs = matrix.recover_coefficients(&["a".to_string(), "b".to_string()]).unwrap();

        // Verify reconstruction
        let mut reconstructed = Fr::zero();
        for share in &shares {
            if let Some(coeff) = coeffs.get(&share.attr) {
                reconstructed = reconstructed + (*coeff * share.share);
            }
        }
        assert_eq!(reconstructed, secret);

        // Single attribute should fail
        assert!(matrix.recover_coefficients(&["a".to_string()]).is_err());
    }

    #[test]
    fn test_reconstruction() {
        let policy = PolicyNode::Or(vec![
            PolicyNode::Attr("a".to_string()),
            PolicyNode::Attr("b".to_string()),
        ]);
        let matrix = LsssMatrix::from_policy(&policy).unwrap();

        let mut rng = thread_rng();
        let secret = Fr::random(&mut rng);
        let shares = matrix.share_secret(&mut rng, secret);

        // Reconstruct with just "a"
        let coeffs = matrix.recover_coefficients(&["a".to_string()]).unwrap();
        let mut reconstructed = Fr::zero();
        for share in &shares {
            if let Some(coeff) = coeffs.get(&share.attr) {
                reconstructed = reconstructed + (*coeff * share.share);
            }
        }
        assert_eq!(reconstructed, secret);
    }

    #[test]
    fn test_canonical_string() {
        let policy = PolicyNode::And(vec![
            PolicyNode::Attr("b".to_string()),
            PolicyNode::Attr("a".to_string()),
        ]);
        let canonical = policy.to_canonical_string();
        assert_eq!(canonical, "(a and b)"); // Should be sorted
    }

    #[test]
    fn test_batch_inverse() {
        let mut rng = thread_rng();

        // Test empty input
        assert_eq!(batch_inverse(&[]), Some(vec![]));

        // Test single element
        let a = Fr::random(&mut rng);
        let result = batch_inverse(&[a]).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(a * result[0], Fr::one());

        // Test multiple elements
        let values: Vec<Fr> = (0..5).map(|_| Fr::random(&mut rng)).collect();
        let inverses = batch_inverse(&values).unwrap();
        assert_eq!(inverses.len(), 5);
        for (v, inv) in values.iter().zip(inverses.iter()) {
            assert_eq!(*v * *inv, Fr::one());
        }

        // Test with zero should return None
        let with_zero = vec![Fr::random(&mut rng), Fr::zero(), Fr::random(&mut rng)];
        assert!(batch_inverse(&with_zero).is_none());
    }

    #[test]
    fn test_can_satisfy() {
        use std::collections::HashSet;

        // Single attribute
        let policy = PolicyNode::Attr("admin".to_string());
        let attrs: HashSet<String> = ["admin".to_string()].into_iter().collect();
        assert!(policy.can_satisfy(&attrs));

        let empty: HashSet<String> = HashSet::new();
        assert!(!policy.can_satisfy(&empty));

        // AND policy
        let and_policy = PolicyNode::And(vec![
            PolicyNode::Attr("a".to_string()),
            PolicyNode::Attr("b".to_string()),
        ]);
        let only_a: HashSet<String> = ["a".to_string()].into_iter().collect();
        let both: HashSet<String> = ["a".to_string(), "b".to_string()].into_iter().collect();
        assert!(!and_policy.can_satisfy(&only_a));
        assert!(and_policy.can_satisfy(&both));

        // OR policy
        let or_policy = PolicyNode::Or(vec![
            PolicyNode::Attr("a".to_string()),
            PolicyNode::Attr("b".to_string()),
        ]);
        assert!(or_policy.can_satisfy(&only_a));
        assert!(or_policy.can_satisfy(&both));

        // Threshold policy (2 of 3)
        let threshold = PolicyNode::Threshold(2, vec![
            PolicyNode::Attr("a".to_string()),
            PolicyNode::Attr("b".to_string()),
            PolicyNode::Attr("c".to_string()),
        ]);
        let ab: HashSet<String> = ["a".to_string(), "b".to_string()].into_iter().collect();
        assert!(threshold.can_satisfy(&ab));
        assert!(!threshold.can_satisfy(&only_a));
    }
}
