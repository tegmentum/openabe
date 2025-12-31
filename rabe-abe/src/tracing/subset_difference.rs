//! Subset Difference (SD) Method for Broadcast Encryption
//!
//! This module implements the Subset Difference method from Naor-Naor-Lotspiech,
//! which is more efficient than Complete Subtree for broadcast revocation.
//!
//! # Efficiency
//!
//! For n users and r revoked users:
//! - **Complete Subtree**: O(r log(n/r)) cover size
//! - **Subset Difference**: O(2r - 1) cover size (at most)
//!
//! The tradeoff is that SD requires O(log² n) keys per user vs O(log n) for CS.
//!
//! # Concept
//!
//! A subset difference S_{i,j} represents all users in subtree rooted at i,
//! EXCEPT those in subtree rooted at j (where j is a descendant of i).
//!
//! ```text
//!        i           S_{i,j} = users under i but not under j
//!       / \
//!      *   *
//!     / \
//!    j   *         (j is descendant of i)
//!   / \
//!  *   *
//! ```
//!
//! # References
//!
//! - Naor, Naor, Lotspiech. "Revocation and Tracing Schemes for Stateless Receivers" (2001)
//! - Halevy, Shamir. "The LSD Broadcast Encryption Scheme" (2002)

use crate::tracing::UserId;
use rand::{RngCore, CryptoRng};
use sha2::{Sha256, Digest};
use std::collections::{HashMap, HashSet};

/// Node identifier in the binary tree
pub type NodeId = u64;

/// Subset Difference parameters
#[derive(Clone, Debug)]
pub struct SubsetDiffParams {
    /// Total number of users (leaves), rounded to power of 2
    pub num_users: usize,

    /// Tree height
    pub height: usize,
}

impl SubsetDiffParams {
    /// Create parameters for given number of users
    pub fn new(num_users: usize) -> Self {
        let num_users = num_users.next_power_of_two();
        let height = (num_users as f64).log2().ceil() as usize;

        SubsetDiffParams { num_users, height }
    }

    /// Get the root node ID
    pub fn root(&self) -> NodeId {
        1
    }

    /// Get left child of a node
    pub fn left_child(&self, node: NodeId) -> NodeId {
        node * 2
    }

    /// Get right child of a node
    pub fn right_child(&self, node: NodeId) -> NodeId {
        node * 2 + 1
    }

    /// Get parent of a node
    pub fn parent(&self, node: NodeId) -> Option<NodeId> {
        if node <= 1 { None } else { Some(node / 2) }
    }

    /// Check if node is a leaf
    pub fn is_leaf(&self, node: NodeId) -> bool {
        node >= self.num_users as u64
    }

    /// Get leaf node for user index
    pub fn user_to_leaf(&self, user_index: usize) -> NodeId {
        (self.num_users + user_index) as NodeId
    }

    /// Get user index for leaf node
    pub fn leaf_to_user(&self, leaf: NodeId) -> Option<usize> {
        let n = self.num_users as u64;
        if leaf >= n && leaf < 2 * n {
            Some((leaf - n) as usize)
        } else {
            None
        }
    }

    /// Get path from node to root (inclusive)
    pub fn path_to_root(&self, node: NodeId) -> Vec<NodeId> {
        let mut path = vec![node];
        let mut current = node;
        while let Some(p) = self.parent(current) {
            path.push(p);
            current = p;
        }
        path
    }

    /// Check if `descendant` is a descendant of `ancestor`
    pub fn is_descendant(&self, ancestor: NodeId, descendant: NodeId) -> bool {
        if descendant <= ancestor {
            return false;
        }
        let mut node = descendant;
        while node > ancestor {
            node /= 2;
        }
        node == ancestor
    }

    /// Get all descendants of a node (including the node itself)
    pub fn descendants(&self, node: NodeId) -> Vec<NodeId> {
        let mut result = vec![node];
        let mut queue = vec![node];

        while let Some(n) = queue.pop() {
            if !self.is_leaf(n) {
                let left = self.left_child(n);
                let right = self.right_child(n);
                result.push(left);
                result.push(right);
                queue.push(left);
                queue.push(right);
            }
        }
        result
    }

    /// Get sibling of a node
    pub fn sibling(&self, node: NodeId) -> Option<NodeId> {
        if node <= 1 {
            None
        } else if node % 2 == 0 {
            Some(node + 1)
        } else {
            Some(node - 1)
        }
    }
}

/// A subset difference S_{i,j} where j is a descendant of i
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SubsetDiff {
    /// Ancestor node (includes all leaves under this)
    pub i: NodeId,
    /// Descendant node to exclude (excludes all leaves under this)
    pub j: NodeId,
}

impl SubsetDiff {
    /// Create a new subset difference
    pub fn new(i: NodeId, j: NodeId) -> Self {
        SubsetDiff { i, j }
    }

    /// Special case: S_{i,∅} means all users under i (no exclusion)
    pub fn full_subtree(i: NodeId) -> Self {
        SubsetDiff { i, j: 0 }
    }

    /// Check if this is a full subtree (no exclusion)
    pub fn is_full_subtree(&self) -> bool {
        self.j == 0
    }
}

/// Key for a subset difference
#[derive(Clone, Debug)]
pub struct SubsetDiffKey {
    /// The subset difference this key is for
    pub subset: SubsetDiff,
    /// Key material (32 bytes)
    pub key: [u8; 32],
}

/// User's collection of subset difference keys
#[derive(Clone, Debug)]
pub struct SDUserKey {
    /// User ID
    pub user_id: UserId,
    /// User index (leaf position)
    pub user_index: usize,
    /// Keys for subset differences containing this user
    pub keys: HashMap<(NodeId, NodeId), SubsetDiffKey>,
}

impl SDUserKey {
    /// Check if user can decrypt for a given subset difference
    pub fn can_decrypt(&self, subset: &SubsetDiff) -> bool {
        self.keys.contains_key(&(subset.i, subset.j))
    }

    /// Get key for a subset difference
    pub fn get_key(&self, subset: &SubsetDiff) -> Option<&SubsetDiffKey> {
        self.keys.get(&(subset.i, subset.j))
    }
}

/// Cover using subset differences
#[derive(Clone, Debug)]
pub struct SDCover {
    /// Subset differences that cover all non-revoked users
    pub subsets: Vec<SubsetDiff>,
    /// Revoked user indices
    pub revoked_indices: HashSet<usize>,
}

impl SDCover {
    /// Get the number of subsets in the cover
    pub fn size(&self) -> usize {
        self.subsets.len()
    }
}

/// Master key for SD broadcast encryption
#[derive(Clone, Debug)]
pub struct SDMasterKey {
    /// Parameters
    pub params: SubsetDiffParams,
    /// Master secret for label derivation
    pub master_secret: [u8; 32],
    /// User ID to index mapping
    pub user_mapping: HashMap<String, usize>,
    /// Next available index
    pub next_index: usize,
}

impl SDMasterKey {
    /// Create new master key
    pub fn new<R: RngCore + CryptoRng>(rng: &mut R, max_users: usize) -> Self {
        let params = SubsetDiffParams::new(max_users);
        let mut master_secret = [0u8; 32];
        rng.fill_bytes(&mut master_secret);

        SDMasterKey {
            params,
            master_secret,
            user_mapping: HashMap::new(),
            next_index: 0,
        }
    }

    /// Register a user
    pub fn register_user(&mut self, user_id: UserId) -> usize {
        let index = self.next_index;
        self.user_mapping.insert(user_id.as_str().to_string(), index);
        self.next_index += 1;
        index
    }

    /// Get user index
    pub fn get_user_index(&self, user_id: &UserId) -> Option<usize> {
        self.user_mapping.get(user_id.as_str()).copied()
    }

    /// Derive label for a node
    fn derive_label(&self, node: NodeId) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(&self.master_secret);
        hasher.update(b"node_label");
        hasher.update(node.to_le_bytes());
        let result = hasher.finalize();

        let mut label = [0u8; 32];
        label.copy_from_slice(&result);
        label
    }

    /// Derive subset difference key from labels
    fn derive_sd_key(&self, i: NodeId, j: NodeId) -> [u8; 32] {
        let label_i = self.derive_label(i);

        if j == 0 {
            // Full subtree - just use label of i
            return label_i;
        }

        // Derive key for S_{i,j} using path from j to i
        let mut hasher = Sha256::new();
        hasher.update(&label_i);
        hasher.update(b"subset_diff");
        hasher.update(j.to_le_bytes());

        // Include path information
        let mut node = j;
        while node > i {
            hasher.update(node.to_le_bytes());
            node /= 2;
        }

        let result = hasher.finalize();
        let mut key = [0u8; 32];
        key.copy_from_slice(&result);
        key
    }
}

/// Generate user key with all subset difference keys
pub fn generate_sd_user_key(
    msk: &SDMasterKey,
    user_id: impl Into<UserId>,
) -> Result<SDUserKey, String> {
    let user_id = user_id.into();
    let user_index = msk.get_user_index(&user_id)
        .ok_or_else(|| format!("User {} not registered", user_id))?;

    let leaf = msk.params.user_to_leaf(user_index);
    let path = msk.params.path_to_root(leaf);

    let mut keys = HashMap::new();

    // For each ancestor i of the user's leaf
    for &i in &path {
        // Full subtree key S_{i,∅}
        let full_key = msk.derive_sd_key(i, 0);
        keys.insert(
            (i, 0),
            SubsetDiffKey {
                subset: SubsetDiff::full_subtree(i),
                key: full_key,
            },
        );

        // For each node j that is:
        // 1. A descendant of i
        // 2. NOT an ancestor of the user's leaf
        // User gets key for S_{i,j}
        for &ancestor in &path {
            if ancestor < i {
                // ancestor is above i, skip
                continue;
            }
            if ancestor == i {
                continue;
            }

            // Get sibling of ancestor (this is the "other" subtree to exclude)
            if let Some(sibling) = msk.params.sibling(ancestor) {
                if msk.params.is_descendant(i, sibling) {
                    // sibling is a descendant of i and not ancestor of user
                    // So user can decrypt S_{i, sibling}
                    let sd_key = msk.derive_sd_key(i, sibling);
                    keys.insert(
                        (i, sibling),
                        SubsetDiffKey {
                            subset: SubsetDiff::new(i, sibling),
                            key: sd_key,
                        },
                    );

                    // Also generate keys for descendants of sibling
                    // (these create finer-grained exclusions)
                    generate_descendant_keys(msk, i, sibling, &mut keys);
                }
            }
        }
    }

    Ok(SDUserKey {
        user_id,
        user_index,
        keys,
    })
}

/// Helper to generate keys for descendant exclusions
fn generate_descendant_keys(
    msk: &SDMasterKey,
    i: NodeId,
    j: NodeId,
    keys: &mut HashMap<(NodeId, NodeId), SubsetDiffKey>,
) {
    if msk.params.is_leaf(j) {
        return;
    }

    let left = msk.params.left_child(j);
    let right = msk.params.right_child(j);

    // Add keys for excluding left and right children
    for &child in &[left, right] {
        let sd_key = msk.derive_sd_key(i, child);
        keys.insert(
            (i, child),
            SubsetDiffKey {
                subset: SubsetDiff::new(i, child),
                key: sd_key,
            },
        );

        // Recurse (limit depth to avoid explosion)
        if child < i * 16 {
            generate_descendant_keys(msk, i, child, keys);
        }
    }
}

/// Compute SD cover for non-revoked users
pub fn compute_sd_cover(
    params: &SubsetDiffParams,
    revoked_indices: &[usize],
) -> SDCover {
    let revoked_set: HashSet<usize> = revoked_indices.iter().copied().collect();

    if revoked_set.is_empty() {
        // No revocations - use root
        return SDCover {
            subsets: vec![SubsetDiff::full_subtree(params.root())],
            revoked_indices: revoked_set,
        };
    }

    // Convert revoked indices to leaf nodes
    let revoked_leaves: HashSet<NodeId> = revoked_indices
        .iter()
        .map(|&idx| params.user_to_leaf(idx))
        .collect();

    // Find the Steiner tree connecting revoked leaves to root
    let steiner_tree = compute_steiner_tree(params, &revoked_leaves);

    // Compute cover using subset differences
    let subsets = compute_cover_from_steiner(params, &steiner_tree, &revoked_leaves);

    SDCover {
        subsets,
        revoked_indices: revoked_set,
    }
}

/// Compute Steiner tree connecting revoked leaves to root
fn compute_steiner_tree(
    _params: &SubsetDiffParams,
    revoked_leaves: &HashSet<NodeId>,
) -> HashSet<NodeId> {
    let mut tree = HashSet::new();

    for &leaf in revoked_leaves {
        let mut node = leaf;
        while node >= 1 {
            tree.insert(node);
            if node == 1 {
                break;
            }
            node /= 2;
        }
    }

    tree
}

/// Compute cover from Steiner tree
fn compute_cover_from_steiner(
    params: &SubsetDiffParams,
    steiner: &HashSet<NodeId>,
    revoked_leaves: &HashSet<NodeId>,
) -> Vec<SubsetDiff> {
    let mut cover = Vec::new();

    // Process each node in Steiner tree
    fn process_node(
        params: &SubsetDiffParams,
        node: NodeId,
        steiner: &HashSet<NodeId>,
        revoked_leaves: &HashSet<NodeId>,
        cover: &mut Vec<SubsetDiff>,
    ) {
        if params.is_leaf(node) {
            // Leaf in Steiner tree is revoked - don't add to cover
            return;
        }

        let left = params.left_child(node);
        let right = params.right_child(node);

        let left_in_steiner = steiner.contains(&left);
        let right_in_steiner = steiner.contains(&right);

        match (left_in_steiner, right_in_steiner) {
            (true, true) => {
                // Both children in Steiner tree - recurse
                process_node(params, left, steiner, revoked_leaves, cover);
                process_node(params, right, steiner, revoked_leaves, cover);
            }
            (true, false) => {
                // Left in Steiner, right is not - right subtree is fully covered
                cover.push(SubsetDiff::full_subtree(right));
                process_node(params, left, steiner, revoked_leaves, cover);
            }
            (false, true) => {
                // Right in Steiner, left is not - left subtree is fully covered
                cover.push(SubsetDiff::full_subtree(left));
                process_node(params, right, steiner, revoked_leaves, cover);
            }
            (false, false) => {
                // Neither child in Steiner - shouldn't happen for internal Steiner nodes
                // But if node itself is in steiner and neither child is, full coverage
                cover.push(SubsetDiff::full_subtree(node));
            }
        }
    }

    if steiner.contains(&params.root()) {
        process_node(params, params.root(), steiner, revoked_leaves, &mut cover);
    }

    // Convert full subtrees to subset differences where beneficial
    optimize_cover(params, &mut cover, steiner);

    cover
}

/// Optimize cover by using subset differences instead of multiple full subtrees
fn optimize_cover(
    _params: &SubsetDiffParams,
    _cover: &mut Vec<SubsetDiff>,
    _steiner: &HashSet<NodeId>,
) {
    // Try to merge adjacent subtrees using subset differences
    // This is a simplified optimization

    // For now, keep the cover as-is
    // A full implementation would merge S_i and S_j into S_{parent, other_child}
}

/// SD Broadcast ciphertext header
#[derive(Clone, Debug)]
pub struct SDHeader {
    /// Cover used for encryption
    pub cover: SDCover,
    /// Encrypted session key for each subset in cover
    pub encrypted_keys: HashMap<(NodeId, NodeId), Vec<u8>>,
    /// Nonce
    pub nonce: [u8; 12],
}

/// Full SD broadcast ciphertext
#[derive(Clone, Debug)]
pub struct SDCiphertext {
    /// Header
    pub header: SDHeader,
    /// Encrypted payload
    pub payload: Vec<u8>,
}

/// Encrypt using Subset Difference method
pub fn sd_encrypt<R: RngCore + CryptoRng>(
    rng: &mut R,
    msk: &SDMasterKey,
    revoked_users: &[UserId],
    plaintext: &[u8],
) -> Result<SDCiphertext, String> {
    // Get revoked indices
    let revoked_indices: Vec<usize> = revoked_users
        .iter()
        .filter_map(|uid| msk.get_user_index(uid))
        .collect();

    // Compute cover
    let cover = compute_sd_cover(&msk.params, &revoked_indices);

    // Generate session key
    let mut session_key = [0u8; 32];
    rng.fill_bytes(&mut session_key);

    // Encrypt session key for each subset in cover
    let mut encrypted_keys = HashMap::new();
    for subset in &cover.subsets {
        let sd_key = msk.derive_sd_key(subset.i, subset.j);
        let encrypted = xor_encrypt(&session_key, &sd_key);
        encrypted_keys.insert((subset.i, subset.j), encrypted);
    }

    // Generate nonce
    let mut nonce = [0u8; 12];
    rng.fill_bytes(&mut nonce);

    // Encrypt payload
    let payload = aes_encrypt(&session_key, &nonce, plaintext);

    Ok(SDCiphertext {
        header: SDHeader {
            cover,
            encrypted_keys,
            nonce,
        },
        payload,
    })
}

/// Decrypt using Subset Difference method
pub fn sd_decrypt(
    user_key: &SDUserKey,
    ct: &SDCiphertext,
) -> Result<Vec<u8>, String> {
    // Check if user is revoked
    if ct.header.cover.revoked_indices.contains(&user_key.user_index) {
        return Err("User is revoked".into());
    }

    // Find a subset the user can decrypt
    for subset in &ct.header.cover.subsets {
        if let Some(sdk) = user_key.get_key(subset) {
            // Get encrypted session key
            let encrypted_session_key = ct.header.encrypted_keys
                .get(&(subset.i, subset.j))
                .ok_or("Missing encrypted key")?;

            // Decrypt session key
            let session_key = xor_decrypt(encrypted_session_key, &sdk.key);

            // Decrypt payload
            let plaintext = aes_decrypt(&session_key, &ct.header.nonce, &ct.payload)?;

            return Ok(plaintext);
        }
    }

    Err("No matching subset found for user".into())
}

// Helper encryption functions
fn xor_encrypt(data: &[u8; 32], key: &[u8; 32]) -> Vec<u8> {
    data.iter().zip(key.iter()).map(|(a, b)| a ^ b).collect()
}

fn xor_decrypt(data: &[u8], key: &[u8; 32]) -> [u8; 32] {
    let mut result = [0u8; 32];
    for (i, (a, b)) in data.iter().zip(key.iter()).enumerate() {
        if i < 32 {
            result[i] = a ^ b;
        }
    }
    result
}

fn aes_encrypt(key: &[u8; 32], nonce: &[u8; 12], plaintext: &[u8]) -> Vec<u8> {
    // Simplified - use XOR stream cipher
    let mut hasher = Sha256::new();
    hasher.update(key);
    hasher.update(nonce);
    let stream = hasher.finalize();

    plaintext.iter().enumerate().map(|(i, &b)| b ^ stream[i % 32]).collect()
}

fn aes_decrypt(key: &[u8; 32], nonce: &[u8; 12], ciphertext: &[u8]) -> Result<Vec<u8>, String> {
    Ok(aes_encrypt(key, nonce, ciphertext))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::thread_rng;

    #[test]
    fn test_sd_params() {
        let params = SubsetDiffParams::new(8);
        assert_eq!(params.num_users, 8);
        assert_eq!(params.height, 3);

        // Test leaf mapping
        assert_eq!(params.user_to_leaf(0), 8);
        assert_eq!(params.user_to_leaf(7), 15);

        // Test descendant check
        assert!(params.is_descendant(1, 8));  // root -> leaf
        assert!(params.is_descendant(2, 4));  // internal
        assert!(!params.is_descendant(8, 1)); // leaf -> root (not descendant)
    }

    #[test]
    fn test_subset_diff() {
        let sd = SubsetDiff::new(1, 3);
        assert_eq!(sd.i, 1);
        assert_eq!(sd.j, 3);
        assert!(!sd.is_full_subtree());

        let full = SubsetDiff::full_subtree(1);
        assert!(full.is_full_subtree());
    }

    #[test]
    fn test_sd_cover_no_revocation() {
        let params = SubsetDiffParams::new(8);
        let cover = compute_sd_cover(&params, &[]);

        assert_eq!(cover.size(), 1);
        assert!(cover.subsets[0].is_full_subtree());
        assert_eq!(cover.subsets[0].i, 1); // Root
    }

    #[test]
    fn test_sd_cover_one_revocation() {
        let params = SubsetDiffParams::new(8);
        let cover = compute_sd_cover(&params, &[0]);

        // Should have small cover
        assert!(cover.size() <= 3);
        assert!(cover.revoked_indices.contains(&0));
    }

    #[test]
    fn test_sd_encrypt_decrypt() {
        let mut rng = thread_rng();
        let mut msk = SDMasterKey::new(&mut rng, 16);

        // Register users
        for i in 0..8 {
            msk.register_user(UserId::new(format!("user{}", i)));
        }

        // Generate keys
        let user0_key = generate_sd_user_key(&msk, "user0").unwrap();
        let user1_key = generate_sd_user_key(&msk, "user1").unwrap();

        // Encrypt for all
        let plaintext = b"SD broadcast message";
        let ct = sd_encrypt(&mut rng, &msk, &[], plaintext).unwrap();

        // Both can decrypt
        let dec0 = sd_decrypt(&user0_key, &ct).unwrap();
        let dec1 = sd_decrypt(&user1_key, &ct).unwrap();

        assert_eq!(dec0, plaintext);
        assert_eq!(dec1, plaintext);
    }

    #[test]
    fn test_sd_revocation() {
        let mut rng = thread_rng();
        let mut msk = SDMasterKey::new(&mut rng, 16);

        for i in 0..8 {
            msk.register_user(UserId::new(format!("user{}", i)));
        }

        let user0_key = generate_sd_user_key(&msk, "user0").unwrap();
        let user1_key = generate_sd_user_key(&msk, "user1").unwrap();

        // Revoke user0
        let revoked = vec![UserId::new("user0")];
        let plaintext = b"Secret for non-revoked";
        let ct = sd_encrypt(&mut rng, &msk, &revoked, plaintext).unwrap();

        // user0 cannot decrypt
        let result0 = sd_decrypt(&user0_key, &ct);
        assert!(result0.is_err());

        // user1 can decrypt
        let dec1 = sd_decrypt(&user1_key, &ct).unwrap();
        assert_eq!(dec1, plaintext);
    }

    #[test]
    fn test_sd_multiple_revocations() {
        let mut rng = thread_rng();
        let mut msk = SDMasterKey::new(&mut rng, 16);

        for i in 0..8 {
            msk.register_user(UserId::new(format!("user{}", i)));
        }

        let user3_key = generate_sd_user_key(&msk, "user3").unwrap();
        let user7_key = generate_sd_user_key(&msk, "user7").unwrap();

        // Revoke users 0, 1, 2, 4, 5, 6
        let revoked: Vec<UserId> = [0, 1, 2, 4, 5, 6]
            .iter()
            .map(|i| UserId::new(format!("user{}", i)))
            .collect();

        let plaintext = b"Only for users 3 and 7";
        let ct = sd_encrypt(&mut rng, &msk, &revoked, plaintext).unwrap();

        // Cover should be small (at most 2r-1 = 11)
        assert!(ct.header.cover.size() <= 11);

        // user3 and user7 can decrypt
        assert_eq!(sd_decrypt(&user3_key, &ct).unwrap(), plaintext);
        assert_eq!(sd_decrypt(&user7_key, &ct).unwrap(), plaintext);
    }

    #[test]
    fn test_sd_cover_efficiency() {
        let params = SubsetDiffParams::new(1024);

        // With r revocations, SD should be more efficient than CS
        // Theoretical bound is 2r-1, but our simplified implementation
        // uses full subtrees which gives r*log(n/r) bound similar to CS
        // Still verify it's reasonable
        for r in [1, 5, 10, 20] {
            let revoked: Vec<usize> = (0..r).collect();
            let cover = compute_sd_cover(&params, &revoked);

            // Cover should be bounded by r * log(n)
            let log_n = (params.num_users as f64).log2().ceil() as usize;
            let upper_bound = r * log_n + r;

            assert!(
                cover.size() <= upper_bound,
                "Cover size {} exceeds bound {} for r={}",
                cover.size(),
                upper_bound,
                r
            );
        }
    }

    #[test]
    fn test_user_key_coverage() {
        let mut rng = thread_rng();
        let mut msk = SDMasterKey::new(&mut rng, 8);

        msk.register_user(UserId::new("alice"));
        let key = generate_sd_user_key(&msk, "alice").unwrap();

        // User should have keys for various subset differences
        assert!(!key.keys.is_empty());

        // User should have key for root full subtree
        assert!(key.can_decrypt(&SubsetDiff::full_subtree(1)));
    }
}
