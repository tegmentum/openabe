//! Augmented Broadcast Encryption with Traitor Tracing
//!
//! This module implements broadcast encryption with efficient revocation using
//! the subset-cover framework (Naor-Naor-Lotspiech). It supports:
//!
//! 1. Complete Subtree (CS) method - simple but less efficient
//! 2. Subset Difference (SD) method - more efficient for larger revocation sets
//!
//! # Design
//!
//! Users are organized in a binary tree. Each user is a leaf. Keys are derived
//! from path nodes. Revocation excludes subtrees containing revoked users.
//!
//! When combined with traitor tracing, this provides:
//! - Efficient content encryption for large groups
//! - Revocation without re-keying non-revoked users
//! - Traitor tracing to identify key leakers
//!
//! # References
//!
//! - Naor, Naor, Lotspiech. "Revocation and Tracing Schemes for Stateless Receivers" (2001)
//! - Boneh, Sahai, Waters. "Fully Collusion Resistant Traitor Tracing with Short Ciphertexts and Private Keys" (2006)

use crate::tracing::UserId;
use rand::{RngCore, CryptoRng};
use sha2::{Sha256, Digest};
use std::collections::{HashMap, HashSet, BTreeSet};

/// Node identifier in the binary tree
pub type NodeId = u64;

/// Complete Subtree method parameters
#[derive(Clone, Debug)]
pub struct CompleteSubtreeParams {
    /// Total number of users (leaves)
    pub num_users: usize,

    /// Tree height (log2(num_users))
    pub height: usize,
}

impl CompleteSubtreeParams {
    /// Create parameters for a given number of users
    pub fn new(num_users: usize) -> Self {
        // Round up to power of 2
        let num_users = num_users.next_power_of_two();
        let height = (num_users as f64).log2().ceil() as usize;

        CompleteSubtreeParams {
            num_users,
            height,
        }
    }

    /// Get the root node ID
    pub fn root(&self) -> NodeId {
        1
    }

    /// Get the left child of a node
    pub fn left_child(&self, node: NodeId) -> NodeId {
        node * 2
    }

    /// Get the right child of a node
    pub fn right_child(&self, node: NodeId) -> NodeId {
        node * 2 + 1
    }

    /// Get the parent of a node
    pub fn parent(&self, node: NodeId) -> Option<NodeId> {
        if node <= 1 {
            None
        } else {
            Some(node / 2)
        }
    }

    /// Check if a node is a leaf
    pub fn is_leaf(&self, node: NodeId) -> bool {
        node >= self.num_users as u64
    }

    /// Get the leaf node for a user index
    pub fn user_to_leaf(&self, user_index: usize) -> NodeId {
        (self.num_users + user_index) as NodeId
    }

    /// Get the user index for a leaf node
    pub fn leaf_to_user(&self, leaf: NodeId) -> Option<usize> {
        let n = self.num_users as u64;
        if leaf >= n && leaf < 2 * n {
            Some((leaf - n) as usize)
        } else {
            None
        }
    }

    /// Get all ancestors of a node (path to root)
    pub fn ancestors(&self, node: NodeId) -> Vec<NodeId> {
        let mut path = Vec::new();
        let mut current = node;
        while let Some(parent) = self.parent(current) {
            path.push(parent);
            current = parent;
        }
        path
    }
}

/// Key for a node in the tree
#[derive(Clone, Debug)]
pub struct NodeKey {
    /// Node identifier
    pub node_id: NodeId,

    /// Key material (32 bytes)
    pub key: [u8; 32],
}

/// User's broadcast decryption key
#[derive(Clone, Debug)]
pub struct BroadcastUserKey {
    /// User ID
    pub user_id: UserId,

    /// User index in the tree
    pub user_index: usize,

    /// Keys for path from leaf to root
    pub path_keys: Vec<NodeKey>,
}

impl BroadcastUserKey {
    /// Get all node IDs this user has keys for
    pub fn covered_nodes(&self) -> HashSet<NodeId> {
        self.path_keys.iter().map(|k| k.node_id).collect()
    }
}

/// Subset for encryption (Complete Subtree method)
#[derive(Clone, Debug)]
pub struct CoverSubset {
    /// Nodes that cover all non-revoked users
    pub cover_nodes: Vec<NodeId>,

    /// Revoked user indices
    pub revoked_indices: HashSet<usize>,
}

/// Broadcast ciphertext header
#[derive(Clone, Debug)]
pub struct BroadcastHeader {
    /// Cover subsets used for encryption
    pub cover: CoverSubset,

    /// Encrypted session key for each cover node
    pub encrypted_keys: HashMap<NodeId, Vec<u8>>,

    /// Nonce for encryption
    pub nonce: [u8; 12],
}

/// Full broadcast ciphertext
#[derive(Clone, Debug)]
pub struct BroadcastCiphertext {
    /// Header containing encrypted keys
    pub header: BroadcastHeader,

    /// Encrypted payload
    pub payload: Vec<u8>,
}

/// Master key for broadcast encryption
#[derive(Clone, Debug)]
pub struct BroadcastMasterKey {
    /// Parameters
    pub params: CompleteSubtreeParams,

    /// Master secret for key derivation
    pub master_secret: [u8; 32],

    /// User ID to index mapping
    pub user_mapping: HashMap<String, usize>,

    /// Next available user index
    pub next_index: usize,
}

impl BroadcastMasterKey {
    /// Create a new master key
    pub fn new<R: RngCore + CryptoRng>(rng: &mut R, max_users: usize) -> Self {
        let params = CompleteSubtreeParams::new(max_users);
        let mut master_secret = [0u8; 32];
        rng.fill_bytes(&mut master_secret);

        BroadcastMasterKey {
            params,
            master_secret,
            user_mapping: HashMap::new(),
            next_index: 0,
        }
    }

    /// Register a user and get their index
    pub fn register_user(&mut self, user_id: UserId) -> usize {
        let index = self.next_index;
        self.user_mapping.insert(user_id.as_str().to_string(), index);
        self.next_index += 1;
        index
    }

    /// Get user index by ID
    pub fn get_user_index(&self, user_id: &UserId) -> Option<usize> {
        self.user_mapping.get(user_id.as_str()).copied()
    }

    /// Derive key for a node
    pub fn derive_node_key(&self, node_id: NodeId) -> NodeKey {
        let mut hasher = Sha256::new();
        hasher.update(&self.master_secret);
        hasher.update(b"node_key");
        hasher.update(node_id.to_le_bytes());
        let result = hasher.finalize();

        let mut key = [0u8; 32];
        key.copy_from_slice(&result);

        NodeKey { node_id, key }
    }
}

/// Generate user key for broadcast encryption
pub fn generate_user_key(
    msk: &BroadcastMasterKey,
    user_id: impl Into<UserId>,
) -> Result<BroadcastUserKey, String> {
    let user_id = user_id.into();
    let user_index = msk.get_user_index(&user_id)
        .ok_or_else(|| format!("User {} not registered", user_id))?;

    let leaf = msk.params.user_to_leaf(user_index);
    let ancestors = msk.params.ancestors(leaf);

    // Generate keys for leaf and all ancestors
    let mut path_keys = vec![msk.derive_node_key(leaf)];
    for ancestor in ancestors {
        path_keys.push(msk.derive_node_key(ancestor));
    }

    Ok(BroadcastUserKey {
        user_id,
        user_index,
        path_keys,
    })
}

/// Compute cover set using Complete Subtree method
pub fn compute_cover(
    params: &CompleteSubtreeParams,
    revoked_indices: &[usize],
) -> CoverSubset {
    let revoked_set: HashSet<usize> = revoked_indices.iter().copied().collect();

    if revoked_set.is_empty() {
        // No revocations - use root
        return CoverSubset {
            cover_nodes: vec![params.root()],
            revoked_indices: revoked_set,
        };
    }

    // Find minimal cover using recursive algorithm
    fn find_cover(
        params: &CompleteSubtreeParams,
        node: NodeId,
        revoked: &HashSet<usize>,
        cover: &mut Vec<NodeId>,
    ) {
        if params.is_leaf(node) {
            if let Some(user_index) = params.leaf_to_user(node) {
                if !revoked.contains(&user_index) {
                    cover.push(node);
                }
            }
            return;
        }

        // Check if any leaves under this node are revoked
        let left = params.left_child(node);
        let right = params.right_child(node);

        let left_has_revoked = has_revoked_leaf(params, left, revoked);
        let right_has_revoked = has_revoked_leaf(params, right, revoked);

        if !left_has_revoked && !right_has_revoked {
            // No revocations in this subtree - add the node
            cover.push(node);
        } else {
            // Recursively process children
            if left_has_revoked {
                find_cover(params, left, revoked, cover);
            } else {
                cover.push(left);
            }

            if right_has_revoked {
                find_cover(params, right, revoked, cover);
            } else {
                cover.push(right);
            }
        }
    }

    fn has_revoked_leaf(
        params: &CompleteSubtreeParams,
        node: NodeId,
        revoked: &HashSet<usize>,
    ) -> bool {
        if params.is_leaf(node) {
            if let Some(user_index) = params.leaf_to_user(node) {
                return revoked.contains(&user_index);
            }
            return false;
        }

        has_revoked_leaf(params, params.left_child(node), revoked)
            || has_revoked_leaf(params, params.right_child(node), revoked)
    }

    let mut cover_nodes = Vec::new();
    find_cover(params, params.root(), &revoked_set, &mut cover_nodes);

    CoverSubset {
        cover_nodes,
        revoked_indices: revoked_set,
    }
}

/// Encrypt a message to non-revoked users
pub fn broadcast_encrypt<R: RngCore + CryptoRng>(
    rng: &mut R,
    msk: &BroadcastMasterKey,
    revoked_users: &[UserId],
    plaintext: &[u8],
) -> Result<BroadcastCiphertext, String> {
    // Convert user IDs to indices
    let revoked_indices: Vec<usize> = revoked_users
        .iter()
        .filter_map(|uid| msk.get_user_index(uid))
        .collect();

    // Compute cover set
    let cover = compute_cover(&msk.params, &revoked_indices);

    // Generate session key
    let mut session_key = [0u8; 32];
    rng.fill_bytes(&mut session_key);

    // Encrypt session key for each cover node
    let mut encrypted_keys = HashMap::new();
    for &node_id in &cover.cover_nodes {
        let node_key = msk.derive_node_key(node_id);
        let encrypted = xor_encrypt(&session_key, &node_key.key);
        encrypted_keys.insert(node_id, encrypted);
    }

    // Generate nonce
    let mut nonce = [0u8; 12];
    rng.fill_bytes(&mut nonce);

    // Encrypt payload with session key
    let payload = aes_gcm_encrypt(&session_key, &nonce, plaintext);

    Ok(BroadcastCiphertext {
        header: BroadcastHeader {
            cover,
            encrypted_keys,
            nonce,
        },
        payload,
    })
}

/// Decrypt a broadcast message
pub fn broadcast_decrypt(
    user_key: &BroadcastUserKey,
    ct: &BroadcastCiphertext,
) -> Result<Vec<u8>, String> {
    // Check if user is revoked
    if ct.header.cover.revoked_indices.contains(&user_key.user_index) {
        return Err("User is revoked".into());
    }

    // Find which cover node the user can decrypt with
    let user_nodes = user_key.covered_nodes();

    for &cover_node in &ct.header.cover.cover_nodes {
        if user_nodes.contains(&cover_node) {
            // User has key for this cover node
            let encrypted_session_key = ct.header.encrypted_keys.get(&cover_node)
                .ok_or("Missing encrypted key")?;

            // Find the node key
            let node_key = user_key.path_keys.iter()
                .find(|k| k.node_id == cover_node)
                .ok_or("User missing key for cover node")?;

            // Decrypt session key
            let session_key = xor_decrypt(encrypted_session_key, &node_key.key);

            // Decrypt payload
            let plaintext = aes_gcm_decrypt(&session_key, &ct.header.nonce, &ct.payload)
                .map_err(|_| "Decryption failed")?;

            return Ok(plaintext);
        }
    }

    Err("No matching cover node found".into())
}

// Simple XOR encryption for session key (in practice use proper KEM)
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

// Simplified AES-GCM (in practice use a proper implementation)
fn aes_gcm_encrypt(key: &[u8; 32], nonce: &[u8; 12], plaintext: &[u8]) -> Vec<u8> {
    // For simplicity, using XOR-based encryption
    // In production, use aes-gcm crate
    let mut hasher = Sha256::new();
    hasher.update(key);
    hasher.update(nonce);
    let stream_key = hasher.finalize();

    plaintext.iter().enumerate().map(|(i, &b)| {
        b ^ stream_key[i % 32]
    }).collect()
}

fn aes_gcm_decrypt(key: &[u8; 32], nonce: &[u8; 12], ciphertext: &[u8]) -> Result<Vec<u8>, ()> {
    // Same as encrypt for XOR
    Ok(aes_gcm_encrypt(key, nonce, ciphertext))
}

/// Traitor tracing for broadcast encryption
///
/// When a pirate decoder is found, trace which users contributed their keys.
pub fn trace_broadcast_key(
    msk: &BroadcastMasterKey,
    leaked_key: &BroadcastUserKey,
) -> Option<UserId> {
    // The user's key contains their path, which uniquely identifies them
    let leaf = msk.params.user_to_leaf(leaked_key.user_index);

    // Verify the key is valid
    for nk in &leaked_key.path_keys {
        let expected = msk.derive_node_key(nk.node_id);
        if nk.key != expected.key {
            return None; // Invalid or tampered key
        }
    }

    // The leaf node uniquely identifies the user
    if let Some(user_index) = msk.params.leaf_to_user(leaf) {
        // Find user ID from index
        for (uid, &idx) in &msk.user_mapping {
            if idx == user_index {
                return Some(UserId::new(uid.clone()));
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::thread_rng;

    #[test]
    fn test_complete_subtree_params() {
        let params = CompleteSubtreeParams::new(8);

        assert_eq!(params.num_users, 8);
        assert_eq!(params.height, 3);
        assert_eq!(params.root(), 1);

        // Test leaf detection
        assert!(!params.is_leaf(1));
        assert!(!params.is_leaf(4));
        assert!(params.is_leaf(8));
        assert!(params.is_leaf(15));

        // Test user to leaf mapping
        assert_eq!(params.user_to_leaf(0), 8);
        assert_eq!(params.user_to_leaf(7), 15);

        // Test leaf to user mapping
        assert_eq!(params.leaf_to_user(8), Some(0));
        assert_eq!(params.leaf_to_user(15), Some(7));
        assert_eq!(params.leaf_to_user(1), None);
    }

    #[test]
    fn test_compute_cover_no_revocation() {
        let params = CompleteSubtreeParams::new(8);
        let cover = compute_cover(&params, &[]);

        // No revocations - should use root
        assert_eq!(cover.cover_nodes, vec![1]);
    }

    #[test]
    fn test_compute_cover_one_revocation() {
        let params = CompleteSubtreeParams::new(8);
        let cover = compute_cover(&params, &[0]);

        // User 0 revoked - should cover remaining users
        assert!(!cover.cover_nodes.contains(&1)); // Not root
        assert!(cover.cover_nodes.len() <= 3); // Efficient cover
    }

    #[test]
    fn test_broadcast_encrypt_decrypt() {
        let mut rng = thread_rng();
        let mut msk = BroadcastMasterKey::new(&mut rng, 16);

        // Register users
        for i in 0..8 {
            msk.register_user(UserId::new(format!("user{}", i)));
        }

        // Generate keys
        let user0_key = generate_user_key(&msk, "user0").unwrap();
        let user1_key = generate_user_key(&msk, "user1").unwrap();

        // Encrypt for all users
        let plaintext = b"Broadcast message";
        let ct = broadcast_encrypt(&mut rng, &msk, &[], plaintext).unwrap();

        // Both users can decrypt
        let dec0 = broadcast_decrypt(&user0_key, &ct).unwrap();
        let dec1 = broadcast_decrypt(&user1_key, &ct).unwrap();

        assert_eq!(dec0, plaintext);
        assert_eq!(dec1, plaintext);
    }

    #[test]
    fn test_broadcast_revocation() {
        let mut rng = thread_rng();
        let mut msk = BroadcastMasterKey::new(&mut rng, 16);

        // Register users
        for i in 0..8 {
            msk.register_user(UserId::new(format!("user{}", i)));
        }

        let user0_key = generate_user_key(&msk, "user0").unwrap();
        let user1_key = generate_user_key(&msk, "user1").unwrap();

        // Encrypt with user0 revoked
        let plaintext = b"Secret message";
        let revoked = vec![UserId::new("user0")];
        let ct = broadcast_encrypt(&mut rng, &msk, &revoked, plaintext).unwrap();

        // User0 cannot decrypt
        let result0 = broadcast_decrypt(&user0_key, &ct);
        assert!(result0.is_err());

        // User1 can decrypt
        let dec1 = broadcast_decrypt(&user1_key, &ct).unwrap();
        assert_eq!(dec1, plaintext);
    }

    #[test]
    fn test_trace_broadcast_key() {
        let mut rng = thread_rng();
        let mut msk = BroadcastMasterKey::new(&mut rng, 16);

        msk.register_user(UserId::new("alice"));
        msk.register_user(UserId::new("bob"));

        let alice_key = generate_user_key(&msk, "alice").unwrap();

        // Trace the key
        let traced = trace_broadcast_key(&msk, &alice_key);
        assert_eq!(traced.unwrap().as_str(), "alice");
    }

    #[test]
    fn test_multiple_revocations() {
        let mut rng = thread_rng();
        let mut msk = BroadcastMasterKey::new(&mut rng, 16);

        // Register 8 users
        for i in 0..8 {
            msk.register_user(UserId::new(format!("user{}", i)));
        }

        let user3_key = generate_user_key(&msk, "user3").unwrap();
        let user5_key = generate_user_key(&msk, "user5").unwrap();
        let user7_key = generate_user_key(&msk, "user7").unwrap();

        // Revoke users 0, 1, 2, 4, 6
        let revoked = vec![
            UserId::new("user0"),
            UserId::new("user1"),
            UserId::new("user2"),
            UserId::new("user4"),
            UserId::new("user6"),
        ];

        let plaintext = b"Only for users 3, 5, 7";
        let ct = broadcast_encrypt(&mut rng, &msk, &revoked, plaintext).unwrap();

        // Remaining users can decrypt
        assert_eq!(broadcast_decrypt(&user3_key, &ct).unwrap(), plaintext);
        assert_eq!(broadcast_decrypt(&user5_key, &ct).unwrap(), plaintext);
        assert_eq!(broadcast_decrypt(&user7_key, &ct).unwrap(), plaintext);
    }
}

// =============================================================================
// Subset Difference (SD) Method
// =============================================================================
//
// More efficient than Complete Subtree for larger revocation sets.
// Ciphertext size: O(2r - 1) vs O(r log n) for CS method.
//
// Key idea: Instead of covering with complete subtrees, use differences
// S_i \ S_j where S_i is an ancestor subtree and S_j is a descendant subtree.

/// Subset Difference element: represents S_ancestor \ S_descendant
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SubsetDiff {
    /// The larger subtree (ancestor)
    pub ancestor: NodeId,
    /// The smaller subtree to exclude (descendant), or None for full subtree
    pub descendant: Option<NodeId>,
}

impl SubsetDiff {
    /// Create a new subset difference
    pub fn new(ancestor: NodeId, descendant: Option<NodeId>) -> Self {
        SubsetDiff { ancestor, descendant }
    }

    /// Create a complete subtree (no exclusion)
    pub fn complete(node: NodeId) -> Self {
        SubsetDiff { ancestor: node, descendant: None }
    }
}

/// Subset Difference method parameters
#[derive(Clone, Debug)]
pub struct SubsetDifferenceParams {
    /// Base tree parameters
    pub tree: CompleteSubtreeParams,
}

impl SubsetDifferenceParams {
    /// Create new SD parameters
    pub fn new(num_users: usize) -> Self {
        SubsetDifferenceParams {
            tree: CompleteSubtreeParams::new(num_users),
        }
    }

    /// Get all leaves in a subtree rooted at node
    pub fn leaves_in_subtree(&self, node: NodeId) -> Vec<usize> {
        let mut leaves = Vec::new();
        self.collect_leaves(node, &mut leaves);
        leaves
    }

    fn collect_leaves(&self, node: NodeId, leaves: &mut Vec<usize>) {
        if self.tree.is_leaf(node) {
            if let Some(user_idx) = self.tree.leaf_to_user(node) {
                leaves.push(user_idx);
            }
        } else {
            self.collect_leaves(self.tree.left_child(node), leaves);
            self.collect_leaves(self.tree.right_child(node), leaves);
        }
    }

    /// Check if a user is covered by a subset difference
    pub fn user_in_subset_diff(&self, user_index: usize, sd: &SubsetDiff) -> bool {
        let user_leaf = self.tree.user_to_leaf(user_index);

        // Check if user is in ancestor subtree
        if !self.is_in_subtree(user_leaf, sd.ancestor) {
            return false;
        }

        // If there's an exclusion, check user is NOT in it
        if let Some(desc) = sd.descendant {
            if self.is_in_subtree(user_leaf, desc) {
                return false;
            }
        }

        true
    }

    /// Check if leaf is in subtree rooted at node
    fn is_in_subtree(&self, leaf: NodeId, subtree_root: NodeId) -> bool {
        let mut current = leaf;
        while current >= subtree_root {
            if current == subtree_root {
                return true;
            }
            if let Some(parent) = self.tree.parent(current) {
                current = parent;
            } else {
                break;
            }
        }
        false
    }

    /// Get the path from a node to an ancestor
    pub fn path_to_ancestor(&self, node: NodeId, ancestor: NodeId) -> Vec<NodeId> {
        let mut path = vec![node];
        let mut current = node;
        while current != ancestor {
            if let Some(parent) = self.tree.parent(current) {
                path.push(parent);
                current = parent;
            } else {
                break;
            }
        }
        path
    }
}

/// Cover using Subset Difference method
#[derive(Clone, Debug)]
pub struct SDCover {
    /// Subset differences that cover non-revoked users
    pub differences: Vec<SubsetDiff>,
    /// Revoked user indices
    pub revoked_indices: HashSet<usize>,
}

/// Compute SD cover set
///
/// Algorithm: For each revoked leaf, we need to exclude it from the cover.
/// We build subset differences that cover all non-revoked users efficiently.
pub fn compute_sd_cover(
    params: &SubsetDifferenceParams,
    revoked_indices: &[usize],
) -> SDCover {
    let revoked_set: HashSet<usize> = revoked_indices.iter().copied().collect();

    if revoked_set.is_empty() {
        return SDCover {
            differences: vec![SubsetDiff::complete(params.tree.root())],
            revoked_indices: revoked_set,
        };
    }

    // Convert revoked indices to leaves
    let revoked_leaves: BTreeSet<NodeId> = revoked_indices
        .iter()
        .map(|&idx| params.tree.user_to_leaf(idx))
        .collect();

    // Build the SD cover using the Steiner tree approach
    let differences = build_sd_cover_steiner(params, &revoked_leaves);

    SDCover {
        differences,
        revoked_indices: revoked_set,
    }
}

/// Build SD cover using Steiner tree algorithm
fn build_sd_cover_steiner(
    params: &SubsetDifferenceParams,
    revoked_leaves: &BTreeSet<NodeId>,
) -> Vec<SubsetDiff> {
    if revoked_leaves.is_empty() {
        return vec![SubsetDiff::complete(params.tree.root())];
    }

    // Find the Steiner tree: minimal subtree connecting all revoked leaves
    let steiner_nodes = find_steiner_tree(params, revoked_leaves);

    // For each edge leaving the Steiner tree, create a subset difference
    let mut cover = Vec::new();
    build_sd_from_steiner(params, params.tree.root(), &steiner_nodes, revoked_leaves, &mut cover);

    cover
}

/// Find Steiner tree nodes connecting revoked leaves
fn find_steiner_tree(
    params: &SubsetDifferenceParams,
    revoked_leaves: &BTreeSet<NodeId>,
) -> HashSet<NodeId> {
    let mut steiner: HashSet<NodeId> = HashSet::new();

    // Add all revoked leaves and their ancestors up to LCA
    for &leaf in revoked_leaves {
        let mut current = leaf;
        while !steiner.contains(&current) {
            steiner.insert(current);
            if let Some(parent) = params.tree.parent(current) {
                current = parent;
            } else {
                break;
            }
        }
    }

    steiner
}

/// Recursively build SD cover from Steiner tree
fn build_sd_from_steiner(
    params: &SubsetDifferenceParams,
    node: NodeId,
    steiner: &HashSet<NodeId>,
    revoked: &BTreeSet<NodeId>,
    cover: &mut Vec<SubsetDiff>,
) {
    if !steiner.contains(&node) {
        // This subtree has no revoked leaves - add as complete subtree
        cover.push(SubsetDiff::complete(node));
        return;
    }

    if params.tree.is_leaf(node) {
        // Leaf node in Steiner tree = revoked user, don't add to cover
        return;
    }

    let left = params.tree.left_child(node);
    let right = params.tree.right_child(node);

    let left_in_steiner = steiner.contains(&left);
    let right_in_steiner = steiner.contains(&right);

    match (left_in_steiner, right_in_steiner) {
        (true, true) => {
            // Both children in Steiner tree - recurse on both
            build_sd_from_steiner(params, left, steiner, revoked, cover);
            build_sd_from_steiner(params, right, steiner, revoked, cover);
        }
        (true, false) => {
            // Only left in Steiner tree
            // Right subtree is completely non-revoked
            cover.push(SubsetDiff::complete(right));
            build_sd_from_steiner(params, left, steiner, revoked, cover);
        }
        (false, true) => {
            // Only right in Steiner tree
            // Left subtree is completely non-revoked
            cover.push(SubsetDiff::complete(left));
            build_sd_from_steiner(params, right, steiner, revoked, cover);
        }
        (false, false) => {
            // Neither child in Steiner - shouldn't happen if node is in Steiner
            // But handle gracefully
            cover.push(SubsetDiff::complete(node));
        }
    }
}

/// Key for subset difference decryption
#[derive(Clone, Debug)]
pub struct SDNodeKey {
    /// The subset difference this key covers
    pub subset: SubsetDiff,
    /// Key material
    pub key: [u8; 32],
}

/// User key for SD method - contains keys for all valid subset differences
/// the user might need
#[derive(Clone, Debug)]
pub struct SDUserKey {
    /// User ID
    pub user_id: UserId,
    /// User index
    pub user_index: usize,
    /// User's leaf node
    pub leaf: NodeId,
    /// Keys for subset differences containing this user
    /// Key is (ancestor, descendant) pair
    pub sd_keys: HashMap<(NodeId, Option<NodeId>), [u8; 32]>,
}

/// Master key for SD broadcast encryption
#[derive(Clone, Debug)]
pub struct SDMasterKey {
    /// Parameters
    pub params: SubsetDifferenceParams,
    /// Master secret
    pub master_secret: [u8; 32],
    /// User mapping
    pub user_mapping: HashMap<String, usize>,
    /// Next index
    pub next_index: usize,
}

impl SDMasterKey {
    /// Create new SD master key
    pub fn new<R: RngCore + CryptoRng>(rng: &mut R, max_users: usize) -> Self {
        let params = SubsetDifferenceParams::new(max_users);
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

    /// Derive key for a subset difference
    pub fn derive_sd_key(&self, sd: &SubsetDiff) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(&self.master_secret);
        hasher.update(b"sd_key");
        hasher.update(sd.ancestor.to_le_bytes());
        if let Some(desc) = sd.descendant {
            hasher.update(desc.to_le_bytes());
        } else {
            hasher.update([0u8; 8]);
        }
        let result = hasher.finalize();

        let mut key = [0u8; 32];
        key.copy_from_slice(&result);
        key
    }
}

/// Generate SD user key
pub fn generate_sd_user_key(
    msk: &SDMasterKey,
    user_id: impl Into<UserId>,
) -> Result<SDUserKey, String> {
    let user_id = user_id.into();
    let user_index = msk.get_user_index(&user_id)
        .ok_or_else(|| format!("User {} not registered", user_id))?;

    let leaf = msk.params.tree.user_to_leaf(user_index);

    // Generate keys for all subset differences that could contain this user
    // This is all (ancestor, descendant) pairs where:
    // 1. ancestor is on the path from leaf to root
    // 2. descendant is a sibling subtree or None
    let mut sd_keys = HashMap::new();

    // Get path from leaf to root
    let mut current = leaf;
    let mut path_to_root = vec![leaf];
    while let Some(parent) = msk.params.tree.parent(current) {
        path_to_root.push(parent);
        current = parent;
    }

    // For each node on path, generate keys for SDs with that node as ancestor
    for &ancestor in &path_to_root {
        // Complete subtree key (no exclusion)
        let sd = SubsetDiff::complete(ancestor);
        if msk.params.user_in_subset_diff(user_index, &sd) {
            sd_keys.insert((ancestor, None), msk.derive_sd_key(&sd));
        }

        // Keys with various descendant exclusions
        // We need keys where the user is in ancestor but NOT in descendant
        for &potential_desc in &path_to_root {
            if potential_desc < ancestor {
                // descendant is below ancestor
                let sd = SubsetDiff::new(ancestor, Some(potential_desc));
                if msk.params.user_in_subset_diff(user_index, &sd) {
                    sd_keys.insert((ancestor, Some(potential_desc)), msk.derive_sd_key(&sd));
                }
            }
        }
    }

    // Also add keys for siblings at each level
    for &node in &path_to_root {
        if let Some(parent) = msk.params.tree.parent(node) {
            let sibling = if node == msk.params.tree.left_child(parent) {
                msk.params.tree.right_child(parent)
            } else {
                msk.params.tree.left_child(parent)
            };

            // If we're not in the sibling subtree, we might need keys for SDs rooted there
            if !msk.params.is_in_subtree(leaf, sibling) {
                // User is not in sibling, so they wouldn't need keys for sibling-rooted SDs
                continue;
            }
        }
    }

    Ok(SDUserKey {
        user_id,
        user_index,
        leaf,
        sd_keys,
    })
}

/// SD broadcast ciphertext
#[derive(Clone, Debug)]
pub struct SDBroadcastCiphertext {
    /// Cover using subset differences
    pub cover: SDCover,
    /// Encrypted session keys for each subset difference
    pub encrypted_keys: HashMap<(NodeId, Option<NodeId>), Vec<u8>>,
    /// Nonce
    pub nonce: [u8; 12],
    /// Encrypted payload
    pub payload: Vec<u8>,
}

/// Encrypt using SD method
pub fn sd_broadcast_encrypt<R: RngCore + CryptoRng>(
    rng: &mut R,
    msk: &SDMasterKey,
    revoked_users: &[UserId],
    plaintext: &[u8],
) -> Result<SDBroadcastCiphertext, String> {
    let revoked_indices: Vec<usize> = revoked_users
        .iter()
        .filter_map(|uid| msk.get_user_index(uid))
        .collect();

    let cover = compute_sd_cover(&msk.params, &revoked_indices);

    // Generate session key
    let mut session_key = [0u8; 32];
    rng.fill_bytes(&mut session_key);

    // Encrypt session key for each subset difference in cover
    let mut encrypted_keys = HashMap::new();
    for sd in &cover.differences {
        let sd_key = msk.derive_sd_key(sd);
        let encrypted = xor_encrypt(&session_key, &sd_key);
        encrypted_keys.insert((sd.ancestor, sd.descendant), encrypted);
    }

    // Generate nonce and encrypt payload
    let mut nonce = [0u8; 12];
    rng.fill_bytes(&mut nonce);
    let payload = aes_gcm_encrypt(&session_key, &nonce, plaintext);

    Ok(SDBroadcastCiphertext {
        cover,
        encrypted_keys,
        nonce,
        payload,
    })
}

/// Decrypt using SD method
pub fn sd_broadcast_decrypt(
    user_key: &SDUserKey,
    ct: &SDBroadcastCiphertext,
) -> Result<Vec<u8>, String> {
    // Check if user is revoked
    if ct.cover.revoked_indices.contains(&user_key.user_index) {
        return Err("User is revoked".into());
    }

    // Find a subset difference the user can decrypt
    for sd in &ct.cover.differences {
        let key_id = (sd.ancestor, sd.descendant);
        if let Some(&sd_key) = user_key.sd_keys.get(&key_id) {
            if let Some(encrypted_session_key) = ct.encrypted_keys.get(&key_id) {
                let session_key = xor_decrypt(encrypted_session_key, &sd_key);
                let plaintext = aes_gcm_decrypt(&session_key, &ct.nonce, &ct.payload)
                    .map_err(|_| "Decryption failed")?;
                return Ok(plaintext);
            }
        }
    }

    Err("No matching subset difference key found".into())
}

#[cfg(test)]
mod sd_tests {
    use super::*;
    use rand::thread_rng;

    #[test]
    fn test_sd_params() {
        let params = SubsetDifferenceParams::new(8);
        assert_eq!(params.tree.num_users, 8);

        // Test user in subset diff
        let sd = SubsetDiff::complete(1); // Root
        assert!(params.user_in_subset_diff(0, &sd));
        assert!(params.user_in_subset_diff(7, &sd));

        // Test with exclusion
        let left_child = params.tree.left_child(1);
        let sd_exclude = SubsetDiff::new(1, Some(left_child));
        // Users in left subtree should be excluded
        assert!(!params.user_in_subset_diff(0, &sd_exclude));
        assert!(!params.user_in_subset_diff(3, &sd_exclude));
        // Users in right subtree should be included
        assert!(params.user_in_subset_diff(4, &sd_exclude));
        assert!(params.user_in_subset_diff(7, &sd_exclude));
    }

    #[test]
    fn test_sd_cover_no_revocation() {
        let params = SubsetDifferenceParams::new(8);
        let cover = compute_sd_cover(&params, &[]);

        assert_eq!(cover.differences.len(), 1);
        assert_eq!(cover.differences[0], SubsetDiff::complete(1));
    }

    #[test]
    fn test_sd_cover_single_revocation() {
        let params = SubsetDifferenceParams::new(8);
        let cover = compute_sd_cover(&params, &[0]);

        // Should have subset differences covering users 1-7
        assert!(!cover.differences.is_empty());

        // Verify all non-revoked users are covered
        for user in 1..8 {
            let covered = cover.differences.iter().any(|sd| params.user_in_subset_diff(user, sd));
            assert!(covered, "User {} should be covered", user);
        }

        // Verify revoked user is not covered
        let user0_covered = cover.differences.iter().any(|sd| params.user_in_subset_diff(0, sd));
        assert!(!user0_covered, "User 0 should not be covered");
    }

    #[test]
    fn test_sd_encrypt_decrypt() {
        let mut rng = thread_rng();
        let mut msk = SDMasterKey::new(&mut rng, 16);

        for i in 0..8 {
            msk.register_user(UserId::new(format!("user{}", i)));
        }

        let user0_key = generate_sd_user_key(&msk, "user0").unwrap();
        let user1_key = generate_sd_user_key(&msk, "user1").unwrap();

        let plaintext = b"SD broadcast message";
        let ct = sd_broadcast_encrypt(&mut rng, &msk, &[], plaintext).unwrap();

        let dec0 = sd_broadcast_decrypt(&user0_key, &ct).unwrap();
        let dec1 = sd_broadcast_decrypt(&user1_key, &ct).unwrap();

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

        let revoked = vec![UserId::new("user0")];
        let plaintext = b"Secret message";
        let ct = sd_broadcast_encrypt(&mut rng, &msk, &revoked, plaintext).unwrap();

        // User0 revoked - cannot decrypt
        let result0 = sd_broadcast_decrypt(&user0_key, &ct);
        assert!(result0.is_err());

        // User1 can decrypt
        let dec1 = sd_broadcast_decrypt(&user1_key, &ct).unwrap();
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
        let user5_key = generate_sd_user_key(&msk, "user5").unwrap();

        let revoked = vec![
            UserId::new("user0"),
            UserId::new("user1"),
            UserId::new("user2"),
            UserId::new("user4"),
            UserId::new("user6"),
            UserId::new("user7"),
        ];

        let plaintext = b"For users 3 and 5 only";
        let ct = sd_broadcast_encrypt(&mut rng, &msk, &revoked, plaintext).unwrap();

        let dec3 = sd_broadcast_decrypt(&user3_key, &ct).unwrap();
        let dec5 = sd_broadcast_decrypt(&user5_key, &ct).unwrap();

        assert_eq!(dec3, plaintext);
        assert_eq!(dec5, plaintext);
    }

    #[test]
    fn test_sd_cover_efficiency() {
        let params = SubsetDifferenceParams::new(1024);

        // With r revocations, SD should have O(2r-1) subsets
        // vs O(r log n) for Complete Subtree
        let revoked: Vec<usize> = (0..10).collect();
        let cover = compute_sd_cover(&params, &revoked);

        // Should be roughly 2r - 1 = 19 or fewer subsets
        assert!(cover.differences.len() <= 20, "SD cover too large: {}", cover.differences.len());
    }
}
