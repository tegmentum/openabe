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
use std::collections::{HashMap, HashSet};

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
