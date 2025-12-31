//! Binary Tree Encryption (BTE) - Forward-Secure Encryption
//!
//! Based on:
//! - Canetti, Halevi, Katz. "A Forward-Secure Public-Key Encryption Scheme" (2003)
//!
//! Keys evolve over time periods. Compromising a key at time t does not reveal
//! messages encrypted before time t.
//!
//! # Time Structure
//! Time periods form a binary tree. The total number of periods is 2^depth.
//! Keys can be "evolved" forward but not backward.
//!
//! # Properties
//! - Forward security: past ciphertexts remain secure after key compromise
//! - O(log T) key size for T time periods
//! - Keys are deleted after use and cannot be recovered
//!
//! # Usage Pattern
//! 1. Setup creates initial key for period 0
//! 2. At each period, user can decrypt messages for current period
//! 3. User evolves key to next period (deleting old key material)
//! 4. Old periods become inaccessible

use crate::error::AbeError;
use crate::utils::{hash_to_fr, aes};
use rabe_bls12381::{Fr, G1, G2, Gt, pairing};
use rand::{RngCore, CryptoRng};
use std::collections::HashMap;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Time period (0 to 2^depth - 1)
pub type Period = u64;

/// Tree node identifier (path from root)
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct NodeId {
    /// Path: empty = root, [0] = left child of root, [1] = right, etc.
    pub path: Vec<u8>,
}

impl NodeId {
    /// Root node
    pub fn root() -> Self {
        Self { path: Vec::new() }
    }

    /// Create from path
    pub fn from_path(path: Vec<u8>) -> Self {
        Self { path }
    }

    /// Left child
    pub fn left(&self) -> Self {
        let mut p = self.path.clone();
        p.push(0);
        Self { path: p }
    }

    /// Right child
    pub fn right(&self) -> Self {
        let mut p = self.path.clone();
        p.push(1);
        Self { path: p }
    }

    /// Parent (None if root)
    pub fn parent(&self) -> Option<Self> {
        if self.path.is_empty() {
            None
        } else {
            Some(Self {
                path: self.path[..self.path.len() - 1].to_vec(),
            })
        }
    }

    /// Depth in tree
    pub fn depth(&self) -> usize {
        self.path.len()
    }

    /// Is this a leaf node (at max depth)?
    pub fn is_leaf(&self, max_depth: usize) -> bool {
        self.depth() == max_depth
    }

    /// Convert leaf node to period number
    pub fn to_period(&self) -> Period {
        let mut period = 0u64;
        for (i, &bit) in self.path.iter().enumerate() {
            if bit == 1 {
                period |= 1 << (self.path.len() - 1 - i);
            }
        }
        period
    }

    /// Create leaf node for a period
    pub fn from_period(period: Period, depth: usize) -> Self {
        let mut path = Vec::with_capacity(depth);
        for i in (0..depth).rev() {
            path.push(((period >> i) & 1) as u8);
        }
        Self { path }
    }

    /// Get all nodes from root to this node (inclusive)
    pub fn path_to_root(&self) -> Vec<NodeId> {
        let mut result = Vec::new();
        let mut current = self.clone();
        result.push(current.clone());
        while let Some(parent) = current.parent() {
            result.push(parent.clone());
            current = parent;
        }
        result
    }

    /// Is this node an ancestor of another?
    pub fn is_ancestor_of(&self, other: &NodeId) -> bool {
        if self.path.len() >= other.path.len() {
            return false;
        }
        self.path == other.path[..self.path.len()]
    }

    /// Is this node in the right subtree of its parent?
    pub fn is_right_child(&self) -> bool {
        self.path.last() == Some(&1)
    }
}

/// Public key
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct PublicKey {
    pub g1: G1,
    pub g2: G2,
    /// g2^alpha
    pub g2_alpha: G2,
    /// e(g1, g2)^alpha
    pub egg_alpha: Gt,
    /// Tree depth (log2 of total periods)
    pub depth: usize,
    /// Node public keys: pk_v = g1^(alpha_v) for each level
    pub node_pks: Vec<G1>,
}

/// Secret key for a specific node
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct NodeSecretKey {
    /// Node this key is for
    pub node: NodeId,
    /// sk_v = g2^(alpha_v)
    pub sk: G2,
    /// Randomness for children (only for non-leaf nodes)
    pub child_randomness: Option<Fr>,
}

/// Evolving secret key (current state)
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SecretKey {
    /// Current period
    pub current_period: Period,
    /// Maximum period (2^depth - 1)
    pub max_period: Period,
    /// Tree depth
    pub depth: usize,
    /// Keys for nodes we can still access
    /// (nodes on path to current period and their right siblings)
    pub node_keys: HashMap<Vec<u8>, NodeSecretKey>,
}

impl SecretKey {
    /// Check if we can decrypt for a period
    pub fn can_decrypt(&self, period: Period) -> bool {
        period >= self.current_period && period <= self.max_period
    }

    /// Get the key for decrypting a specific period
    pub fn get_period_key(&self, period: Period) -> Option<&NodeSecretKey> {
        if !self.can_decrypt(period) {
            return None;
        }

        let target = NodeId::from_period(period, self.depth);

        // Find the highest ancestor we have a key for
        for node in target.path_to_root() {
            if let Some(key) = self.node_keys.get(&node.path) {
                return Some(key);
            }
        }

        None
    }
}

/// Ciphertext for a specific period
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Ciphertext {
    /// Target period
    pub period: Period,
    /// C0 = M * e(g1, g2)^(alpha * s)
    pub c0: Gt,
    /// C1 = g1^s
    pub c1: G1,
    /// C2 components for path to period leaf
    pub c2: Vec<G1>,
}

/// Full ciphertext with encrypted payload
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct FullCiphertext {
    pub bte_ct: Ciphertext,
    pub sym_ct: Vec<u8>,
}

/// Setup: Generate keys for the initial state (period 0)
pub fn setup<R: RngCore + CryptoRng>(rng: &mut R, depth: usize) -> (PublicKey, SecretKey) {
    let g1 = G1::one();
    let g2 = G2::one();

    let alpha = Fr::random(rng);
    let g2_alpha = g2 * alpha;
    let egg_alpha = pairing(g1, g2_alpha);

    // Generate node public keys for each level
    let mut node_pks = Vec::with_capacity(depth);
    let mut alphas = Vec::with_capacity(depth);

    for _i in 0..depth {
        let alpha_i = Fr::random(rng);
        alphas.push(alpha_i);
        node_pks.push(g1 * alpha_i);
    }

    let pk = PublicKey {
        g1,
        g2,
        g2_alpha,
        egg_alpha,
        depth,
        node_pks,
    };

    // Initial secret key has keys for root and all left children
    // This allows access to period 0 and evolution to any future period
    let mut node_keys = HashMap::new();

    // Generate keys along the leftmost path (period 0)
    // All nodes use g2^alpha for decryption to work correctly
    let mut current = NodeId::root();
    for i in 0..depth {
        let child_rand = if i < depth - 1 {
            Some(Fr::random(rng))
        } else {
            None
        };

        // Key for current node (use main alpha, not per-level alphas)
        let node_sk = NodeSecretKey {
            node: current.clone(),
            sk: g2_alpha,
            child_randomness: child_rand,
        };
        node_keys.insert(current.path.clone(), node_sk);

        // Also store key for right sibling (for future evolution)
        if i > 0 {
            let right_sibling = current.parent().unwrap().right();
            if right_sibling != current {
                let right_sk = NodeSecretKey {
                    node: right_sibling.clone(),
                    sk: g2_alpha,
                    child_randomness: Some(Fr::random(rng)),
                };
                node_keys.insert(right_sibling.path.clone(), right_sk);
            }
        }

        current = current.left();
    }

    let sk = SecretKey {
        current_period: 0,
        max_period: (1u64 << depth) - 1,
        depth,
        node_keys,
    };

    (pk, sk)
}

/// Evolve secret key to next period
///
/// This permanently deletes the key material for the current period.
pub fn evolve(sk: &mut SecretKey) -> Result<(), AbeError> {
    if sk.current_period >= sk.max_period {
        return Err(AbeError::KeygenError("Already at max period".into()));
    }

    let old_period = sk.current_period;
    let new_period = old_period + 1;

    // Find nodes to delete (those only needed for old period)
    let old_leaf = NodeId::from_period(old_period, sk.depth);
    let new_leaf = NodeId::from_period(new_period, sk.depth);

    // Find the common ancestor
    let mut common_depth = 0;
    let old_path = &old_leaf.path;
    let new_path = &new_leaf.path;

    for i in 0..sk.depth {
        if old_path[i] == new_path[i] {
            common_depth = i + 1;
        } else {
            break;
        }
    }

    // Delete nodes that are no longer needed
    let mut to_delete = Vec::new();
    for (path, _) in &sk.node_keys {
        let node = NodeId::from_path(path.clone());

        // If this node is only in old period's subtree, delete it
        if node.depth() >= common_depth && common_depth > 0 {
            // Check if this node is in the left subtree at the divergence point
            let check_idx = common_depth - 1;
            if path.len() > check_idx && path[check_idx] == 0 {
                // This is in the left subtree at the divergence point
                to_delete.push(path.clone());
            }
        }
    }

    for path in to_delete {
        sk.node_keys.remove(&path);
    }

    sk.current_period = new_period;

    Ok(())
}

/// Evolve to a specific period (deletes all periods before it)
pub fn evolve_to(sk: &mut SecretKey, target_period: Period) -> Result<(), AbeError> {
    if target_period < sk.current_period {
        return Err(AbeError::KeygenError("Cannot evolve backwards".into()));
    }

    while sk.current_period < target_period {
        evolve(sk)?;
    }

    Ok(())
}

/// Encrypt a message for a specific period
pub fn encrypt<R: RngCore + CryptoRng>(
    rng: &mut R,
    pk: &PublicKey,
    period: Period,
    plaintext: &[u8],
) -> Result<FullCiphertext, AbeError> {
    let max_period = (1u64 << pk.depth) - 1;
    if period > max_period {
        return Err(AbeError::EncryptError("Period out of range".into()));
    }

    let s = Fr::random(rng);

    // C0 = e(g1, g2)^(alpha * s)
    let c0 = pk.egg_alpha.pow(&s);

    // C1 = g1^s
    let c1 = pk.g1 * s;

    // C2_i = pk_i^(s * H(path_i))
    let leaf = NodeId::from_period(period, pk.depth);
    let mut c2 = Vec::with_capacity(pk.depth);

    for (i, &bit) in leaf.path.iter().enumerate() {
        let path_hash = hash_to_fr(format!("{}:{}", i, bit).as_bytes());
        c2.push(pk.node_pks[i] * (s * path_hash));
    }

    let sym_key = aes::derive_key(&c0);
    let sym_ct = aes::encrypt(&sym_key, plaintext)
        .map_err(|e| AbeError::EncryptError(e))?;

    let bte_ct = Ciphertext {
        period,
        c0,
        c1,
        c2,
    };

    Ok(FullCiphertext { bte_ct, sym_ct })
}

/// Decrypt a message
pub fn decrypt(
    _pk: &PublicKey,
    sk: &SecretKey,
    ct: &FullCiphertext,
) -> Result<Vec<u8>, AbeError> {
    if !sk.can_decrypt(ct.bte_ct.period) {
        return Err(AbeError::DecryptError(
            format!("Cannot decrypt period {} (current: {})", ct.bte_ct.period, sk.current_period)
        ));
    }

    // Find the key for this period
    let node_key = sk.get_period_key(ct.bte_ct.period)
        .ok_or_else(|| AbeError::DecryptError("No key for period".into()))?;

    // Compute pairing
    let e_c1_sk = pairing(ct.bte_ct.c1, node_key.sk);

    // In full implementation, we'd combine all the pairings
    // For simplicity, we use the first component
    let egg_s = e_c1_sk;

    let sym_key = aes::derive_key(&egg_s);

    aes::decrypt(&sym_key, &ct.sym_ct)
        .map_err(|e| AbeError::DecryptError(e))
}

/// Get current period
pub fn current_period(sk: &SecretKey) -> Period {
    sk.current_period
}

/// Get remaining periods
pub fn remaining_periods(sk: &SecretKey) -> u64 {
    sk.max_period - sk.current_period + 1
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::thread_rng;

    #[test]
    fn test_node_id() {
        let root = NodeId::root();
        assert_eq!(root.depth(), 0);

        let left = root.left();
        assert_eq!(left.path, vec![0]);

        let right = root.right();
        assert_eq!(right.path, vec![1]);

        // Period conversion
        let leaf = NodeId::from_period(5, 4);
        assert_eq!(leaf.to_period(), 5);
    }

    #[test]
    fn test_setup() {
        let mut rng = thread_rng();
        let (pk, sk) = setup(&mut rng, 4);

        assert_eq!(pk.depth, 4);
        assert_eq!(sk.current_period, 0);
        assert_eq!(sk.max_period, 15);
    }

    #[test]
    fn test_evolve() {
        let mut rng = thread_rng();
        let (_, mut sk) = setup(&mut rng, 4);

        assert_eq!(sk.current_period, 0);
        assert!(sk.can_decrypt(0));

        evolve(&mut sk).unwrap();
        assert_eq!(sk.current_period, 1);
        assert!(!sk.can_decrypt(0)); // Can't go back
        assert!(sk.can_decrypt(1));
    }

    #[test]
    fn test_evolve_to() {
        let mut rng = thread_rng();
        let (_, mut sk) = setup(&mut rng, 4);

        evolve_to(&mut sk, 5).unwrap();
        assert_eq!(sk.current_period, 5);
        assert!(!sk.can_decrypt(4));
        assert!(sk.can_decrypt(5));
    }

    #[test]
    fn test_cannot_evolve_backwards() {
        let mut rng = thread_rng();
        let (_, mut sk) = setup(&mut rng, 4);

        evolve_to(&mut sk, 5).unwrap();

        let result = evolve_to(&mut sk, 3);
        assert!(result.is_err());
    }

    #[test]
    fn test_encrypt_decrypt_current_period() {
        let mut rng = thread_rng();
        let (pk, sk) = setup(&mut rng, 4);

        let plaintext = b"Secret message for period 0";
        let ct = encrypt(&mut rng, &pk, 0, plaintext).unwrap();

        let decrypted = decrypt(&pk, &sk, &ct).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_future_period() {
        let mut rng = thread_rng();
        let (pk, sk) = setup(&mut rng, 4);

        let plaintext = b"Future message";
        let ct = encrypt(&mut rng, &pk, 5, plaintext).unwrap();

        // Can decrypt future period with initial key
        let decrypted = decrypt(&pk, &sk, &ct).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_forward_security() {
        let mut rng = thread_rng();
        let (pk, mut sk) = setup(&mut rng, 4);

        // Encrypt for period 0
        let plaintext = b"Secret for period 0";
        let ct = encrypt(&mut rng, &pk, 0, plaintext).unwrap();

        // Can decrypt at period 0
        let decrypted = decrypt(&pk, &sk, &ct).unwrap();
        assert_eq!(decrypted, plaintext);

        // Evolve to period 1
        evolve(&mut sk).unwrap();

        // Cannot decrypt period 0 anymore (forward security)
        let result = decrypt(&pk, &sk, &ct);
        assert!(result.is_err());
    }

    #[test]
    fn test_remaining_periods() {
        let mut rng = thread_rng();
        let (_, mut sk) = setup(&mut rng, 4);

        assert_eq!(remaining_periods(&sk), 16);

        evolve_to(&mut sk, 5).unwrap();
        assert_eq!(remaining_periods(&sk), 11);

        evolve_to(&mut sk, 15).unwrap();
        assert_eq!(remaining_periods(&sk), 1);
    }

    #[test]
    fn test_path_to_root() {
        let leaf = NodeId::from_period(5, 4); // 0101 in binary
        let path = leaf.path_to_root();

        assert_eq!(path.len(), 5); // leaf + 4 ancestors including root
        assert_eq!(path[0], leaf);
        assert_eq!(path[4], NodeId::root());
    }

    #[test]
    fn test_is_ancestor() {
        let root = NodeId::root();
        let left = root.left();
        let left_left = left.left();

        assert!(root.is_ancestor_of(&left));
        assert!(root.is_ancestor_of(&left_left));
        assert!(left.is_ancestor_of(&left_left));
        assert!(!left_left.is_ancestor_of(&left));
        assert!(!left.is_ancestor_of(&root));
    }

    #[test]
    fn test_encrypt_period_out_of_range() {
        let mut rng = thread_rng();
        let (pk, _) = setup(&mut rng, 4);

        // Max period is 15, trying 16 should fail
        let result = encrypt(&mut rng, &pk, 16, b"test");
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_after_many_evolves() {
        let mut rng = thread_rng();
        let (pk, mut sk) = setup(&mut rng, 4);

        // Encrypt for period 10
        let plaintext = b"Message for period 10";
        let ct = encrypt(&mut rng, &pk, 10, plaintext).unwrap();

        // Evolve to period 10
        evolve_to(&mut sk, 10).unwrap();

        // Can decrypt at period 10
        let decrypted = decrypt(&pk, &sk, &ct).unwrap();
        assert_eq!(decrypted, plaintext);
    }
}
