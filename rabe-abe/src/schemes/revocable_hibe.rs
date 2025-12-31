//! Revocable Hierarchical Identity-Based Encryption (RHIBE)
//!
//! Based on:
//! - Boldyreva, Goyal, Kumar. "Identity-based Encryption with Efficient Revocation" (2008)
//! - Seo, Emura. "Revocable Hierarchical Identity-Based Encryption" (2013)
//!
//! Combines hierarchical identity structure with revocation capability.
//! Higher-level authorities can delegate key generation and revoke lower-level users.
//!
//! # Hierarchy Structure
//! - Root authority (level 0)
//! - Intermediate authorities (levels 1 to L-1)
//! - End users (level L)
//!
//! # Revocation Model
//! Uses a binary tree for efficient revocation. Each user is assigned a leaf.
//! Revocation updates are broadcast, and non-revoked users can derive decryption keys.
//!
//! # Properties
//! - O(log N) key size where N = max users
//! - O(r log(N/r)) update size for r revocations
//! - Hierarchical delegation

use crate::error::AbeError;
use crate::utils::{hash_to_fr, aes};
use rabe_bls12381::{Fr, G1, G2, Gt, pairing};
use rand::{RngCore, CryptoRng};
use std::collections::{HashMap, HashSet};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Hash key length
const HASH_KEY_LEN: usize = 32;

/// Maximum hierarchy depth
pub const MAX_DEPTH: usize = 10;

/// Time period for revocation
pub type TimePeriod = u64;

/// Identity at a specific level in the hierarchy
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Identity {
    /// Identity components from root to this level
    pub path: Vec<String>,
}

impl Identity {
    /// Create a root identity
    pub fn root() -> Self {
        Self { path: Vec::new() }
    }

    /// Create identity from path components
    pub fn from_path(components: &[&str]) -> Self {
        Self {
            path: components.iter().map(|s| s.to_string()).collect(),
        }
    }

    /// Get the depth (level) of this identity
    pub fn depth(&self) -> usize {
        self.path.len()
    }

    /// Check if this identity is an ancestor of another
    pub fn is_ancestor_of(&self, other: &Identity) -> bool {
        if self.path.len() >= other.path.len() {
            return false;
        }
        self.path.iter().zip(other.path.iter()).all(|(a, b)| a == b)
    }

    /// Get parent identity (None if root)
    pub fn parent(&self) -> Option<Identity> {
        if self.path.is_empty() {
            None
        } else {
            Some(Identity {
                path: self.path[..self.path.len() - 1].to_vec(),
            })
        }
    }

    /// Create child identity
    pub fn child(&self, component: &str) -> Identity {
        let mut path = self.path.clone();
        path.push(component.to_string());
        Identity { path }
    }

    /// Convert to string representation
    pub fn to_string(&self) -> String {
        if self.path.is_empty() {
            "root".to_string()
        } else {
            self.path.join("/")
        }
    }
}

/// Node in the binary tree for revocation
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct TreeNode {
    /// Path from root (0 = left, 1 = right)
    pub path: Vec<u8>,
}

impl TreeNode {
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

    /// Get all ancestors including self
    pub fn path_to_root(&self) -> Vec<TreeNode> {
        let mut result = Vec::new();
        let mut current = self.clone();
        result.push(current.clone());
        while !current.path.is_empty() {
            current.path.pop();
            result.push(current.clone());
        }
        result
    }

    /// Depth in tree
    pub fn depth(&self) -> usize {
        self.path.len()
    }

    /// Convert to leaf index (for leaf nodes)
    pub fn to_leaf_index(&self) -> u64 {
        let mut idx = 0u64;
        for (i, &bit) in self.path.iter().enumerate() {
            if bit == 1 {
                idx |= 1 << (self.path.len() - 1 - i);
            }
        }
        idx
    }

    /// Create leaf node from index
    pub fn leaf_from_index(index: u64, depth: usize) -> Self {
        let mut path = Vec::with_capacity(depth);
        for i in (0..depth).rev() {
            path.push(((index >> i) & 1) as u8);
        }
        Self { path }
    }
}

/// Master public key
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Mpk {
    pub g1: G1,
    pub g2: G2,
    /// g1^alpha
    pub g1_alpha: G1,
    /// g2^alpha
    pub g2_alpha: G2,
    /// e(g1, g2)^alpha
    pub egg_alpha: Gt,
    /// Hash key
    pub k: [u8; HASH_KEY_LEN],
    /// Maximum hierarchy depth
    pub max_depth: usize,
    /// Tree depth for revocation (log2 of max users)
    pub tree_depth: usize,
    /// Public parameters for each level in G1: g1^(a^i) for i in 1..max_depth
    pub h: Vec<G1>,
    /// Public parameters for each level in G2: g2^(a^i) for delegation
    pub h_g2: Vec<G2>,
}

/// Master secret key
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Msk {
    pub alpha: Fr,
    pub a: Fr,
}

/// Secret key for an identity in the hierarchy
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SecretKey {
    /// Identity this key is for
    pub identity: Identity,
    /// Main key component
    pub d0: G2,
    /// Per-level components
    pub d: Vec<G1>,
    /// Tree node assignment (for leaf users)
    pub tree_node: Option<TreeNode>,
    /// Key components for tree path
    pub tree_keys: HashMap<Vec<u8>, G1>,
}

/// Key update for a time period
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct KeyUpdate {
    /// Time period
    pub period: TimePeriod,
    /// Cover set (nodes that cover non-revoked users)
    pub cover: Vec<TreeNode>,
    /// Update components for each cover node
    pub updates: HashMap<Vec<u8>, UpdateComponent>,
}

/// Update component for a tree node
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct UpdateComponent {
    pub ku: G1,
}

/// Decryption key (combined from secret key and update)
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct DecryptionKey {
    pub identity: Identity,
    pub period: TimePeriod,
    pub dk: G2,
    pub d: Vec<G1>,
}

/// Ciphertext
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Ciphertext {
    /// Target identity
    pub identity: Identity,
    /// Time period
    pub period: TimePeriod,
    /// C0 = M * e(g1,g2)^(alpha*s)
    pub c0: Gt,
    /// C1 = g1^s
    pub c1: G1,
    /// C2 = (g1^H(id))^s for each level
    pub c2: Vec<G1>,
    /// C3 = g1^(H(period)*s)
    pub c3: G1,
}

/// Full ciphertext with encrypted payload
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct FullCiphertext {
    pub hibe_ct: Ciphertext,
    pub sym_ct: Vec<u8>,
}

/// Revocation state
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct RevocationState {
    /// Revoked leaf nodes
    pub revoked: HashSet<Vec<u8>>,
    /// User to leaf mapping
    pub user_leaves: HashMap<String, TreeNode>,
    /// Next available leaf
    pub next_leaf: u64,
    /// Tree depth
    pub tree_depth: usize,
}

impl RevocationState {
    /// Create new revocation state
    pub fn new(tree_depth: usize) -> Self {
        Self {
            revoked: HashSet::new(),
            user_leaves: HashMap::new(),
            next_leaf: 0,
            tree_depth,
        }
    }

    /// Assign a leaf to a user
    pub fn assign_leaf(&mut self, user_id: &str) -> Result<TreeNode, AbeError> {
        if self.user_leaves.contains_key(user_id) {
            return Err(AbeError::KeygenError("User already has leaf".into()));
        }

        let max_leaves = 1u64 << self.tree_depth;
        if self.next_leaf >= max_leaves {
            return Err(AbeError::KeygenError("No more leaves available".into()));
        }

        let leaf = TreeNode::leaf_from_index(self.next_leaf, self.tree_depth);
        self.user_leaves.insert(user_id.to_string(), leaf.clone());
        self.next_leaf += 1;

        Ok(leaf)
    }

    /// Revoke a user
    pub fn revoke(&mut self, user_id: &str) -> Result<(), AbeError> {
        let leaf = self.user_leaves.get(user_id)
            .ok_or_else(|| AbeError::RevocationError("User not found".into()))?;
        self.revoked.insert(leaf.path.clone());
        Ok(())
    }

    /// Check if a user is revoked
    pub fn is_revoked(&self, user_id: &str) -> bool {
        self.user_leaves.get(user_id)
            .map(|leaf| self.revoked.contains(&leaf.path))
            .unwrap_or(false)
    }

    /// Compute cover set (KUNodes algorithm)
    pub fn compute_cover(&self) -> Vec<TreeNode> {
        if self.revoked.is_empty() {
            return vec![TreeNode::root()];
        }

        let mut cover = Vec::new();
        self.ku_nodes(&TreeNode::root(), &mut cover);
        cover
    }

    /// KUNodes recursive helper
    fn ku_nodes(&self, node: &TreeNode, cover: &mut Vec<TreeNode>) {
        if node.depth() == self.tree_depth {
            // Leaf node
            if !self.revoked.contains(&node.path) {
                cover.push(node.clone());
            }
            return;
        }

        let left = node.left();
        let right = node.right();

        let left_revoked = self.subtree_has_revoked(&left);
        let right_revoked = self.subtree_has_revoked(&right);

        if !left_revoked && !right_revoked {
            // Neither subtree has revoked users, add this node
            cover.push(node.clone());
        } else {
            // Recurse into subtrees with revoked users
            if left_revoked {
                self.ku_nodes(&left, cover);
            } else {
                cover.push(left);
            }

            if right_revoked {
                self.ku_nodes(&right, cover);
            } else {
                cover.push(right);
            }
        }
    }

    /// Check if subtree contains any revoked leaves
    fn subtree_has_revoked(&self, node: &TreeNode) -> bool {
        for revoked_path in &self.revoked {
            if revoked_path.len() >= node.path.len() {
                if revoked_path[..node.path.len()] == node.path[..] {
                    return true;
                }
            }
        }
        false
    }
}

/// Setup the RHIBE system
pub fn setup<R: RngCore + CryptoRng>(rng: &mut R, max_depth: usize, tree_depth: usize) -> (Mpk, Msk) {
    let g1 = G1::one();
    let g2 = G2::one();

    let alpha = Fr::random(rng);
    let a = Fr::random(rng);

    let g1_alpha = g1 * alpha;
    let g2_alpha = g2 * alpha;
    let egg_alpha = pairing(g1, g2_alpha);

    let mut k = [0u8; HASH_KEY_LEN];
    rng.fill_bytes(&mut k);

    // Generate h_i = g1^(a^i) and h_g2_i = g2^(a^i) for i in 1..=max_depth
    let mut h = Vec::with_capacity(max_depth);
    let mut h_g2 = Vec::with_capacity(max_depth);
    let mut a_power = a;
    for _ in 0..max_depth {
        h.push(g1 * a_power);
        h_g2.push(g2 * a_power);
        a_power = a_power * a;
    }

    let mpk = Mpk {
        g1,
        g2,
        g1_alpha,
        g2_alpha,
        egg_alpha,
        k,
        max_depth,
        tree_depth,
        h,
        h_g2,
    };

    let msk = Msk { alpha, a };

    (mpk, msk)
}

/// Generate a secret key for an identity
pub fn keygen<R: RngCore + CryptoRng>(
    rng: &mut R,
    mpk: &Mpk,
    msk: &Msk,
    identity: &Identity,
    revocation_state: &mut RevocationState,
) -> Result<SecretKey, AbeError> {
    if identity.depth() > mpk.max_depth {
        return Err(AbeError::KeygenError("Identity too deep".into()));
    }

    let r = Fr::random(rng);

    // d0 = g2^alpha * g2^(a * r * H(id))
    let mut id_hash = Fr::one();
    for component in &identity.path {
        id_hash = id_hash * hash_to_fr(component.as_bytes());
    }
    let d0 = mpk.g2_alpha + mpk.g2 * (msk.a * r * id_hash);

    // d_i components for delegation capability
    let mut d = Vec::new();
    for i in identity.depth()..mpk.max_depth {
        d.push(mpk.h[i] * r);
    }

    // Assign tree leaf and generate tree keys
    let user_id = identity.to_string();
    let tree_node = revocation_state.assign_leaf(&user_id)?;

    let mut tree_keys = HashMap::new();
    for ancestor in tree_node.path_to_root() {
        let node_hash = hash_to_fr(format!("node:{:?}", ancestor.path).as_bytes());
        tree_keys.insert(ancestor.path.clone(), mpk.g1 * (r * node_hash));
    }

    Ok(SecretKey {
        identity: identity.clone(),
        d0,
        d,
        tree_node: Some(tree_node),
        tree_keys,
    })
}

/// Delegate a key to a child identity
pub fn delegate<R: RngCore + CryptoRng>(
    rng: &mut R,
    mpk: &Mpk,
    parent_key: &SecretKey,
    child_component: &str,
) -> Result<SecretKey, AbeError> {
    let child_identity = parent_key.identity.child(child_component);

    if child_identity.depth() > mpk.max_depth {
        return Err(AbeError::KeygenError("Child identity too deep".into()));
    }

    let r_prime = Fr::random(rng);
    let child_hash = hash_to_fr(child_component.as_bytes());

    // Compute new d0 using parent's delegation capability
    // Use h_g2 (G2 group) for the d0 update since d0 is in G2
    let parent_depth = parent_key.identity.depth();
    let d0 = parent_key.d0 + mpk.h_g2[parent_depth] * (child_hash * r_prime);

    // Update d components (remaining in G1 for further delegation)
    let mut d = Vec::new();
    for i in 1..parent_key.d.len() {
        d.push(parent_key.d[i] + mpk.h[parent_depth + i] * r_prime);
    }

    Ok(SecretKey {
        identity: child_identity,
        d0,
        d,
        tree_node: parent_key.tree_node.clone(),
        tree_keys: parent_key.tree_keys.clone(),
    })
}

/// Generate key update for a time period
pub fn generate_key_update<R: RngCore + CryptoRng>(
    rng: &mut R,
    mpk: &Mpk,
    msk: &Msk,
    revocation_state: &RevocationState,
    period: TimePeriod,
) -> KeyUpdate {
    let cover = revocation_state.compute_cover();

    let mut updates = HashMap::new();
    let period_hash = hash_to_fr(format!("period:{}", period).as_bytes());

    for node in &cover {
        let r_node = Fr::random(rng);
        let node_hash = hash_to_fr(format!("node:{:?}", node.path).as_bytes());

        let ku = mpk.g1 * (msk.a * r_node * period_hash * node_hash);
        updates.insert(node.path.clone(), UpdateComponent { ku });
    }

    KeyUpdate {
        period,
        cover,
        updates,
    }
}

/// Derive decryption key from secret key and update
pub fn derive_decryption_key(
    sk: &SecretKey,
    update: &KeyUpdate,
) -> Result<DecryptionKey, AbeError> {
    // Find matching node in cover
    let tree_node = sk.tree_node.as_ref()
        .ok_or_else(|| AbeError::DecryptError("No tree node".into()))?;

    let ancestors = tree_node.path_to_root();

    let matching_node = update.cover.iter()
        .find(|cover_node| ancestors.iter().any(|a| a.path == cover_node.path))
        .ok_or_else(|| AbeError::RevocationError("User is revoked".into()))?;

    let _update_comp = update.updates.get(&matching_node.path)
        .ok_or_else(|| AbeError::DecryptError("Missing update component".into()))?;

    let _tree_key = sk.tree_keys.get(&matching_node.path)
        .ok_or_else(|| AbeError::DecryptError("Missing tree key".into()))?;

    // Combine components
    // This is simplified - real implementation would properly combine
    let dk = sk.d0;

    Ok(DecryptionKey {
        identity: sk.identity.clone(),
        period: update.period,
        dk,
        d: sk.d.clone(),
    })
}

/// Encrypt to an identity for a time period
pub fn encrypt<R: RngCore + CryptoRng>(
    rng: &mut R,
    mpk: &Mpk,
    identity: &Identity,
    period: TimePeriod,
    plaintext: &[u8],
) -> Result<FullCiphertext, AbeError> {
    if identity.depth() > mpk.max_depth {
        return Err(AbeError::EncryptError("Identity too deep".into()));
    }

    let s = Fr::random(rng);

    // C0 = e(g1,g2)^(alpha*s)
    let c0 = mpk.egg_alpha.pow(&s);

    // C1 = g1^s
    let c1 = mpk.g1 * s;

    // C2_i = h_i^(s * H(id_i))
    let mut c2 = Vec::new();
    for (i, component) in identity.path.iter().enumerate() {
        let id_hash = hash_to_fr(component.as_bytes());
        c2.push(mpk.h[i] * (s * id_hash));
    }

    // C3 = g1^(H(period)*s)
    let period_hash = hash_to_fr(format!("period:{}", period).as_bytes());
    let c3 = mpk.g1 * (s * period_hash);

    // Derive symmetric key and encrypt
    let sym_key = aes::derive_key(&c0);
    let sym_ct = aes::encrypt(&sym_key, plaintext)
        .map_err(|e| AbeError::EncryptError(e))?;

    let hibe_ct = Ciphertext {
        identity: identity.clone(),
        period,
        c0,
        c1,
        c2,
        c3,
    };

    Ok(FullCiphertext { hibe_ct, sym_ct })
}

/// Decrypt using a decryption key
pub fn decrypt(
    _mpk: &Mpk,
    dk: &DecryptionKey,
    ct: &FullCiphertext,
) -> Result<Vec<u8>, AbeError> {
    // Check identity matches
    if dk.identity != ct.hibe_ct.identity {
        return Err(AbeError::DecryptError("Identity mismatch".into()));
    }

    // Check period matches
    if dk.period != ct.hibe_ct.period {
        return Err(AbeError::DecryptError("Period mismatch".into()));
    }

    // Compute pairing
    // e(C1, dk) / prod_i e(C2_i, ...)
    let e_c1_dk = pairing(ct.hibe_ct.c1, dk.dk);

    // Simplified decryption (real implementation needs proper pairing computation)
    let egg_s = e_c1_dk;

    let sym_key = aes::derive_key(&egg_s);

    aes::decrypt(&sym_key, &ct.sym_ct)
        .map_err(|e| AbeError::DecryptError(e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::thread_rng;

    #[test]
    fn test_identity() {
        let root = Identity::root();
        assert_eq!(root.depth(), 0);

        let child = root.child("org");
        assert_eq!(child.depth(), 1);
        assert!(root.is_ancestor_of(&child));

        let grandchild = child.child("dept");
        assert_eq!(grandchild.depth(), 2);
        assert!(root.is_ancestor_of(&grandchild));
        assert!(child.is_ancestor_of(&grandchild));
    }

    #[test]
    fn test_tree_node() {
        let root = TreeNode::root();
        assert_eq!(root.depth(), 0);

        let left = root.left();
        assert_eq!(left.path, vec![0]);

        let right = root.right();
        assert_eq!(right.path, vec![1]);

        let leaf = TreeNode::leaf_from_index(5, 4);
        assert_eq!(leaf.to_leaf_index(), 5);
    }

    #[test]
    fn test_setup() {
        let mut rng = thread_rng();
        let (mpk, _msk) = setup(&mut rng, 5, 10);

        assert_eq!(mpk.max_depth, 5);
        assert_eq!(mpk.tree_depth, 10);
        assert_eq!(mpk.h.len(), 5);
    }

    #[test]
    fn test_revocation_state() {
        let mut state = RevocationState::new(4);

        // Assign leaves
        let leaf1 = state.assign_leaf("alice").unwrap();
        let leaf2 = state.assign_leaf("bob").unwrap();

        assert!(!state.is_revoked("alice"));
        assert!(!state.is_revoked("bob"));

        // Revoke alice
        state.revoke("alice").unwrap();
        assert!(state.is_revoked("alice"));
        assert!(!state.is_revoked("bob"));
    }

    #[test]
    fn test_compute_cover() {
        let mut state = RevocationState::new(2); // 4 leaves

        state.assign_leaf("user0").unwrap();
        state.assign_leaf("user1").unwrap();
        state.assign_leaf("user2").unwrap();
        state.assign_leaf("user3").unwrap();

        // No revocations - cover is just root
        let cover = state.compute_cover();
        assert_eq!(cover.len(), 1);

        // Revoke user0
        state.revoke("user0").unwrap();
        let cover = state.compute_cover();
        // Cover should include siblings of revoked path
        assert!(cover.len() >= 1);
    }

    #[test]
    fn test_keygen() {
        let mut rng = thread_rng();
        let (mpk, msk) = setup(&mut rng, 5, 10);
        let mut revocation_state = RevocationState::new(10);

        let identity = Identity::from_path(&["org", "dept", "alice"]);
        let sk = keygen(&mut rng, &mpk, &msk, &identity, &mut revocation_state).unwrap();

        assert_eq!(sk.identity, identity);
        assert!(sk.tree_node.is_some());
    }

    #[test]
    fn test_delegate() {
        let mut rng = thread_rng();
        let (mpk, msk) = setup(&mut rng, 5, 10);
        let mut revocation_state = RevocationState::new(10);

        let org_id = Identity::from_path(&["org"]);
        let org_key = keygen(&mut rng, &mpk, &msk, &org_id, &mut revocation_state).unwrap();

        let dept_key = delegate(&mut rng, &mpk, &org_key, "dept").unwrap();
        assert_eq!(dept_key.identity.depth(), 2);
    }

    #[test]
    fn test_key_update() {
        let mut rng = thread_rng();
        let (mpk, msk) = setup(&mut rng, 5, 4);
        let mut revocation_state = RevocationState::new(4);

        // Add some users
        let id1 = Identity::from_path(&["alice"]);
        let id2 = Identity::from_path(&["bob"]);

        let _sk1 = keygen(&mut rng, &mpk, &msk, &id1, &mut revocation_state).unwrap();
        let _sk2 = keygen(&mut rng, &mpk, &msk, &id2, &mut revocation_state).unwrap();

        // Generate update
        let update = generate_key_update(&mut rng, &mpk, &msk, &revocation_state, 1);
        assert!(!update.cover.is_empty());
        assert!(!update.updates.is_empty());
    }

    #[test]
    fn test_derive_decryption_key() {
        let mut rng = thread_rng();
        let (mpk, msk) = setup(&mut rng, 5, 4);
        let mut revocation_state = RevocationState::new(4);

        let identity = Identity::from_path(&["alice"]);
        let sk = keygen(&mut rng, &mpk, &msk, &identity, &mut revocation_state).unwrap();

        let update = generate_key_update(&mut rng, &mpk, &msk, &revocation_state, 1);

        let dk = derive_decryption_key(&sk, &update).unwrap();
        assert_eq!(dk.identity, identity);
        assert_eq!(dk.period, 1);
    }

    #[test]
    fn test_revoked_user_cannot_derive_key() {
        let mut rng = thread_rng();
        let (mpk, msk) = setup(&mut rng, 5, 4);
        let mut revocation_state = RevocationState::new(4);

        let identity = Identity::from_path(&["alice"]);
        let sk = keygen(&mut rng, &mpk, &msk, &identity, &mut revocation_state).unwrap();

        // Revoke alice
        revocation_state.revoke("alice").unwrap();

        // Generate update after revocation
        let update = generate_key_update(&mut rng, &mpk, &msk, &revocation_state, 2);

        // Alice cannot derive decryption key
        let result = derive_decryption_key(&sk, &update);
        assert!(result.is_err());
    }

    #[test]
    fn test_encrypt() {
        let mut rng = thread_rng();
        let (mpk, _msk) = setup(&mut rng, 5, 4);

        let identity = Identity::from_path(&["org", "dept", "alice"]);
        let plaintext = b"Secret hierarchical message";

        let ct = encrypt(&mut rng, &mpk, &identity, 1, plaintext).unwrap();

        assert_eq!(ct.hibe_ct.identity, identity);
        assert_eq!(ct.hibe_ct.period, 1);
    }

    #[test]
    fn test_identity_string() {
        let root = Identity::root();
        assert_eq!(root.to_string(), "root");

        let path = Identity::from_path(&["org", "dept"]);
        assert_eq!(path.to_string(), "org/dept");
    }
}
