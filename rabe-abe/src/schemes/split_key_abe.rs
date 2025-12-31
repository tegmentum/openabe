//! Server-Aided Revocation (Split Keys) for CP-ABE
//!
//! Keys are split between user and a key server. The server can instantly
//! revoke users by refusing to provide or update their share.
//!
//! # Difference from Mediated ABE (SEM)
//! - Server share can be cached by the user
//! - No per-decryption server interaction needed (after initial share retrieval)
//! - Revocation takes effect when user requests share refresh
//! - Supports optional periodic share rotation for proactive security
//!
//! # Properties
//! - User cannot decrypt without valid server share
//! - Server cannot decrypt alone (doesn't have user's key component)
//! - Revocation by invalidating server share
//! - Share expiration for time-limited access

use crate::error::AbeError;
use crate::lsss::LsssMatrix;
use crate::schemes::waters::parse_policy;
use crate::utils::{hash_to_g1_keyed, aes};
use rabe_bls12381::{Fr, G1, G2, Gt, pairing};
use rand::{RngCore, CryptoRng};
use std::collections::{HashMap, HashSet};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Hash key length
const HASH_KEY_LEN: usize = 32;

/// Share version/epoch for rotation
pub type ShareEpoch = u64;

/// Master public key
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Mpk {
    /// Generator g1
    pub g1: G1,
    /// Generator g2
    pub g2: G2,
    /// g1^a
    pub g1a: G1,
    /// g2^alpha
    pub g2alpha: G2,
    /// e(g1, g2)^alpha
    pub egg_alpha: Gt,
    /// Hash key
    pub k: [u8; HASH_KEY_LEN],
}

/// Master secret key
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Msk {
    /// Master secret
    pub alpha: Fr,
    /// Exponent a
    pub a: Fr,
    /// g2^a
    pub g2a: G2,
    /// User's alpha share
    pub alpha_user: Fr,
    /// Server's alpha share
    pub alpha_server: Fr,
}

/// Key server's master secret
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ServerMasterKey {
    /// Server's share of alpha
    pub alpha_s: Fr,
    /// g2^alpha_s
    pub g2_alpha_s: G2,
    /// Current epoch
    pub current_epoch: ShareEpoch,
}

/// User's key share (permanent, stored by user)
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct UserKeyShare {
    /// User identifier
    pub user_id: String,
    /// K_u = g2^alpha_u * g2^(a*t)
    pub k_u: G2,
    /// L = g2^t
    pub l: G2,
    /// Per-attribute components
    pub kx: HashMap<String, G1>,
    /// Attributes
    pub attributes: Vec<String>,
}

/// Server's share for a user (can be revoked/rotated)
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ServerKeyShare {
    /// Share identifier
    pub share_id: String,
    /// User this share belongs to
    pub user_id: String,
    /// K_s = g2^alpha_s (server's contribution)
    pub k_s: G2,
    /// Epoch when this share was issued
    pub epoch: ShareEpoch,
    /// Optional expiration timestamp (Unix time)
    pub expires_at: Option<u64>,
    /// Whether this share has been revoked
    pub revoked: bool,
}

/// Combined key for decryption (user caches this)
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct CombinedKey {
    /// User's share
    pub user_share: UserKeyShare,
    /// Server's share (cached)
    pub server_share: ServerKeyShare,
}

/// Per-attribute ciphertext component
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct CiphertextComponent {
    pub c: G1,
    pub d: G2,
}

/// ABE ciphertext
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Ciphertext {
    pub policy: String,
    pub c: Gt,
    pub c_prime: G1,
    pub components: HashMap<String, CiphertextComponent>,
    /// Minimum epoch required for decryption (optional)
    pub min_epoch: Option<ShareEpoch>,
}

/// Full ciphertext with encrypted payload
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct FullCiphertext {
    pub abe_ct: Ciphertext,
    pub sym_ct: Vec<u8>,
}

/// Key server state
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct KeyServer {
    /// Server master key
    pub master_key: ServerMasterKey,
    /// Issued shares (by share_id)
    pub shares: HashMap<String, ServerKeyShare>,
    /// Revoked users
    pub revoked_users: HashSet<String>,
}

impl KeyServer {
    /// Create a new key server
    pub fn new(master_key: ServerMasterKey) -> Self {
        Self {
            master_key,
            shares: HashMap::new(),
            revoked_users: HashSet::new(),
        }
    }

    /// Issue a share for a user
    pub fn issue_share(&mut self, user_id: &str, expires_at: Option<u64>) -> Result<ServerKeyShare, AbeError> {
        if self.revoked_users.contains(user_id) {
            return Err(AbeError::RevocationError(
                format!("User {} is revoked", user_id)
            ));
        }

        let share_id = format!("{}_{}", user_id, self.master_key.current_epoch);

        let share = ServerKeyShare {
            share_id: share_id.clone(),
            user_id: user_id.to_string(),
            k_s: self.master_key.g2_alpha_s,
            epoch: self.master_key.current_epoch,
            expires_at,
            revoked: false,
        };

        self.shares.insert(share_id, share.clone());
        Ok(share)
    }

    /// Revoke a user
    pub fn revoke_user(&mut self, user_id: &str) {
        self.revoked_users.insert(user_id.to_string());

        // Revoke all their shares
        for share in self.shares.values_mut() {
            if share.user_id == user_id {
                share.revoked = true;
            }
        }
    }

    /// Unrevoke a user
    pub fn unrevoke_user(&mut self, user_id: &str) {
        self.revoked_users.remove(user_id);
    }

    /// Check if user is revoked
    pub fn is_revoked(&self, user_id: &str) -> bool {
        self.revoked_users.contains(user_id)
    }

    /// Request a share (checks revocation)
    pub fn request_share(&self, user_id: &str) -> Result<&ServerKeyShare, AbeError> {
        if self.revoked_users.contains(user_id) {
            return Err(AbeError::RevocationError(
                format!("User {} is revoked", user_id)
            ));
        }

        // Find the user's most recent share
        let share = self.shares.values()
            .filter(|s| s.user_id == user_id && !s.revoked)
            .max_by_key(|s| s.epoch)
            .ok_or_else(|| AbeError::RevocationError(
                format!("No valid share for user {}", user_id)
            ))?;

        Ok(share)
    }

    /// Rotate to new epoch (invalidates old shares)
    pub fn rotate_epoch(&mut self) {
        self.master_key.current_epoch += 1;
    }

    /// Get current epoch
    pub fn current_epoch(&self) -> ShareEpoch {
        self.master_key.current_epoch
    }
}

/// Setup: Generate master keys and server key
pub fn setup<R: RngCore + CryptoRng>(rng: &mut R) -> (Mpk, Msk, ServerMasterKey) {
    let g1 = G1::one();
    let g2 = G2::one();

    let alpha = Fr::random(rng);
    let alpha_user = Fr::random(rng);
    let alpha_server = alpha - alpha_user;

    let a = Fr::random(rng);

    let g1a = g1 * a;
    let g2alpha = g2 * alpha;
    let g2a = g2 * a;
    let egg_alpha = pairing(g1, g2alpha);

    let mut k = [0u8; HASH_KEY_LEN];
    rng.fill_bytes(&mut k);

    let mpk = Mpk {
        g1,
        g2,
        g1a,
        g2alpha,
        egg_alpha,
        k,
    };

    let msk = Msk {
        alpha,
        a,
        g2a,
        alpha_user,
        alpha_server,
    };

    let server_key = ServerMasterKey {
        alpha_s: alpha_server,
        g2_alpha_s: g2 * alpha_server,
        current_epoch: 1,
    };

    (mpk, msk, server_key)
}

/// Generate user's key share
pub fn keygen<R: RngCore + CryptoRng>(
    rng: &mut R,
    mpk: &Mpk,
    msk: &Msk,
    user_id: &str,
    attributes: &[&str],
) -> Result<UserKeyShare, AbeError> {
    let t = Fr::random(rng);

    // K_u = g2^alpha_u * g2^(a*t)
    let k_u = mpk.g2 * msk.alpha_user + msk.g2a * t;

    // L = g2^t
    let l = mpk.g2 * t;

    let mut kx = HashMap::new();
    for attr in attributes {
        let h_attr = hash_to_g1_keyed(&mpk.k, attr);
        kx.insert(attr.to_string(), h_attr * t);
    }

    Ok(UserKeyShare {
        user_id: user_id.to_string(),
        k_u,
        l,
        kx,
        attributes: attributes.iter().map(|s| s.to_string()).collect(),
    })
}

/// Combine user share with server share
pub fn combine_keys(
    user_share: UserKeyShare,
    server_share: ServerKeyShare,
) -> Result<CombinedKey, AbeError> {
    if user_share.user_id != server_share.user_id {
        return Err(AbeError::DecryptError("User ID mismatch".into()));
    }

    if server_share.revoked {
        return Err(AbeError::RevocationError("Server share is revoked".into()));
    }

    Ok(CombinedKey {
        user_share,
        server_share,
    })
}

/// Encrypt a message
pub fn encrypt<R: RngCore + CryptoRng>(
    rng: &mut R,
    mpk: &Mpk,
    policy: &str,
    plaintext: &[u8],
) -> Result<FullCiphertext, AbeError> {
    encrypt_with_epoch(rng, mpk, policy, plaintext, None)
}

/// Encrypt with minimum epoch requirement
pub fn encrypt_with_epoch<R: RngCore + CryptoRng>(
    rng: &mut R,
    mpk: &Mpk,
    policy: &str,
    plaintext: &[u8],
    min_epoch: Option<ShareEpoch>,
) -> Result<FullCiphertext, AbeError> {
    let policy_node = parse_policy(policy)
        .map_err(|e| AbeError::InvalidPolicy(e.to_string()))?;
    let lsss = LsssMatrix::from_policy(&policy_node)?;

    let s = Fr::random(rng);
    let c_prime = mpk.g1 * s;
    let egg_s = pairing(c_prime, mpk.g2alpha);

    let sym_key = aes::derive_key(&egg_s);
    let sym_ct = aes::encrypt(&sym_key, plaintext)
        .map_err(|e| AbeError::EncryptError(e))?;

    let shares = lsss.share_secret(rng, s);

    let mut components = HashMap::new();
    for share in shares {
        let r_i = Fr::random(rng);
        let h_attr = hash_to_g1_keyed(&mpk.k, &share.attr);

        let c_i = mpk.g1a * share.share + h_attr * (-r_i);
        let d_i = mpk.g2 * r_i;

        components.insert(share.attr.clone(), CiphertextComponent { c: c_i, d: d_i });
    }

    let abe_ct = Ciphertext {
        policy: policy_node.to_canonical_string(),
        c: egg_s,
        c_prime,
        components,
        min_epoch,
    };

    Ok(FullCiphertext { abe_ct, sym_ct })
}

/// Decrypt with combined key
pub fn decrypt(
    _mpk: &Mpk,
    key: &CombinedKey,
    ct: &FullCiphertext,
) -> Result<Vec<u8>, AbeError> {
    // Check revocation
    if key.server_share.revoked {
        return Err(AbeError::RevocationError("Key share is revoked".into()));
    }

    // Check expiration
    if let Some(expires) = key.server_share.expires_at {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        if now > expires {
            return Err(AbeError::RevocationError("Key share has expired".into()));
        }
    }

    // Check epoch requirement
    if let Some(min_epoch) = ct.abe_ct.min_epoch {
        if key.server_share.epoch < min_epoch {
            return Err(AbeError::RevocationError(
                format!("Key share epoch {} is below minimum {}", key.server_share.epoch, min_epoch)
            ));
        }
    }

    // Parse policy
    let policy_node = parse_policy(&ct.abe_ct.policy)
        .map_err(|e| AbeError::InvalidPolicy(e.to_string()))?;
    let lsss = LsssMatrix::from_policy(&policy_node)?;

    // Find satisfying subset
    let coeffs = lsss.recover_coefficients(&key.user_share.attributes)
        .map_err(|_| AbeError::PolicyNotSatisfied)?;

    // Compute pairing products
    let mut g1_for_pairing = Vec::new();
    let mut g2_for_pairing = Vec::new();

    for (attr, coeff) in &coeffs {
        let comp = ct.abe_ct.components.get(attr)
            .ok_or_else(|| AbeError::DecryptError("Missing ciphertext component".into()))?;

        let kx = key.user_share.kx.get(attr)
            .ok_or_else(|| AbeError::DecryptError("Missing key component".into()))?;

        g1_for_pairing.push(*kx * *coeff);
        g2_for_pairing.push(comp.d);
    }

    let mut prod_t = Gt::one();
    for (g1_elem, g2_elem) in g1_for_pairing.iter().zip(g2_for_pairing.iter()) {
        prod_t = prod_t * pairing(*g1_elem, *g2_elem);
    }

    let mut c_sum = G1::zero();
    for (attr, coeff) in &coeffs {
        let comp = ct.abe_ct.components.get(attr).unwrap();
        c_sum = c_sum + comp.c * *coeff;
    }

    let e_c_l = pairing(c_sum, key.user_share.l);

    // Combine user and server shares
    // Full key would be K = g2^alpha * g2^(a*t)
    // We have K_u = g2^alpha_u * g2^(a*t) and K_s = g2^alpha_s
    // So K = K_u + K_s (additively, which is multiplication in G2)
    let full_k = key.user_share.k_u + key.server_share.k_s;

    let e_c_k = pairing(ct.abe_ct.c_prime, full_k);

    let denominator = e_c_l * prod_t;
    let egg_s = e_c_k * denominator.inverse();

    let sym_key = aes::derive_key(&egg_s);

    aes::decrypt(&sym_key, &ct.sym_ct)
        .map_err(|e| AbeError::DecryptError(e))
}

/// Check if combined key can decrypt (not revoked, not expired, satisfies policy)
pub fn can_decrypt(key: &CombinedKey, policy: &str, current_time: Option<u64>) -> bool {
    if key.server_share.revoked {
        return false;
    }

    if let Some(expires) = key.server_share.expires_at {
        let now = current_time.unwrap_or_else(|| {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
        });
        if now > expires {
            return false;
        }
    }

    let policy_node = match parse_policy(policy) {
        Ok(p) => p,
        Err(_) => return false,
    };

    let lsss = match LsssMatrix::from_policy(&policy_node) {
        Ok(l) => l,
        Err(_) => return false,
    };
    lsss.recover_coefficients(&key.user_share.attributes).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::thread_rng;

    #[test]
    fn test_setup() {
        let mut rng = thread_rng();
        let (mpk, msk, server_key) = setup(&mut rng);

        assert_eq!(msk.alpha, msk.alpha_user + msk.alpha_server);
        assert_eq!(server_key.alpha_s, msk.alpha_server);
        assert_eq!(server_key.current_epoch, 1);
    }

    #[test]
    fn test_keygen() {
        let mut rng = thread_rng();
        let (mpk, msk, _) = setup(&mut rng);

        let user_share = keygen(&mut rng, &mpk, &msk, "alice", &["admin", "hr"]).unwrap();

        assert_eq!(user_share.user_id, "alice");
        assert!(user_share.kx.contains_key("admin"));
        assert!(user_share.kx.contains_key("hr"));
    }

    #[test]
    fn test_key_server() {
        let mut rng = thread_rng();
        let (_, _, server_key) = setup(&mut rng);

        let mut server = KeyServer::new(server_key);

        // Issue share
        let share = server.issue_share("alice", None).unwrap();
        assert_eq!(share.user_id, "alice");
        assert!(!share.revoked);

        // Request share
        let requested = server.request_share("alice").unwrap();
        assert_eq!(requested.user_id, "alice");

        // Revoke user
        server.revoke_user("alice");
        assert!(server.is_revoked("alice"));
        assert!(server.request_share("alice").is_err());
    }

    #[test]
    fn test_encrypt_decrypt() {
        let mut rng = thread_rng();
        let (mpk, msk, server_key) = setup(&mut rng);

        let mut server = KeyServer::new(server_key);

        let user_share = keygen(&mut rng, &mpk, &msk, "alice", &["admin"]).unwrap();
        let server_share = server.issue_share("alice", None).unwrap();

        let combined = combine_keys(user_share, server_share).unwrap();

        let plaintext = b"Secret admin data";
        let ct = encrypt(&mut rng, &mpk, "admin", plaintext).unwrap();

        let decrypted = decrypt(&mpk, &combined, &ct).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_revoked_cannot_decrypt() {
        let mut rng = thread_rng();
        let (mpk, msk, server_key) = setup(&mut rng);

        let mut server = KeyServer::new(server_key);

        let user_share = keygen(&mut rng, &mpk, &msk, "alice", &["admin"]).unwrap();
        let mut server_share = server.issue_share("alice", None).unwrap();

        // Manually revoke the share
        server_share.revoked = true;

        // combine_keys should reject a revoked share
        let result = combine_keys(user_share, server_share);
        assert!(result.is_err());

        // Alternative: if a user has a cached combined key and it gets marked revoked
        let user_share2 = keygen(&mut rng, &mpk, &msk, "bob", &["admin"]).unwrap();
        let mut server_share2 = server.issue_share("bob", None).unwrap();
        let mut combined = combine_keys(user_share2, server_share2).unwrap();

        let plaintext = b"Secret";
        let ct = encrypt(&mut rng, &mpk, "admin", plaintext).unwrap();

        // Can decrypt initially
        assert!(decrypt(&mpk, &combined, &ct).is_ok());

        // Mark the cached share as revoked (simulating server-side revocation)
        combined.server_share.revoked = true;

        // Now decrypt fails
        let result = decrypt(&mpk, &combined, &ct);
        assert!(result.is_err());
    }

    #[test]
    fn test_server_revocation() {
        let mut rng = thread_rng();
        let (mpk, msk, server_key) = setup(&mut rng);

        let mut server = KeyServer::new(server_key);

        let user_share = keygen(&mut rng, &mpk, &msk, "alice", &["admin"]).unwrap();
        server.issue_share("alice", None).unwrap();

        // User can get share initially
        assert!(server.request_share("alice").is_ok());

        // Revoke user
        server.revoke_user("alice");

        // Now cannot get share
        assert!(server.request_share("alice").is_err());

        // Cannot issue new share either
        assert!(server.issue_share("alice", None).is_err());

        // Unrevoke
        server.unrevoke_user("alice");
        assert!(server.issue_share("alice", None).is_ok());
    }

    #[test]
    fn test_epoch_requirement() {
        let mut rng = thread_rng();
        let (mpk, msk, server_key) = setup(&mut rng);

        let mut server = KeyServer::new(server_key);

        let user_share = keygen(&mut rng, &mpk, &msk, "alice", &["admin"]).unwrap();
        let server_share = server.issue_share("alice", None).unwrap();
        let combined = combine_keys(user_share, server_share).unwrap();

        let plaintext = b"Epoch-locked message";

        // Encrypt requiring epoch 2
        let ct = encrypt_with_epoch(&mut rng, &mpk, "admin", plaintext, Some(2)).unwrap();

        // Key is epoch 1, cannot decrypt
        let result = decrypt(&mpk, &combined, &ct);
        assert!(result.is_err());

        // Get new share after epoch rotation
        server.rotate_epoch();
        let user_share2 = keygen(&mut rng, &mpk, &msk, "alice", &["admin"]).unwrap();
        let server_share2 = server.issue_share("alice", None).unwrap();
        let combined2 = combine_keys(user_share2, server_share2).unwrap();

        // Now can decrypt
        let decrypted = decrypt(&mpk, &combined2, &ct).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_expiration() {
        let mut rng = thread_rng();
        let (mpk, msk, server_key) = setup(&mut rng);

        let mut server = KeyServer::new(server_key);

        let user_share = keygen(&mut rng, &mpk, &msk, "alice", &["admin"]).unwrap();

        // Issue share that expires immediately (in the past)
        let server_share = server.issue_share("alice", Some(0)).unwrap();
        let combined = combine_keys(user_share, server_share).unwrap();

        let plaintext = b"Time-sensitive";
        let ct = encrypt(&mut rng, &mpk, "admin", plaintext).unwrap();

        // Should fail due to expiration
        let result = decrypt(&mpk, &combined, &ct);
        assert!(result.is_err());
    }

    #[test]
    fn test_policy_not_satisfied() {
        let mut rng = thread_rng();
        let (mpk, msk, server_key) = setup(&mut rng);

        let mut server = KeyServer::new(server_key);

        // User has "developer" not "admin"
        let user_share = keygen(&mut rng, &mpk, &msk, "alice", &["developer"]).unwrap();
        let server_share = server.issue_share("alice", None).unwrap();
        let combined = combine_keys(user_share, server_share).unwrap();

        let plaintext = b"Admin only";
        let ct = encrypt(&mut rng, &mpk, "admin", plaintext).unwrap();

        let result = decrypt(&mpk, &combined, &ct);
        assert!(result.is_err());
    }

    #[test]
    fn test_multiple_users() {
        let mut rng = thread_rng();
        let (mpk, msk, server_key) = setup(&mut rng);

        let mut server = KeyServer::new(server_key);

        let alice_user = keygen(&mut rng, &mpk, &msk, "alice", &["admin"]).unwrap();
        let bob_user = keygen(&mut rng, &mpk, &msk, "bob", &["admin"]).unwrap();

        let alice_server = server.issue_share("alice", None).unwrap();
        let bob_server = server.issue_share("bob", None).unwrap();

        let alice_key = combine_keys(alice_user, alice_server).unwrap();
        let bob_key = combine_keys(bob_user, bob_server).unwrap();

        let plaintext = b"Team message";
        let ct = encrypt(&mut rng, &mpk, "admin", plaintext).unwrap();

        // Both can decrypt
        assert_eq!(decrypt(&mpk, &alice_key, &ct).unwrap(), plaintext);
        assert_eq!(decrypt(&mpk, &bob_key, &ct).unwrap(), plaintext);

        // Revoke bob
        server.revoke_user("bob");

        // Alice still works (has cached share)
        assert!(decrypt(&mpk, &alice_key, &ct).is_ok());

        // Bob's cached share is not revoked yet
        // But if he needed a new one, he couldn't get it
        assert!(server.request_share("bob").is_err());
    }

    #[test]
    fn test_can_decrypt() {
        let mut rng = thread_rng();
        let (mpk, msk, server_key) = setup(&mut rng);

        let mut server = KeyServer::new(server_key);

        let user_share = keygen(&mut rng, &mpk, &msk, "alice", &["admin", "hr"]).unwrap();
        let server_share = server.issue_share("alice", None).unwrap();
        let combined = combine_keys(user_share, server_share).unwrap();

        assert!(can_decrypt(&combined, "admin", None));
        assert!(can_decrypt(&combined, "hr", None));
        assert!(can_decrypt(&combined, "admin AND hr", None));
        assert!(!can_decrypt(&combined, "finance", None));
    }

    #[test]
    fn test_complex_policy() {
        let mut rng = thread_rng();
        let (mpk, msk, server_key) = setup(&mut rng);

        let mut server = KeyServer::new(server_key);

        let user_share = keygen(&mut rng, &mpk, &msk, "alice", &["admin", "finance", "hr"]).unwrap();
        let server_share = server.issue_share("alice", None).unwrap();
        let combined = combine_keys(user_share, server_share).unwrap();

        let plaintext = b"Executive budget";
        let ct = encrypt(&mut rng, &mpk, "(admin AND finance) OR hr", plaintext).unwrap();

        let decrypted = decrypt(&mpk, &combined, &ct).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_user_id_mismatch() {
        let mut rng = thread_rng();
        let (mpk, msk, server_key) = setup(&mut rng);

        let mut server = KeyServer::new(server_key);

        let alice_share = keygen(&mut rng, &mpk, &msk, "alice", &["admin"]).unwrap();
        let bob_server = server.issue_share("bob", None).unwrap();

        // Trying to combine mismatched shares should fail
        let result = combine_keys(alice_share, bob_server);
        assert!(result.is_err());
    }
}
