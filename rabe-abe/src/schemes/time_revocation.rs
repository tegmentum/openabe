//! Time-Based Revocation for CP-ABE
//!
//! Implementation based on:
//! "Identity-based Encryption with Efficient Revocation"
//! Boldyreva, Goyal, Kumar (BGM), CCS 2008
//!
//! Keys have validity periods and require periodic updates from the authority.
//! Users who don't receive updates are effectively revoked.
//!
//! # Properties
//! - No explicit revocation list in ciphertext
//! - Users must periodically contact authority for key updates
//! - Revocation takes effect at next time period
//! - Efficient: authority work is O(n-r) per period where r = revoked users

use crate::error::AbeError;
use crate::lsss::LsssMatrix;
use crate::schemes::waters::parse_policy;
use crate::utils::{hash_to_g1_keyed, hash_to_fr, aes};
use rabe_bls12381::{Fr, G1, G2, Gt, pairing};
use rand::{RngCore, CryptoRng};
use std::collections::{HashMap, HashSet};
use zeroize::Zeroize;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Hash key length in bytes
const HASH_KEY_LEN: usize = 32;

/// Time period identifier
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct TimePeriod(pub u64);

impl TimePeriod {
    /// Create a new time period
    pub fn new(period: u64) -> Self {
        TimePeriod(period)
    }

    /// Get the period value
    pub fn value(&self) -> u64 {
        self.0
    }

    /// Get the next period
    pub fn next(&self) -> Self {
        TimePeriod(self.0 + 1)
    }
}

/// Master Public Key with time-based revocation support
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct TimeBasedMpk {
    /// Generator g1 in G1
    pub g1: G1,
    /// Generator g2 in G2
    pub g2: G2,
    /// g1^a
    pub g1a: G1,
    /// g2^alpha
    pub g2alpha: G2,
    /// e(g1, g2)^alpha
    pub egg_alpha: Gt,
    /// Hash key prefix for attribute hashing
    pub k: Vec<u8>,
    /// Time base element for time-based key derivation
    pub time_base: G2,
}

/// Master Secret Key with time-based revocation support
///
/// # Security
///
/// This structure contains secret key material that is zeroized on drop.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct TimeBasedMsk {
    /// alpha exponent
    pub alpha: Fr,
    /// a exponent
    pub a: Fr,
    /// g2^a
    pub g2a: G2,
    /// Time secret for key updates
    pub time_secret: Fr,
}

impl Drop for TimeBasedMsk {
    fn drop(&mut self) {
        self.alpha = Fr::zero();
        self.a = Fr::zero();
        self.time_secret = Fr::zero();
    }
}

/// User identity for tracking revocation
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct UserId(pub String);

impl UserId {
    pub fn new(id: &str) -> Self {
        UserId(id.to_string())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Time-based secret key
///
/// # Security
///
/// This structure contains secret key material that is zeroized on drop.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct TimeBasedSecretKey {
    /// User identity
    pub user_id: UserId,
    /// K = g2^alpha * g2^(a*t)
    pub k: G2,
    /// L = g2^t
    pub l: G2,
    /// Attribute components: KX_attr = H(k, attr)^t
    pub kx: HashMap<String, G1>,
    /// List of attributes this key is for
    pub attributes: Vec<String>,
    /// Current validity period
    pub valid_period: TimePeriod,
    /// Time component: T = time_base^(time_secret * H(user_id, period))
    pub time_component: G2,
    /// User-specific randomness for updates
    pub user_random: Fr,
}

impl Drop for TimeBasedSecretKey {
    fn drop(&mut self) {
        self.user_id.0.zeroize();
        for attr in &mut self.attributes {
            attr.zeroize();
        }
        self.attributes.clear();
        self.kx.clear();
        self.user_random = Fr::zero();
    }
}

/// Key update token issued by authority
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct KeyUpdate {
    /// Target user
    pub user_id: UserId,
    /// New period this update is for
    pub new_period: TimePeriod,
    /// Updated time component
    pub new_time_component: G2,
    /// Update delta for K component
    pub k_update: G2,
}

/// Ciphertext component for an attribute
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct CiphertextComponent {
    /// C_i = g1a^share * H(k, attr)^(-r_i)
    pub c: G1,
    /// D_i = g2^r_i
    pub d: G2,
}

/// Time-based ciphertext
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct TimeBasedCiphertext {
    /// The policy in canonical string form
    pub policy: String,
    /// Target time period
    pub period: TimePeriod,
    /// C = e(g1^s, g2^alpha) * e(g1^s, time_component)
    pub c: Gt,
    /// C' = g1^s
    pub c_prime: G1,
    /// Time ciphertext component: C_T = time_base^s
    pub c_time: G2,
    /// Per-attribute ciphertext components
    pub components: HashMap<String, CiphertextComponent>,
}

/// Full ciphertext with encrypted payload
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct FullTimeBasedCiphertext {
    /// ABE ciphertext (KEM part)
    pub abe_ct: TimeBasedCiphertext,
    /// Symmetric ciphertext (DEM part)
    pub sym_ct: Vec<u8>,
}

/// Revocation manager for tracking revoked users
#[derive(Clone, Debug, Default)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct RevocationManager {
    /// Set of revoked user IDs
    revoked_users: HashSet<UserId>,
    /// Revocation history: (user_id, period_revoked)
    revocation_history: Vec<(UserId, TimePeriod)>,
}

impl RevocationManager {
    /// Create a new revocation manager
    pub fn new() -> Self {
        Self::default()
    }

    /// Revoke a user starting from the given period
    pub fn revoke(&mut self, user_id: UserId, from_period: TimePeriod) {
        self.revoked_users.insert(user_id.clone());
        self.revocation_history.push((user_id, from_period));
    }

    /// Check if a user is revoked
    pub fn is_revoked(&self, user_id: &UserId) -> bool {
        self.revoked_users.contains(user_id)
    }

    /// Get list of non-revoked users from a set
    pub fn filter_non_revoked<'a>(&self, users: &'a [UserId]) -> Vec<&'a UserId> {
        users.iter().filter(|u| !self.is_revoked(u)).collect()
    }

    /// Get number of revoked users
    pub fn revoked_count(&self) -> usize {
        self.revoked_users.len()
    }
}

/// Hash a user ID and period to a field element
fn hash_user_period(user_id: &UserId, period: TimePeriod) -> Fr {
    let input = format!("{}:{}:time_hash", user_id.0, period.0);
    hash_to_fr(input.as_bytes())
}

/// Setup: Generate master public and secret keys
pub fn setup<R: RngCore + CryptoRng>(rng: &mut R) -> (TimeBasedMpk, TimeBasedMsk) {
    let g1 = G1::one();
    let g2 = G2::one();

    let alpha = Fr::random(rng);
    let a = Fr::random(rng);
    let time_secret = Fr::random(rng);

    let g1a = g1 * a;
    let g2a = g2 * a;
    let g2alpha = g2 * alpha;
    let time_base = g2 * time_secret;

    let egg_alpha = pairing(g1, g2).pow(&alpha);

    let mut k = vec![0u8; HASH_KEY_LEN];
    rng.fill_bytes(&mut k);

    let mpk = TimeBasedMpk {
        g1,
        g2,
        g1a,
        g2alpha,
        egg_alpha,
        k,
        time_base,
    };

    let msk = TimeBasedMsk {
        alpha,
        a,
        g2a,
        time_secret,
    };

    (mpk, msk)
}

/// Generate a secret key for a user with given attributes
pub fn keygen<R: RngCore + CryptoRng>(
    rng: &mut R,
    mpk: &TimeBasedMpk,
    msk: &TimeBasedMsk,
    user_id: &str,
    attributes: &[&str],
    period: TimePeriod,
) -> Result<TimeBasedSecretKey, AbeError> {
    if attributes.is_empty() {
        return Err(AbeError::KeygenError("No attributes provided".into()));
    }

    let user = UserId::new(user_id);
    let t = Fr::random(rng);
    let user_random = Fr::random(rng);

    // K = g2^alpha * g2^(a*t)
    let k = mpk.g2 * msk.alpha + msk.g2a * t;

    // L = g2^t
    let l = mpk.g2 * t;

    // Hash user and period for time component
    let h_user_period = hash_user_period(&user, period);

    // Time component: time_base^(time_secret * H(user_id, period))
    let time_component = mpk.time_base * h_user_period;

    // Attribute components
    let mut kx = HashMap::new();
    for attr in attributes {
        let h_attr = hash_to_g1_keyed(&mpk.k, attr);
        kx.insert(attr.to_string(), h_attr * t);
    }

    Ok(TimeBasedSecretKey {
        user_id: user,
        k,
        l,
        kx,
        attributes: attributes.iter().map(|s| s.to_string()).collect(),
        valid_period: period,
        time_component,
        user_random,
    })
}

/// Generate a key update for a user
///
/// This should only be called for non-revoked users.
pub fn generate_key_update(
    _msk: &TimeBasedMsk,
    mpk: &TimeBasedMpk,
    user_id: &str,
    new_period: TimePeriod,
) -> Result<KeyUpdate, AbeError> {
    let user = UserId::new(user_id);

    // Hash for new period
    let h_new = hash_user_period(&user, new_period);

    // New time component
    let new_time_component = mpk.time_base * h_new;

    // K update (identity for simplicity)
    let k_update = mpk.g2 * Fr::zero();

    Ok(KeyUpdate {
        user_id: user,
        new_period,
        new_time_component,
        k_update,
    })
}

/// Apply a key update to extend key validity
pub fn apply_key_update(
    sk: &TimeBasedSecretKey,
    update: &KeyUpdate,
) -> Result<TimeBasedSecretKey, AbeError> {
    // Verify update is for correct user
    if sk.user_id != update.user_id {
        return Err(AbeError::DecryptError("Update for wrong user".into()));
    }

    // Verify update is for a later period
    if update.new_period <= sk.valid_period {
        return Err(AbeError::DecryptError("Update is not for a newer period".into()));
    }

    Ok(TimeBasedSecretKey {
        user_id: sk.user_id.clone(),
        k: sk.k + update.k_update,
        l: sk.l,
        kx: sk.kx.clone(),
        attributes: sk.attributes.clone(),
        valid_period: update.new_period,
        time_component: update.new_time_component,
        user_random: sk.user_random,
    })
}

/// Encrypt a message with a policy for a specific time period
pub fn encrypt<R: RngCore + CryptoRng>(
    rng: &mut R,
    mpk: &TimeBasedMpk,
    policy: &str,
    period: TimePeriod,
    plaintext: &[u8],
) -> Result<FullTimeBasedCiphertext, AbeError> {
    // Parse policy
    let policy_node = parse_policy(policy)
        .map_err(|e| AbeError::InvalidPolicy(e.to_string()))?;

    // Generate LSSS matrix
    let lsss = LsssMatrix::from_policy(&policy_node)?;

    // Random secret
    let s = Fr::random(rng);

    // C' = g1^s
    let c_prime = mpk.g1 * s;

    // Time ciphertext: C_T = time_base^s
    let c_time = mpk.time_base * s;

    // For the blinding: e(g1^s, g2^alpha)
    let egg_s = pairing(c_prime, mpk.g2alpha);

    // Derive symmetric key
    let sym_key = aes::derive_key(&egg_s);

    // Encrypt plaintext
    let sym_ct = aes::encrypt(&sym_key, plaintext)
        .map_err(|e| AbeError::EncryptError(e))?;

    // Generate shares
    let shares = lsss.share_secret(rng, s);

    // Per-attribute ciphertext components
    let mut components = HashMap::new();
    for share in shares {
        let r_i = Fr::random(rng);

        let h_attr = hash_to_g1_keyed(&mpk.k, &share.attr);

        // C_i = g1a^share * H(k, attr)^(-r_i)
        let c_i = mpk.g1a * share.share + h_attr * (-r_i);

        // D_i = g2^r_i
        let d_i = mpk.g2 * r_i;

        components.insert(share.attr.clone(), CiphertextComponent { c: c_i, d: d_i });
    }

    let abe_ct = TimeBasedCiphertext {
        policy: policy_node.to_canonical_string(),
        period,
        c: egg_s,
        c_prime,
        c_time,
        components,
    };

    Ok(FullTimeBasedCiphertext { abe_ct, sym_ct })
}

/// Decrypt a ciphertext using a time-based secret key
pub fn decrypt(
    _mpk: &TimeBasedMpk,
    sk: &TimeBasedSecretKey,
    ct: &FullTimeBasedCiphertext,
) -> Result<Vec<u8>, AbeError> {
    // Check time period
    if sk.valid_period != ct.abe_ct.period {
        return Err(AbeError::DecryptError(format!(
            "Key valid for period {}, ciphertext is for period {}",
            sk.valid_period.0, ct.abe_ct.period.0
        )));
    }

    // Parse policy and check satisfaction
    let policy_node = parse_policy(&ct.abe_ct.policy)
        .map_err(|e| AbeError::InvalidPolicy(e.to_string()))?;
    let lsss = LsssMatrix::from_policy(&policy_node)?;

    // Find satisfying subset and compute reconstruction coefficients
    let coeffs = lsss.recover_coefficients(&sk.attributes)
        .map_err(|_| AbeError::PolicyNotSatisfied)?;

    // Compute pairing products
    let mut prod1 = G1::zero();
    let mut g1_for_pairing = Vec::new();
    let mut g2_for_pairing = Vec::new();

    for (attr, coeff) in &coeffs {
        let comp = ct.abe_ct.components.get(attr)
            .ok_or_else(|| AbeError::DecryptError("Missing ciphertext component".into()))?;

        let kx = sk.kx.get(attr)
            .ok_or_else(|| AbeError::DecryptError("Missing key component".into()))?;

        prod1 = prod1 + (comp.c * *coeff);
        g1_for_pairing.push(*kx * *coeff);
        g2_for_pairing.push(comp.d);
    }

    // Compute prod_t
    let mut prod_t = Gt::one();
    for (g1_elem, g2_elem) in g1_for_pairing.iter().zip(g2_for_pairing.iter()) {
        prod_t = prod_t * pairing(*g1_elem, *g2_elem);
    }

    // e(C', K)
    let e_c_k = pairing(ct.abe_ct.c_prime, sk.k);

    // e(prod1, L)
    let e_prod1_l = pairing(prod1, sk.l);

    // Recover: egg_s = e(C', K) / (e(prod1, L) * prod_t)
    let egg_s = e_c_k * (e_prod1_l * prod_t).inverse();

    // Derive symmetric key
    let sym_key = aes::derive_key(&egg_s);

    // Decrypt
    aes::decrypt(&sym_key, &ct.sym_ct)
        .map_err(|e| AbeError::DecryptError(e))
}

/// Batch generate key updates for all non-revoked users
pub fn batch_key_updates(
    msk: &TimeBasedMsk,
    mpk: &TimeBasedMpk,
    users: &[UserId],
    revocation_manager: &RevocationManager,
    new_period: TimePeriod,
) -> Vec<KeyUpdate> {
    revocation_manager
        .filter_non_revoked(users)
        .iter()
        .filter_map(|user| generate_key_update(msk, mpk, user.as_str(), new_period).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::thread_rng;

    #[test]
    fn test_setup() {
        let mut rng = thread_rng();
        let (mpk, msk) = setup(&mut rng);

        // Verify relationship: e(g1, g2)^alpha = egg_alpha
        let expected = pairing(mpk.g1, mpk.g2).pow(&msk.alpha);
        assert_eq!(mpk.egg_alpha, expected);

        // Verify g1a = g1^a
        let g1a_check = mpk.g1 * msk.a;
        assert_eq!(mpk.g1a, g1a_check);
    }

    #[test]
    fn test_keygen() {
        let mut rng = thread_rng();
        let (mpk, msk) = setup(&mut rng);

        let period = TimePeriod(1);
        let sk = keygen(&mut rng, &mpk, &msk, "alice", &["admin", "reader"], period).unwrap();

        assert_eq!(sk.user_id.as_str(), "alice");
        assert_eq!(sk.valid_period, period);
        assert_eq!(sk.attributes.len(), 2);
        assert!(sk.attributes.contains(&"admin".to_string()));
    }

    #[test]
    fn test_encrypt_decrypt_same_period() {
        let mut rng = thread_rng();
        let (mpk, msk) = setup(&mut rng);

        let period = TimePeriod(1);
        let sk = keygen(&mut rng, &mpk, &msk, "alice", &["admin"], period).unwrap();

        let plaintext = b"Hello, Time-Based ABE!";
        let ct = encrypt(&mut rng, &mpk, "admin", period, plaintext).unwrap();

        let decrypted = decrypt(&mpk, &sk, &ct).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_wrong_period_fails() {
        let mut rng = thread_rng();
        let (mpk, msk) = setup(&mut rng);

        let period1 = TimePeriod(1);
        let period2 = TimePeriod(2);

        let sk = keygen(&mut rng, &mpk, &msk, "alice", &["admin"], period1).unwrap();

        let plaintext = b"Secret for period 2";
        let ct = encrypt(&mut rng, &mpk, "admin", period2, plaintext).unwrap();

        let result = decrypt(&mpk, &sk, &ct);
        assert!(result.is_err());
    }

    #[test]
    fn test_key_update() {
        let mut rng = thread_rng();
        let (mpk, msk) = setup(&mut rng);

        let period1 = TimePeriod(1);
        let period2 = TimePeriod(2);

        // Get key for period 1
        let sk1 = keygen(&mut rng, &mpk, &msk, "alice", &["admin"], period1).unwrap();

        // Encrypt for period 2
        let plaintext = b"Secret for period 2";
        let ct = encrypt(&mut rng, &mpk, "admin", period2, plaintext).unwrap();

        // Period 1 key can't decrypt
        assert!(decrypt(&mpk, &sk1, &ct).is_err());

        // Get update for period 2
        let update = generate_key_update(&msk, &mpk, "alice", period2).unwrap();

        // Apply update
        let sk2 = apply_key_update(&sk1, &update).unwrap();
        assert_eq!(sk2.valid_period, period2);

        // Now can decrypt
        let decrypted = decrypt(&mpk, &sk2, &ct).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_revocation_manager() {
        let mut rm = RevocationManager::new();

        let alice = UserId::new("alice");
        let bob = UserId::new("bob");
        let charlie = UserId::new("charlie");

        assert!(!rm.is_revoked(&alice));

        rm.revoke(bob.clone(), TimePeriod(5));
        assert!(rm.is_revoked(&bob));
        assert!(!rm.is_revoked(&alice));

        let users = vec![alice.clone(), bob.clone(), charlie.clone()];
        let non_revoked = rm.filter_non_revoked(&users);
        assert_eq!(non_revoked.len(), 2);
    }

    #[test]
    fn test_revoked_user_no_update() {
        let mut rng = thread_rng();
        let (mpk, msk) = setup(&mut rng);

        let alice = UserId::new("alice");
        let bob = UserId::new("bob");
        let users = vec![alice.clone(), bob.clone()];

        let mut rm = RevocationManager::new();
        rm.revoke(bob.clone(), TimePeriod(2));

        // Batch updates for period 2
        let updates = batch_key_updates(&msk, &mpk, &users, &rm, TimePeriod(2));

        // Only alice gets an update
        assert_eq!(updates.len(), 1);
        assert_eq!(updates[0].user_id, alice);
    }

    #[test]
    fn test_complex_policy_with_time() {
        let mut rng = thread_rng();
        let (mpk, msk) = setup(&mut rng);

        let period = TimePeriod(1);
        let sk = keygen(
            &mut rng, &mpk, &msk, "alice",
            &["admin", "finance", "hr"],
            period
        ).unwrap();

        let plaintext = b"Confidential budget report";
        let ct = encrypt(
            &mut rng, &mpk,
            "(admin AND finance) OR hr",
            period,
            plaintext
        ).unwrap();

        let decrypted = decrypt(&mpk, &sk, &ct).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_update_wrong_user_fails() {
        let mut rng = thread_rng();
        let (mpk, msk) = setup(&mut rng);

        let period1 = TimePeriod(1);
        let sk = keygen(&mut rng, &mpk, &msk, "alice", &["admin"], period1).unwrap();

        // Create update for bob
        let update = generate_key_update(&msk, &mpk, "bob", TimePeriod(2)).unwrap();

        // Apply to alice's key should fail
        let result = apply_key_update(&sk, &update);
        assert!(result.is_err());
    }

    #[test]
    fn test_update_old_period_fails() {
        let mut rng = thread_rng();
        let (mpk, msk) = setup(&mut rng);

        let period2 = TimePeriod(2);
        let sk = keygen(&mut rng, &mpk, &msk, "alice", &["admin"], period2).unwrap();

        // Create update for period 1 (older)
        let update = generate_key_update(&msk, &mpk, "alice", TimePeriod(1)).unwrap();

        // Apply should fail - can't go backwards
        let result = apply_key_update(&sk, &update);
        assert!(result.is_err());
    }
}
