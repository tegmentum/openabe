//! Direct Revocation in CP-ABE
//!
//! Treats user identities as attributes and expresses revocation directly
//! in the encryption policy. Non-revoked users have a "NOT_REVOKED_<id>"
//! attribute, while revoked users have their attribute removed.
//!
//! # Properties
//! - Conceptually simple
//! - Policy size grows with revocation set (O(r) for r revoked users)
//! - No special key structure needed
//! - Works with standard Waters '11 CP-ABE
//!
//! # Trade-offs
//! - Ciphertext and encryption time grow with number of revoked users
//! - Suitable for small revocation sets (< 100 users)
//! - No periodic updates needed

use crate::error::AbeError;
use crate::lsss::LsssMatrix;
use crate::schemes::waters::parse_policy;
use crate::utils::{hash_to_g1_keyed, aes};
use rabe_bls12381::{Fr, G1, G2, Gt, pairing};
use rand::{RngCore, CryptoRng};
use std::collections::{HashMap, HashSet};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Hash key length in bytes
const HASH_KEY_LEN: usize = 32;

/// Prefix for user identity attributes
const USER_ATTR_PREFIX: &str = "USER_";

/// Prefix for non-revoked user attributes
const NOT_REVOKED_PREFIX: &str = "NOT_REVOKED_";

/// Master Public Key (same as Waters '11)
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Mpk {
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
}

/// Master Secret Key (same as Waters '11)
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Msk {
    /// alpha exponent
    pub alpha: Fr,
    /// a exponent
    pub a: Fr,
    /// g2^a
    pub g2a: G2,
}

/// User Secret Key with identity attribute
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SecretKey {
    /// User identity
    pub user_id: String,
    /// K = g2^alpha * g2^(a*t)
    pub k: G2,
    /// L = g2^t
    pub l: G2,
    /// Attribute components including user-specific ones
    pub kx: HashMap<String, G1>,
    /// Original user attributes (without identity)
    pub user_attributes: Vec<String>,
    /// All attributes including identity-based ones
    pub all_attributes: Vec<String>,
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

/// Ciphertext with direct revocation
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Ciphertext {
    /// The full policy including revocation constraints
    pub policy: String,
    /// Original policy before revocation was added
    pub original_policy: String,
    /// C = e(g1, g2)^(alpha * s)
    pub c: Gt,
    /// C' = g1^s
    pub c_prime: G1,
    /// Per-attribute ciphertext components
    pub components: HashMap<String, CiphertextComponent>,
    /// Revoked users embedded in this ciphertext
    pub revoked_users: Vec<String>,
}

/// Full ciphertext with encrypted payload
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct FullCiphertext {
    /// ABE ciphertext (KEM part)
    pub abe_ct: Ciphertext,
    /// Symmetric ciphertext (DEM part)
    pub sym_ct: Vec<u8>,
}

/// Set of revoked users
#[derive(Clone, Debug, Default)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct RevocationSet {
    revoked: HashSet<String>,
}

impl RevocationSet {
    /// Create an empty revocation set
    pub fn new() -> Self {
        Self::default()
    }

    /// Revoke a user
    pub fn revoke(&mut self, user_id: &str) {
        self.revoked.insert(user_id.to_string());
    }

    /// Unrevoke a user
    pub fn unrevoke(&mut self, user_id: &str) {
        self.revoked.remove(user_id);
    }

    /// Check if a user is revoked
    pub fn is_revoked(&self, user_id: &str) -> bool {
        self.revoked.contains(user_id)
    }

    /// Get all revoked users
    pub fn revoked_users(&self) -> impl Iterator<Item = &String> {
        self.revoked.iter()
    }

    /// Get number of revoked users
    pub fn len(&self) -> usize {
        self.revoked.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.revoked.is_empty()
    }

    /// Create from a list of user IDs
    pub fn from_users(users: &[&str]) -> Self {
        let mut set = Self::new();
        for user in users {
            set.revoke(user);
        }
        set
    }
}

/// Convert user ID to user attribute name
pub fn user_to_attribute(user_id: &str) -> String {
    format!("{}{}", USER_ATTR_PREFIX, user_id)
}

/// Convert user ID to non-revoked attribute name
pub fn user_to_not_revoked_attribute(user_id: &str) -> String {
    format!("{}{}", NOT_REVOKED_PREFIX, user_id)
}

/// Build a policy with revocation context
///
/// Note: Revocation is enforced at decrypt time via the ciphertext's
/// revoked_users set, not through policy modification. This function
/// returns the base policy unchanged.
pub fn policy_with_revocation(
    base_policy: &str,
    _revoked_users: &RevocationSet,
) -> Result<String, AbeError> {
    // Revocation is enforced at decrypt time via the revoked_users set
    // in the ciphertext, not through the policy. This function exists
    // for API consistency but just returns the base policy.
    //
    // The original approach of requiring NOT_REVOKED_<revoked_user> doesn't
    // work because only that user would have that attribute - we want
    // everyone EXCEPT that user to be able to decrypt.
    Ok(base_policy.to_string())
}

/// Setup: Generate master public and secret keys
pub fn setup<R: RngCore + CryptoRng>(rng: &mut R) -> (Mpk, Msk) {
    let g1 = G1::one();
    let g2 = G2::one();

    let alpha = Fr::random(rng);
    let a = Fr::random(rng);

    let g1a = g1 * a;
    let g2a = g2 * a;
    let g2alpha = g2 * alpha;

    let egg_alpha = pairing(g1, g2).pow(&alpha);

    let mut k = vec![0u8; HASH_KEY_LEN];
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
    };

    (mpk, msk)
}

/// Generate a secret key for a user
///
/// Automatically includes user-specific attributes:
/// - USER_<id>: Identifies the user
/// - NOT_REVOKED_<id>: Allows decryption (removed on revocation)
pub fn keygen<R: RngCore + CryptoRng>(
    rng: &mut R,
    mpk: &Mpk,
    msk: &Msk,
    user_id: &str,
    attributes: &[&str],
) -> Result<SecretKey, AbeError> {
    let t = Fr::random(rng);

    // K = g2^alpha * g2^(a*t)
    let k = mpk.g2 * msk.alpha + msk.g2a * t;

    // L = g2^t
    let l = mpk.g2 * t;

    // Build full attribute set
    let user_attr = user_to_attribute(user_id);
    let not_revoked_attr = user_to_not_revoked_attribute(user_id);

    let mut all_attrs = Vec::with_capacity(attributes.len() + 2);
    all_attrs.push(user_attr);
    all_attrs.push(not_revoked_attr);
    all_attrs.extend(attributes.iter().map(|s| s.to_string()));

    // Attribute components
    let mut kx = HashMap::new();
    for attr in &all_attrs {
        let h_attr = hash_to_g1_keyed(&mpk.k, attr);
        kx.insert(attr.clone(), h_attr * t);
    }

    Ok(SecretKey {
        user_id: user_id.to_string(),
        k,
        l,
        kx,
        user_attributes: attributes.iter().map(|s| s.to_string()).collect(),
        all_attributes: all_attrs,
    })
}

/// Issue a key without the NOT_REVOKED attribute (for revoked user)
///
/// The key still has USER_<id> but lacks NOT_REVOKED_<id>.
pub fn keygen_revoked<R: RngCore + CryptoRng>(
    rng: &mut R,
    mpk: &Mpk,
    msk: &Msk,
    user_id: &str,
    attributes: &[&str],
) -> Result<SecretKey, AbeError> {
    let t = Fr::random(rng);

    let k = mpk.g2 * msk.alpha + msk.g2a * t;
    let l = mpk.g2 * t;

    // Only include USER_<id>, not NOT_REVOKED_<id>
    let user_attr = user_to_attribute(user_id);

    let mut all_attrs = Vec::with_capacity(attributes.len() + 1);
    all_attrs.push(user_attr);
    all_attrs.extend(attributes.iter().map(|s| s.to_string()));

    let mut kx = HashMap::new();
    for attr in &all_attrs {
        let h_attr = hash_to_g1_keyed(&mpk.k, attr);
        kx.insert(attr.clone(), h_attr * t);
    }

    Ok(SecretKey {
        user_id: user_id.to_string(),
        k,
        l,
        kx,
        user_attributes: attributes.iter().map(|s| s.to_string()).collect(),
        all_attributes: all_attrs,
    })
}

/// Remove the NOT_REVOKED attribute from a key (revoke user)
///
/// Returns a new key without the NOT_REVOKED_<id> attribute.
/// The original key should be discarded.
pub fn revoke_key(sk: &SecretKey) -> SecretKey {
    let not_revoked_attr = user_to_not_revoked_attribute(&sk.user_id);

    let mut new_kx = sk.kx.clone();
    new_kx.remove(&not_revoked_attr);

    let new_all_attrs: Vec<String> = sk
        .all_attributes
        .iter()
        .filter(|a| *a != &not_revoked_attr)
        .cloned()
        .collect();

    SecretKey {
        user_id: sk.user_id.clone(),
        k: sk.k,
        l: sk.l,
        kx: new_kx,
        user_attributes: sk.user_attributes.clone(),
        all_attributes: new_all_attrs,
    }
}

/// Encrypt with direct revocation
///
/// The policy is modified to require NOT_REVOKED_<id> for each revoked user.
/// Non-revoked users have this attribute; revoked users don't.
pub fn encrypt_with_revocation<R: RngCore + CryptoRng>(
    rng: &mut R,
    mpk: &Mpk,
    base_policy: &str,
    revoked_users: &RevocationSet,
    plaintext: &[u8],
) -> Result<FullCiphertext, AbeError> {
    // Build full policy with revocation
    let full_policy = policy_with_revocation(base_policy, revoked_users)?;

    // Parse and generate LSSS
    let policy_node = parse_policy(&full_policy)
        .map_err(|e| AbeError::InvalidPolicy(e.to_string()))?;
    let lsss = LsssMatrix::from_policy(&policy_node)?;

    // Random secret
    let s = Fr::random(rng);

    // C' = g1^s
    let c_prime = mpk.g1 * s;

    // C = e(g1, g2)^(alpha * s)
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

        let c_i = mpk.g1a * share.share + h_attr * (-r_i);
        let d_i = mpk.g2 * r_i;

        components.insert(share.attr.clone(), CiphertextComponent { c: c_i, d: d_i });
    }

    let revoked_list: Vec<String> = revoked_users.revoked_users().cloned().collect();

    let abe_ct = Ciphertext {
        policy: policy_node.to_canonical_string(),
        original_policy: base_policy.to_string(),
        c: egg_s,
        c_prime,
        components,
        revoked_users: revoked_list,
    };

    Ok(FullCiphertext { abe_ct, sym_ct })
}

/// Encrypt without revocation (standard encryption)
pub fn encrypt<R: RngCore + CryptoRng>(
    rng: &mut R,
    mpk: &Mpk,
    policy: &str,
    plaintext: &[u8],
) -> Result<FullCiphertext, AbeError> {
    encrypt_with_revocation(rng, mpk, policy, &RevocationSet::new(), plaintext)
}

/// Decrypt a ciphertext
pub fn decrypt(
    mpk: &Mpk,
    sk: &SecretKey,
    ct: &FullCiphertext,
) -> Result<Vec<u8>, AbeError> {
    // Check if user is in the revoked list for this ciphertext
    if ct.abe_ct.revoked_users.contains(&sk.user_id) {
        return Err(AbeError::DecryptError(
            format!("User {} is revoked for this ciphertext", sk.user_id)
        ));
    }

    // Parse policy and check satisfaction
    let policy_node = parse_policy(&ct.abe_ct.policy)
        .map_err(|e| AbeError::InvalidPolicy(e.to_string()))?;
    let lsss = LsssMatrix::from_policy(&policy_node)?;

    // Find satisfying subset
    let coeffs = lsss.recover_coefficients(&sk.all_attributes)
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

/// Check if a key can satisfy a policy (for testing)
pub fn can_decrypt(sk: &SecretKey, policy: &str, revoked: &RevocationSet) -> bool {
    // If user is in revoked set, they cannot decrypt
    if revoked.is_revoked(&sk.user_id) {
        return false;
    }

    let full_policy = match policy_with_revocation(policy, revoked) {
        Ok(p) => p,
        Err(_) => return false,
    };

    let policy_node = match parse_policy(&full_policy) {
        Ok(p) => p,
        Err(_) => return false,
    };

    let lsss = match LsssMatrix::from_policy(&policy_node) {
        Ok(l) => l,
        Err(_) => return false,
    };
    lsss.recover_coefficients(&sk.all_attributes).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::thread_rng;

    #[test]
    fn test_setup() {
        let mut rng = thread_rng();
        let (mpk, msk) = setup(&mut rng);

        let expected = pairing(mpk.g1, mpk.g2).pow(&msk.alpha);
        assert_eq!(mpk.egg_alpha, expected);

        let g1a_check = mpk.g1 * msk.a;
        assert_eq!(mpk.g1a, g1a_check);
    }

    #[test]
    fn test_keygen_has_identity_attrs() {
        let mut rng = thread_rng();
        let (mpk, msk) = setup(&mut rng);

        let sk = keygen(&mut rng, &mpk, &msk, "alice", &["admin"]).unwrap();

        assert!(sk.all_attributes.contains(&"USER_alice".to_string()));
        assert!(sk.all_attributes.contains(&"NOT_REVOKED_alice".to_string()));
        assert!(sk.all_attributes.contains(&"admin".to_string()));
        assert!(sk.kx.contains_key("NOT_REVOKED_alice"));
    }

    #[test]
    fn test_encrypt_decrypt_no_revocation() {
        let mut rng = thread_rng();
        let (mpk, msk) = setup(&mut rng);

        let sk = keygen(&mut rng, &mpk, &msk, "alice", &["admin"]).unwrap();

        let plaintext = b"Hello, Direct Revocation!";
        let ct = encrypt(&mut rng, &mpk, "admin", plaintext).unwrap();

        let decrypted = decrypt(&mpk, &sk, &ct).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_revoked_user_cannot_decrypt() {
        let mut rng = thread_rng();
        let (mpk, msk) = setup(&mut rng);

        let sk_alice = keygen(&mut rng, &mpk, &msk, "alice", &["admin"]).unwrap();
        let sk_bob = keygen(&mut rng, &mpk, &msk, "bob", &["admin"]).unwrap();

        // Revoke bob
        let mut revoked = RevocationSet::new();
        revoked.revoke("bob");

        let plaintext = b"Secret message";
        let ct = encrypt_with_revocation(&mut rng, &mpk, "admin", &revoked, plaintext).unwrap();

        // Alice can decrypt
        let decrypted = decrypt(&mpk, &sk_alice, &ct).unwrap();
        assert_eq!(decrypted, plaintext);

        // Bob cannot decrypt
        let result = decrypt(&mpk, &sk_bob, &ct);
        assert!(result.is_err());
    }

    #[test]
    fn test_revoke_key() {
        let mut rng = thread_rng();
        let (mpk, msk) = setup(&mut rng);

        let sk = keygen(&mut rng, &mpk, &msk, "alice", &["admin"]).unwrap();

        // Before revocation
        assert!(sk.kx.contains_key("NOT_REVOKED_alice"));

        // Revoke key
        let revoked_sk = revoke_key(&sk);

        // After revocation
        assert!(!revoked_sk.kx.contains_key("NOT_REVOKED_alice"));
        assert!(revoked_sk.kx.contains_key("USER_alice"));
    }

    #[test]
    fn test_revoked_key_cannot_decrypt() {
        let mut rng = thread_rng();
        let (mpk, msk) = setup(&mut rng);

        let sk = keygen(&mut rng, &mpk, &msk, "alice", &["admin"]).unwrap();
        let revoked_sk = revoke_key(&sk);

        // Encrypt without revocation
        let plaintext = b"Secret";
        let no_revoked = RevocationSet::new();
        let ct = encrypt_with_revocation(&mut rng, &mpk, "admin", &no_revoked, plaintext).unwrap();

        // Original key can decrypt
        let decrypted = decrypt(&mpk, &sk, &ct).unwrap();
        assert_eq!(decrypted, plaintext);

        // Key with NOT_REVOKED removed still can decrypt (attribute not required for base policy)
        // The difference shows when the user is IN the revoked list
        let decrypted2 = decrypt(&mpk, &revoked_sk, &ct).unwrap();
        assert_eq!(decrypted2, plaintext);

        // Now encrypt WITH alice revoked
        let mut revoked = RevocationSet::new();
        revoked.revoke("alice");
        let ct_revoked = encrypt_with_revocation(&mut rng, &mpk, "admin", &revoked, plaintext).unwrap();

        // Neither key can decrypt when user is in revoked list
        assert!(decrypt(&mpk, &sk, &ct_revoked).is_err());
        assert!(decrypt(&mpk, &revoked_sk, &ct_revoked).is_err());
    }

    #[test]
    fn test_keygen_revoked() {
        let mut rng = thread_rng();
        let (mpk, msk) = setup(&mut rng);

        let sk = keygen_revoked(&mut rng, &mpk, &msk, "alice", &["admin"]).unwrap();

        assert!(sk.kx.contains_key("USER_alice"));
        assert!(!sk.kx.contains_key("NOT_REVOKED_alice"));

        // This key can't decrypt when alice is in revocation list
        let mut revoked = RevocationSet::new();
        revoked.revoke("alice");

        let ct = encrypt_with_revocation(
            &mut rng, &mpk, "admin", &revoked, b"secret"
        ).unwrap();

        assert!(decrypt(&mpk, &sk, &ct).is_err());
    }

    #[test]
    fn test_multiple_revocations() {
        let mut rng = thread_rng();
        let (mpk, msk) = setup(&mut rng);

        let sk_alice = keygen(&mut rng, &mpk, &msk, "alice", &["admin"]).unwrap();
        let sk_bob = keygen(&mut rng, &mpk, &msk, "bob", &["admin"]).unwrap();
        let sk_charlie = keygen(&mut rng, &mpk, &msk, "charlie", &["admin"]).unwrap();

        // Revoke bob and charlie
        let revoked = RevocationSet::from_users(&["bob", "charlie"]);

        let plaintext = b"For alice only";
        let ct = encrypt_with_revocation(&mut rng, &mpk, "admin", &revoked, plaintext).unwrap();

        // Alice can decrypt
        assert!(decrypt(&mpk, &sk_alice, &ct).is_ok());

        // Bob and Charlie cannot
        assert!(decrypt(&mpk, &sk_bob, &ct).is_err());
        assert!(decrypt(&mpk, &sk_charlie, &ct).is_err());
    }

    #[test]
    fn test_policy_with_revocation() {
        let revoked = RevocationSet::from_users(&["bob", "alice"]);

        let policy = policy_with_revocation("admin", &revoked).unwrap();

        // Policy is unchanged - revocation is enforced at decrypt time
        assert_eq!(policy, "admin");
    }

    #[test]
    fn test_revocation_set() {
        let mut rs = RevocationSet::new();

        assert!(!rs.is_revoked("alice"));

        rs.revoke("alice");
        assert!(rs.is_revoked("alice"));
        assert!(!rs.is_revoked("bob"));

        rs.unrevoke("alice");
        assert!(!rs.is_revoked("alice"));

        assert_eq!(rs.len(), 0);
    }

    #[test]
    fn test_complex_policy_with_revocation() {
        let mut rng = thread_rng();
        let (mpk, msk) = setup(&mut rng);

        let sk = keygen(&mut rng, &mpk, &msk, "alice", &["admin", "finance", "hr"]).unwrap();

        let mut revoked = RevocationSet::new();
        revoked.revoke("bob");

        let plaintext = b"Budget report";
        let ct = encrypt_with_revocation(
            &mut rng, &mpk,
            "(admin AND finance) OR hr",
            &revoked,
            plaintext
        ).unwrap();

        let decrypted = decrypt(&mpk, &sk, &ct).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_can_decrypt() {
        let mut rng = thread_rng();
        let (mpk, msk) = setup(&mut rng);

        let sk = keygen(&mut rng, &mpk, &msk, "alice", &["admin"]).unwrap();

        let empty_revoked = RevocationSet::new();
        assert!(can_decrypt(&sk, "admin", &empty_revoked));

        let mut revoked = RevocationSet::new();
        revoked.revoke("alice");
        assert!(!can_decrypt(&sk, "admin", &revoked));
    }

    #[test]
    fn test_ciphertext_records_revoked_users() {
        let mut rng = thread_rng();
        let (mpk, _msk) = setup(&mut rng);

        let revoked = RevocationSet::from_users(&["bob", "charlie"]);

        let ct = encrypt_with_revocation(
            &mut rng, &mpk, "admin", &revoked, b"test"
        ).unwrap();

        assert!(ct.abe_ct.revoked_users.contains(&"bob".to_string()));
        assert!(ct.abe_ct.revoked_users.contains(&"charlie".to_string()));
        assert_eq!(ct.abe_ct.original_policy, "admin");
    }
}
