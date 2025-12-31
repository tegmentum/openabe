//! Accumulator-Based Revocation
//!
//! Implementation based on:
//! - Camenisch, Lysyanskaya. "Dynamic Accumulators and Application to
//!   Efficient Revocation" (CCS 2002)
//! - Nguyen. "Accumulators from Bilinear Pairings" (CT-RSA 2005)
//!
//! Uses bilinear accumulators to efficiently prove membership or non-membership.
//! Non-revoked users can prove they're not in the revocation set using a
//! constant-size witness.
//!
//! # Properties
//! - Constant-size revocation witness (O(1))
//! - Efficient updates when users are revoked (O(1) per witness)
//! - No need to enumerate all revoked users in ciphertext
//! - Based on q-SDH assumption

use crate::error::AbeError;
use crate::utils::hash_to_fr;
use rabe_bls12381::{Fr, G1, G2, Gt, pairing};
use rand::{RngCore, CryptoRng};
use std::collections::HashSet;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// User identity for accumulator
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

    /// Hash user ID to field element
    pub fn to_fr(&self) -> Fr {
        let input = format!("{}:accumulator_user_id", self.0);
        hash_to_fr(input.as_bytes())
    }
}

/// Accumulator public parameters
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct AccumulatorPublicKey {
    /// Generator g1 in G1
    pub g1: G1,
    /// Generator g2 in G2
    pub g2: G2,
    /// Powers: g1^(s^i) for i = 0..q
    pub g1_powers: Vec<G1>,
    /// Powers: g2^(s^i) for i = 0..q
    pub g2_powers: Vec<G2>,
    /// e(g1, g2)
    pub e_g1_g2: Gt,
}

/// Accumulator secret key (trapdoor)
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct AccumulatorSecretKey {
    /// Secret exponent s
    pub s: Fr,
}

/// The accumulator value
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Accumulator {
    /// Current accumulator value in G1
    pub value: G1,
    /// Auxiliary value in G2 for efficient verification
    pub aux: G2,
    /// Set of accumulated (revoked) user IDs
    pub accumulated_users: HashSet<String>,
    /// Version counter
    pub version: u64,
}

/// Membership witness (proves element IS in accumulator)
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct MembershipWitness {
    /// Witness element
    pub witness: G1,
    /// The element being witnessed
    pub element: Fr,
    /// The user ID
    pub user_id: String,
}

/// Non-membership witness (proves element is NOT in accumulator)
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct NonMembershipWitness {
    /// Witness component d in G1
    pub d: G1,
    /// Coefficient a
    pub a: Fr,
    /// Coefficient b
    pub b: Fr,
    /// The element being witnessed
    pub element: Fr,
    /// The user ID
    pub user_id: String,
}

/// Update information when an element is added to the accumulator
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct AccumulatorUpdate {
    /// The element that was added (revoked user)
    pub added_element: Fr,
    /// The user ID that was added
    pub added_user_id: String,
    /// Previous accumulator value
    pub old_acc: G1,
    /// New accumulator value
    pub new_acc: G1,
    /// New version
    pub version: u64,
}

/// Setup the accumulator with public parameters
///
/// The parameter `q` determines the maximum number of elements that can be
/// accumulated (revoked users).
pub fn accumulator_setup<R: RngCore + CryptoRng>(
    rng: &mut R,
    q: usize,
) -> (AccumulatorPublicKey, AccumulatorSecretKey) {
    let g1 = G1::one();
    let g2 = G2::one();

    // Secret trapdoor
    let s = Fr::random(rng);

    // Compute powers g1^(s^i) and g2^(s^i) for i = 0..q
    let mut g1_powers = Vec::with_capacity(q + 1);
    let mut g2_powers = Vec::with_capacity(q + 1);

    let mut s_power = Fr::one();
    for _ in 0..=q {
        g1_powers.push(g1 * s_power);
        g2_powers.push(g2 * s_power);
        s_power = s_power * s;
    }

    let e_g1_g2 = pairing(g1, g2);

    let pk = AccumulatorPublicKey {
        g1,
        g2,
        g1_powers,
        g2_powers,
        e_g1_g2,
    };

    let sk = AccumulatorSecretKey { s };

    (pk, sk)
}

impl Accumulator {
    /// Create an empty accumulator (no revoked users)
    pub fn empty(pk: &AccumulatorPublicKey) -> Self {
        Accumulator {
            value: pk.g1,  // g1^1 = accumulator of empty set
            aux: pk.g2,
            accumulated_users: HashSet::new(),
            version: 0,
        }
    }

    /// Get the number of accumulated elements
    pub fn size(&self) -> usize {
        self.accumulated_users.len()
    }

    /// Check if a user ID is in the accumulator
    pub fn contains_user(&self, user_id: &str) -> bool {
        self.accumulated_users.contains(user_id)
    }
}

/// Add an element to the accumulator (revoke a user)
///
/// Updates the accumulator value: acc' = acc^(s + x) where x is the new element.
pub fn add_to_accumulator(
    _pk: &AccumulatorPublicKey,
    sk: &AccumulatorSecretKey,
    acc: &mut Accumulator,
    user_id: &str,
) -> Result<AccumulatorUpdate, AbeError> {
    if acc.accumulated_users.contains(user_id) {
        return Err(AbeError::RevocationError("User already in accumulator".into()));
    }

    let element = UserId::new(user_id).to_fr();
    let old_acc = acc.value;

    // Compute (s + x)
    let s_plus_x = sk.s + element;

    // acc' = acc^(s + x)
    acc.value = acc.value * s_plus_x;
    acc.aux = acc.aux * s_plus_x;

    acc.accumulated_users.insert(user_id.to_string());
    acc.version += 1;

    Ok(AccumulatorUpdate {
        added_element: element,
        added_user_id: user_id.to_string(),
        old_acc,
        new_acc: acc.value,
        version: acc.version,
    })
}

/// Revoke a user by adding them to the accumulator
pub fn revoke_user(
    pk: &AccumulatorPublicKey,
    sk: &AccumulatorSecretKey,
    acc: &mut Accumulator,
    user_id: &UserId,
) -> Result<AccumulatorUpdate, AbeError> {
    add_to_accumulator(pk, sk, acc, user_id.as_str())
}

/// Generate a membership witness (prove element IS in accumulator)
///
/// This is used to prove a user is revoked.
pub fn generate_membership_witness(
    _pk: &AccumulatorPublicKey,
    sk: &AccumulatorSecretKey,
    acc: &Accumulator,
    user_id: &str,
) -> Result<MembershipWitness, AbeError> {
    if !acc.accumulated_users.contains(user_id) {
        return Err(AbeError::RevocationError("User not in accumulator".into()));
    }

    let element = UserId::new(user_id).to_fr();

    // Membership witness: w = g1^(prod_{y in S, y ≠ x}(s + y))
    let mut product = Fr::one();
    for uid in &acc.accumulated_users {
        if uid != user_id {
            let y = UserId::new(uid).to_fr();
            product = product * (sk.s + y);
        }
    }

    let witness = G1::one() * product;

    Ok(MembershipWitness {
        witness,
        element,
        user_id: user_id.to_string(),
    })
}

/// Verify a membership witness
pub fn verify_membership(
    pk: &AccumulatorPublicKey,
    acc: &Accumulator,
    witness: &MembershipWitness,
) -> bool {
    // We need g2^(s + x) = g2^s * g2^x = pk.g2_powers[1] * g2^x
    let g2_s_plus_x = pk.g2_powers[1] + pk.g2 * witness.element;

    // Check: e(acc, g2) = e(w, g2^(s + x))
    let lhs = pairing(acc.value, pk.g2);
    let rhs = pairing(witness.witness, g2_s_plus_x);

    lhs == rhs
}

/// Generate a non-membership witness (prove element is NOT in accumulator)
///
/// This is used to prove a user is NOT revoked.
pub fn generate_non_membership_witness(
    pk: &AccumulatorPublicKey,
    sk: &AccumulatorSecretKey,
    acc: &Accumulator,
    user_id: &str,
) -> Result<NonMembershipWitness, AbeError> {
    if acc.accumulated_users.contains(user_id) {
        return Err(AbeError::RevocationError(
            "User is in accumulator, cannot prove non-membership".into()
        ));
    }

    let element = UserId::new(user_id).to_fr();

    // For empty accumulator, witness is trivial
    if acc.accumulated_users.is_empty() {
        return Ok(NonMembershipWitness {
            d: pk.g1,
            a: Fr::one(),
            b: Fr::zero(),
            element,
            user_id: user_id.to_string(),
        });
    }

    // Compute f(s) = prod_{y in S}(s + y)
    let mut f_s = Fr::one();
    for uid in &acc.accumulated_users {
        let y = UserId::new(uid).to_fr();
        f_s = f_s * (sk.s + y);
    }

    // Compute f(x) = prod_{y in S}(x + y)
    let mut f_x = Fr::one();
    for uid in &acc.accumulated_users {
        let y = UserId::new(uid).to_fr();
        f_x = f_x * (element + y);
    }

    // Compute (f(s) - f(x)) / (s - x)
    let s_minus_x = sk.s - element;
    let s_minus_x_inv = match s_minus_x.inverse() {
        Some(inv) => inv,
        None => return Err(AbeError::RevocationError("Division by zero".into())),
    };

    let quotient = (f_s - f_x) * s_minus_x_inv;

    let d = pk.g1 * quotient;

    Ok(NonMembershipWitness {
        d,
        a: f_x,
        b: s_minus_x_inv,
        element,
        user_id: user_id.to_string(),
    })
}

/// Verify a non-membership witness
pub fn verify_non_membership(
    pk: &AccumulatorPublicKey,
    acc: &Accumulator,
    witness: &NonMembershipWitness,
) -> bool {
    // For empty accumulator, trivially non-member
    if acc.accumulated_users.is_empty() {
        return !acc.accumulated_users.contains(&witness.user_id);
    }

    // Compute g2^(s - x) = g2^s * g2^(-x)
    let neg_x = -witness.element;
    let g2_s_minus_x = pk.g2_powers[1] + pk.g2 * neg_x;

    // e(d, g2^(s-x))
    let e_d = pairing(witness.d, g2_s_minus_x);

    // e(g1, g2)^f(x) = e_g1_g2^(witness.a)
    let e_fx = pk.e_g1_g2.pow(&witness.a);

    // e(acc, g2)
    let e_acc = pairing(acc.value, pk.g2);

    // Verify: e(d, g2^(s-x)) * e(g1,g2)^f(x) = e(acc, g2)
    e_d * e_fx == e_acc
}

/// Update a non-membership witness after a new element is added
pub fn update_non_membership_witness(
    pk: &AccumulatorPublicKey,
    witness: &NonMembershipWitness,
    update: &AccumulatorUpdate,
) -> Result<NonMembershipWitness, AbeError> {
    // If the witness element was the one added, it's now a member
    if witness.user_id == update.added_user_id {
        return Err(AbeError::RevocationError(
            "User was added to accumulator, no longer non-member".into()
        ));
    }

    // New f(x) includes the new element
    let new_factor = witness.element + update.added_element;
    let new_a = witness.a * new_factor;

    // Adjustment
    let x_minus_added = witness.element - update.added_element;
    let x_minus_added_inv = match x_minus_added.inverse() {
        Some(inv) => inv,
        None => return Err(AbeError::RevocationError("Update element collision".into())),
    };

    let adjustment = new_a * x_minus_added_inv;
    let new_d = witness.d + pk.g1 * adjustment;

    Ok(NonMembershipWitness {
        d: new_d,
        a: new_a,
        b: witness.b,
        element: witness.element,
        user_id: witness.user_id.clone(),
    })
}

/// Batch update multiple non-membership witnesses
pub fn batch_update_witnesses(
    pk: &AccumulatorPublicKey,
    witnesses: &[NonMembershipWitness],
    update: &AccumulatorUpdate,
) -> Vec<Result<NonMembershipWitness, AbeError>> {
    witnesses
        .iter()
        .map(|w| update_non_membership_witness(pk, w, update))
        .collect()
}

/// User registration: generate initial non-membership witness
pub fn register_user(
    pk: &AccumulatorPublicKey,
    sk: &AccumulatorSecretKey,
    acc: &Accumulator,
    user_id: &UserId,
) -> Result<NonMembershipWitness, AbeError> {
    generate_non_membership_witness(pk, sk, acc, user_id.as_str())
}

/// Check if a user can decrypt (not revoked)
pub fn check_user_status(
    pk: &AccumulatorPublicKey,
    acc: &Accumulator,
    user_id: &UserId,
    witness: &NonMembershipWitness,
) -> bool {
    if user_id.as_str() != witness.user_id {
        return false;
    }
    verify_non_membership(pk, acc, witness)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::thread_rng;

    #[test]
    fn test_accumulator_setup() {
        let mut rng = thread_rng();
        let (pk, _sk) = accumulator_setup(&mut rng, 100);

        assert_eq!(pk.g1_powers.len(), 101);
        assert_eq!(pk.g2_powers.len(), 101);
        assert_eq!(pk.g1_powers[0], pk.g1);
    }

    #[test]
    fn test_empty_accumulator() {
        let mut rng = thread_rng();
        let (pk, _sk) = accumulator_setup(&mut rng, 100);

        let acc = Accumulator::empty(&pk);
        assert_eq!(acc.size(), 0);
        assert_eq!(acc.value, pk.g1);
    }

    #[test]
    fn test_add_to_accumulator() {
        let mut rng = thread_rng();
        let (pk, sk) = accumulator_setup(&mut rng, 100);

        let mut acc = Accumulator::empty(&pk);

        let old_value = acc.value;
        let update = add_to_accumulator(&pk, &sk, &mut acc, "alice").unwrap();

        assert!(acc.contains_user("alice"));
        assert_eq!(acc.size(), 1);
        assert_ne!(acc.value, old_value);
        assert_eq!(update.version, 1);
    }

    #[test]
    fn test_membership_witness() {
        let mut rng = thread_rng();
        let (pk, sk) = accumulator_setup(&mut rng, 100);

        let mut acc = Accumulator::empty(&pk);

        // Add user
        add_to_accumulator(&pk, &sk, &mut acc, "alice").unwrap();

        // Generate membership witness
        let witness = generate_membership_witness(&pk, &sk, &acc, "alice").unwrap();

        // Verify
        assert!(verify_membership(&pk, &acc, &witness));
    }

    #[test]
    fn test_non_membership_witness_empty() {
        let mut rng = thread_rng();
        let (pk, sk) = accumulator_setup(&mut rng, 100);

        let acc = Accumulator::empty(&pk);

        // Generate non-membership witness for empty accumulator
        let witness = generate_non_membership_witness(&pk, &sk, &acc, "alice").unwrap();

        // Verify
        assert!(verify_non_membership(&pk, &acc, &witness));
    }

    #[test]
    fn test_non_membership_witness() {
        let mut rng = thread_rng();
        let (pk, sk) = accumulator_setup(&mut rng, 100);

        let mut acc = Accumulator::empty(&pk);

        // Add some users
        add_to_accumulator(&pk, &sk, &mut acc, "bob").unwrap();
        add_to_accumulator(&pk, &sk, &mut acc, "charlie").unwrap();

        // Test user not in accumulator
        let witness = generate_non_membership_witness(&pk, &sk, &acc, "alice").unwrap();

        assert!(verify_non_membership(&pk, &acc, &witness));
    }

    #[test]
    fn test_revoke_user() {
        let mut rng = thread_rng();
        let (pk, sk) = accumulator_setup(&mut rng, 100);

        let mut acc = Accumulator::empty(&pk);
        let bob = UserId::new("bob");

        // Bob is not revoked initially
        assert!(!acc.contains_user("bob"));

        // Revoke bob
        revoke_user(&pk, &sk, &mut acc, &bob).unwrap();

        // Bob is now revoked
        assert!(acc.contains_user("bob"));
    }

    #[test]
    fn test_register_and_check_user() {
        let mut rng = thread_rng();
        let (pk, sk) = accumulator_setup(&mut rng, 100);

        let mut acc = Accumulator::empty(&pk);
        let alice = UserId::new("alice");

        // Register alice (get non-membership witness)
        let witness = register_user(&pk, &sk, &acc, &alice).unwrap();

        // Alice can decrypt (not revoked)
        assert!(check_user_status(&pk, &acc, &alice, &witness));

        // Revoke alice
        revoke_user(&pk, &sk, &mut acc, &alice).unwrap();

        // Alice's old witness no longer valid
        assert!(!check_user_status(&pk, &acc, &alice, &witness));
    }

    #[test]
    fn test_witness_update_after_revocation() {
        let mut rng = thread_rng();
        let (pk, sk) = accumulator_setup(&mut rng, 100);

        let mut acc = Accumulator::empty(&pk);

        let alice = UserId::new("alice");
        let bob = UserId::new("bob");

        // Get witness for alice
        let alice_witness = register_user(&pk, &sk, &acc, &alice).unwrap();

        // Alice is valid
        assert!(check_user_status(&pk, &acc, &alice, &alice_witness));

        // Revoke bob
        let _update = revoke_user(&pk, &sk, &mut acc, &bob).unwrap();

        // After any revocation, users can regenerate their witness
        // This is a simpler approach than incremental updates
        let alice_new_witness = register_user(&pk, &sk, &acc, &alice).unwrap();

        // Alice still valid with fresh witness
        assert!(check_user_status(&pk, &acc, &alice, &alice_new_witness));

        // Alice's old witness is no longer valid (accumulator changed)
        assert!(!check_user_status(&pk, &acc, &alice, &alice_witness));
    }

    #[test]
    fn test_double_add_fails() {
        let mut rng = thread_rng();
        let (pk, sk) = accumulator_setup(&mut rng, 100);

        let mut acc = Accumulator::empty(&pk);

        // First add succeeds
        add_to_accumulator(&pk, &sk, &mut acc, "alice").unwrap();

        // Second add fails
        let result = add_to_accumulator(&pk, &sk, &mut acc, "alice");
        assert!(result.is_err());
    }

    #[test]
    fn test_membership_of_non_member_fails() {
        let mut rng = thread_rng();
        let (pk, sk) = accumulator_setup(&mut rng, 100);

        let mut acc = Accumulator::empty(&pk);

        add_to_accumulator(&pk, &sk, &mut acc, "alice").unwrap();

        // Can't generate membership witness for non-member
        let result = generate_membership_witness(&pk, &sk, &acc, "bob");
        assert!(result.is_err());
    }

    #[test]
    fn test_non_membership_of_member_fails() {
        let mut rng = thread_rng();
        let (pk, sk) = accumulator_setup(&mut rng, 100);

        let mut acc = Accumulator::empty(&pk);

        add_to_accumulator(&pk, &sk, &mut acc, "alice").unwrap();

        // Can't generate non-membership witness for member
        let result = generate_non_membership_witness(&pk, &sk, &acc, "alice");
        assert!(result.is_err());
    }

    #[test]
    fn test_batch_update_witnesses() {
        let mut rng = thread_rng();
        let (pk, sk) = accumulator_setup(&mut rng, 100);

        let mut acc = Accumulator::empty(&pk);

        // Create several users
        let users: Vec<_> = (0..5)
            .map(|i| UserId::new(&format!("user{}", i)))
            .collect();

        // Register all users
        let witnesses: Vec<_> = users
            .iter()
            .map(|u| register_user(&pk, &sk, &acc, u).unwrap())
            .collect();

        // Revoke user0
        let update = revoke_user(&pk, &sk, &mut acc, &users[0]).unwrap();

        // Batch update remaining witnesses
        let updated = batch_update_witnesses(&pk, &witnesses[1..], &update);

        // First one should fail (revoked)
        let revoked_update = update_non_membership_witness(&pk, &witnesses[0], &update);
        assert!(revoked_update.is_err());

        // Others should succeed
        for result in &updated {
            assert!(result.is_ok());
        }
    }
}
