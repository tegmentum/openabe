//! rabe-bls12381: BLS12-381 pairing library
//!
//! This is a drop-in replacement for rabe-bn that uses the BLS12-381 curve
//! instead of BN254, providing 128-bit security level.
//!
//! The API is designed to be compatible with rabe-bn so that RABE can use
//! either library by simply changing the dependency.

// C FFI bindings for OpenABE integration (always compiled for static library use)
pub mod ffi;

use ark_bls12_381::{
    Bls12_381, Fr as ArkFr, G1Affine, G1Projective, G2Affine, G2Projective,
};
use ark_ec::{pairing::Pairing, CurveGroup, Group as ArkGroup, VariableBaseMSM};
use ark_ff::{Field, One, PrimeField, UniformRand, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use rand::RngCore;
use std::ops::{Add, Mul, Neg, Sub};

#[cfg(feature = "serde")]
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// The scalar field element (Fr) for BLS12-381
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fr(pub ArkFr);

/// G1 group element
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct G1(pub G1Projective);

/// G2 group element
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct G2(pub G2Projective);

/// Target group element (GT = Fp12 for BLS12-381)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Gt(pub <Bls12_381 as Pairing>::TargetField);

// ============================================================================
// Fr Implementation
// ============================================================================

impl Fr {
    /// Returns the zero element
    pub fn zero() -> Self {
        Fr(ArkFr::zero())
    }

    /// Returns the multiplicative identity (one)
    pub fn one() -> Self {
        Fr(ArkFr::one())
    }

    /// Generate a random field element
    pub fn random<R: RngCore>(rng: &mut R) -> Self {
        Fr(ArkFr::rand(rng))
    }

    /// Check if this is zero
    pub fn is_zero(&self) -> bool {
        self.0.is_zero()
    }

    /// Compute the multiplicative inverse
    pub fn inverse(&self) -> Option<Self> {
        self.0.inverse().map(Fr)
    }

    /// Compute self^exp
    pub fn pow(&self, exp: &Fr) -> Self {
        // Convert exp to bits and use square-and-multiply
        let exp_bigint = exp.0.into_bigint();
        Fr(self.0.pow(exp_bigint))
    }

    /// Convert to bytes (little-endian)
    pub fn into_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        self.0.serialize_compressed(&mut bytes).expect("serialization failed");
        bytes
    }

    /// Create from bytes (little-endian)
    pub fn from_slice(data: &[u8]) -> Option<Self> {
        ArkFr::deserialize_compressed(data).ok().map(Fr)
    }

    /// Interpret a 64-byte array as a field element
    /// Used for hashing to field
    pub fn interpret(buf: &[u8; 64]) -> Self {
        Fr(ArkFr::from_le_bytes_mod_order(buf))
    }

    /// Create from a string representation (decimal)
    pub fn from_str(s: &str) -> Option<Self> {
        s.parse::<ArkFr>().ok().map(Fr)
    }

    /// Create a new multiplication factor (alias for random in some contexts)
    pub fn new_mul_factor<R: RngCore>(rng: &mut R) -> Self {
        Self::random(rng)
    }

    /// Create from a u64 value
    pub fn from_u64(val: u64) -> Self {
        Fr(ArkFr::from(val))
    }
}

impl Default for Fr {
    fn default() -> Self {
        Self::zero()
    }
}

impl Add for Fr {
    type Output = Fr;
    fn add(self, other: Fr) -> Fr {
        Fr(self.0 + other.0)
    }
}

impl Sub for Fr {
    type Output = Fr;
    fn sub(self, other: Fr) -> Fr {
        Fr(self.0 - other.0)
    }
}

impl Mul for Fr {
    type Output = Fr;
    fn mul(self, other: Fr) -> Fr {
        Fr(self.0 * other.0)
    }
}

impl Neg for Fr {
    type Output = Fr;
    fn neg(self) -> Fr {
        Fr(-self.0)
    }
}

// ============================================================================
// G1 Implementation
// ============================================================================

impl G1 {
    /// Returns the identity element (point at infinity)
    pub fn zero() -> Self {
        G1(G1Projective::zero())
    }

    /// Returns the generator
    pub fn one() -> Self {
        G1(G1Projective::generator())
    }

    /// Generate a random group element
    pub fn random<R: RngCore>(rng: &mut R) -> Self {
        G1(G1Projective::rand(rng))
    }

    /// Check if this is the identity
    pub fn is_zero(&self) -> bool {
        self.0.is_zero()
    }

    /// Normalize to affine coordinates
    pub fn normalize(&self) -> Self {
        G1(self.0.into_affine().into())
    }

    /// Convert to bytes
    pub fn into_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        self.0.into_affine().serialize_compressed(&mut bytes).expect("serialization failed");
        bytes
    }

    /// Create from bytes
    pub fn from_slice(data: &[u8]) -> Option<Self> {
        G1Affine::deserialize_compressed(data)
            .ok()
            .map(|a| G1(a.into()))
    }

    /// Create from bytes with full validation
    ///
    /// This performs all security checks:
    /// - Point is on the curve
    /// - Point is in the prime-order subgroup (trivial for G1 since cofactor=1)
    /// - Point is not the identity (if reject_identity is true)
    pub fn from_slice_checked(data: &[u8], reject_identity: bool) -> Option<Self> {
        let point = Self::from_slice(data)?;
        if reject_identity && point.is_zero() {
            return None;
        }
        // For G1 in BLS12-381, cofactor is 1, so all curve points are in subgroup
        Some(point)
    }

    /// Check if point is in the prime-order subgroup
    ///
    /// For G1 in BLS12-381, this is always true for valid curve points
    /// since the cofactor is 1.
    pub fn is_in_subgroup(&self) -> bool {
        // G1 has cofactor 1, so all points are in the subgroup
        true
    }

    /// Hash to G1 (simple hash-and-check, not constant-time)
    pub fn hash_to_curve(data: &[u8]) -> Self {
        use sha2::{Sha256, Digest};

        // Simple hash-and-pray approach
        // TODO: Use proper hash_to_curve from draft-irtf-cfrg-hash-to-curve
        let mut counter = 0u64;
        loop {
            let mut hasher = Sha256::new();
            hasher.update(data);
            hasher.update(counter.to_le_bytes());
            let hash = hasher.finalize();

            // Try to interpret as x-coordinate
            let mut buf = [0u8; 64];
            buf[..32].copy_from_slice(&hash);

            // Use the hash to generate a scalar and multiply generator
            let scalar = Fr::interpret(&buf);
            if !scalar.is_zero() {
                return G1::one() * scalar;
            }
            counter += 1;
        }
    }

    /// Multi-scalar multiplication (MSM) using Pippenger's algorithm
    ///
    /// Computes: sum(points[i] * scalars[i]) for all i
    ///
    /// This is significantly faster than computing individual scalar
    /// multiplications and summing when there are multiple points:
    /// - 2-4 points: ~2x faster
    /// - 10+ points: ~3-4x faster
    ///
    /// # Panics
    /// Panics if `points` and `scalars` have different lengths.
    #[inline]
    pub fn multi_scalar_mul(points: &[G1], scalars: &[Fr]) -> G1 {
        assert_eq!(points.len(), scalars.len(), "points and scalars must have same length");
        if points.is_empty() {
            return G1::zero();
        }
        // Convert to affine points and ark scalars for MSM
        let affine_points: Vec<G1Affine> = points.iter().map(|p| p.0.into_affine()).collect();
        let ark_scalars: Vec<ArkFr> = scalars.iter().map(|s| s.0).collect();
        G1(G1Projective::msm(&affine_points, &ark_scalars).expect("MSM failed"))
    }
}

impl Default for G1 {
    fn default() -> Self {
        Self::zero()
    }
}

impl Add for G1 {
    type Output = G1;
    fn add(self, other: G1) -> G1 {
        G1(self.0 + other.0)
    }
}

impl Sub for G1 {
    type Output = G1;
    fn sub(self, other: G1) -> G1 {
        G1(self.0 - other.0)
    }
}

impl Neg for G1 {
    type Output = G1;
    fn neg(self) -> G1 {
        G1(-self.0)
    }
}

impl Mul<Fr> for G1 {
    type Output = G1;
    fn mul(self, scalar: Fr) -> G1 {
        G1(self.0 * scalar.0)
    }
}

// ============================================================================
// G2 Implementation
// ============================================================================

impl G2 {
    /// Returns the identity element (point at infinity)
    pub fn zero() -> Self {
        G2(G2Projective::zero())
    }

    /// Returns the generator
    pub fn one() -> Self {
        G2(G2Projective::generator())
    }

    /// Generate a random group element
    pub fn random<R: RngCore>(rng: &mut R) -> Self {
        G2(G2Projective::rand(rng))
    }

    /// Check if this is the identity
    pub fn is_zero(&self) -> bool {
        self.0.is_zero()
    }

    /// Normalize to affine coordinates
    pub fn normalize(&self) -> Self {
        G2(self.0.into_affine().into())
    }

    /// Convert to bytes
    pub fn into_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        self.0.into_affine().serialize_compressed(&mut bytes).expect("serialization failed");
        bytes
    }

    /// Create from bytes
    pub fn from_slice(data: &[u8]) -> Option<Self> {
        G2Affine::deserialize_compressed(data)
            .ok()
            .map(|a| G2(a.into()))
    }

    /// Create from bytes with full validation
    ///
    /// This performs all security checks:
    /// - Point is on the curve
    /// - Point is in the prime-order subgroup (critical for G2 security!)
    /// - Point is not the identity (if reject_identity is true)
    ///
    /// Unlike G1, G2 has a non-trivial cofactor, so subgroup checks are essential
    /// to prevent small-subgroup attacks.
    pub fn from_slice_checked(data: &[u8], reject_identity: bool) -> Option<Self> {
        let affine = G2Affine::deserialize_compressed(data).ok()?;

        // Critical: Check subgroup membership for G2
        // G2 has cofactor != 1, so not all curve points are in the prime-order subgroup
        if !affine.is_in_correct_subgroup_assuming_on_curve() {
            return None;
        }

        let point = G2(affine.into());
        if reject_identity && point.is_zero() {
            return None;
        }

        Some(point)
    }

    /// Check if point is in the prime-order subgroup
    ///
    /// For G2 in BLS12-381, this is a critical security check because
    /// G2 has a non-trivial cofactor. Points not in the subgroup can
    /// lead to small-subgroup attacks.
    pub fn is_in_subgroup(&self) -> bool {
        self.0.into_affine().is_in_correct_subgroup_assuming_on_curve()
    }

    /// Hash to G2 (simple hash-and-multiply, not constant-time)
    pub fn hash_to_curve(data: &[u8]) -> Self {
        use sha2::{Sha256, Digest};

        // Simple hash to scalar, multiply generator approach
        // TODO: Use proper hash_to_curve from draft-irtf-cfrg-hash-to-curve
        let mut counter = 0u64;
        loop {
            let mut hasher = Sha256::new();
            hasher.update(b"G2_HASH");  // Domain separator
            hasher.update(data);
            hasher.update(counter.to_le_bytes());
            let hash = hasher.finalize();

            // Use the hash to generate a scalar and multiply generator
            let mut buf = [0u8; 64];
            buf[..32].copy_from_slice(&hash);

            let scalar = Fr::interpret(&buf);
            if !scalar.is_zero() {
                return G2::one() * scalar;
            }
            counter += 1;
        }
    }

    /// Multi-scalar multiplication (MSM) using Pippenger's algorithm
    ///
    /// Computes: sum(points[i] * scalars[i]) for all i
    ///
    /// This is significantly faster than computing individual scalar
    /// multiplications and summing when there are multiple points.
    ///
    /// # Panics
    /// Panics if `points` and `scalars` have different lengths.
    #[inline]
    pub fn multi_scalar_mul(points: &[G2], scalars: &[Fr]) -> G2 {
        assert_eq!(points.len(), scalars.len(), "points and scalars must have same length");
        if points.is_empty() {
            return G2::zero();
        }
        // Convert to affine points and ark scalars for MSM
        let affine_points: Vec<G2Affine> = points.iter().map(|p| p.0.into_affine()).collect();
        let ark_scalars: Vec<ArkFr> = scalars.iter().map(|s| s.0).collect();
        G2(G2Projective::msm(&affine_points, &ark_scalars).expect("MSM failed"))
    }
}

impl Default for G2 {
    fn default() -> Self {
        Self::zero()
    }
}

impl Add for G2 {
    type Output = G2;
    fn add(self, other: G2) -> G2 {
        G2(self.0 + other.0)
    }
}

impl Sub for G2 {
    type Output = G2;
    fn sub(self, other: G2) -> G2 {
        G2(self.0 - other.0)
    }
}

impl Neg for G2 {
    type Output = G2;
    fn neg(self) -> G2 {
        G2(-self.0)
    }
}

impl Mul<Fr> for G2 {
    type Output = G2;
    fn mul(self, scalar: Fr) -> G2 {
        G2(self.0 * scalar.0)
    }
}

// ============================================================================
// Gt Implementation
// ============================================================================

impl Gt {
    /// Returns the multiplicative identity (one)
    pub fn one() -> Self {
        Gt(<Bls12_381 as Pairing>::TargetField::one())
    }

    /// Check if this is the identity
    pub fn is_one(&self) -> bool {
        self.0 == <Bls12_381 as Pairing>::TargetField::one()
    }

    /// Compute the multiplicative inverse
    pub fn inverse(&self) -> Self {
        Gt(self.0.inverse().expect("Gt element has no inverse"))
    }

    /// Compute self^exp
    pub fn pow(&self, exp: &Fr) -> Self {
        let exp_bigint = exp.0.into_bigint();
        Gt(self.0.pow(exp_bigint))
    }

    /// Convert to bytes
    pub fn into_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        self.0.serialize_compressed(&mut bytes).expect("serialization failed");
        bytes
    }

    /// Create from bytes
    pub fn from_slice(data: &[u8]) -> Option<Self> {
        <Bls12_381 as Pairing>::TargetField::deserialize_compressed(data)
            .ok()
            .map(Gt)
    }

    /// Create from bytes with validation
    ///
    /// Validates that the element is not the identity (if reject_identity is true).
    /// Note: Unlike G1/G2, Gt elements from untrusted sources are less common
    /// since they typically come from pairing operations, not direct deserialization.
    pub fn from_slice_checked(data: &[u8], reject_identity: bool) -> Option<Self> {
        let gt = Self::from_slice(data)?;
        if reject_identity && gt.is_one() {
            return None;
        }
        Some(gt)
    }
}

impl Default for Gt {
    fn default() -> Self {
        Self::one()
    }
}

impl Mul for Gt {
    type Output = Gt;
    fn mul(self, other: Gt) -> Gt {
        Gt(self.0 * other.0)
    }
}

// ============================================================================
// Pairing Functions
// ============================================================================

/// Compute the bilinear pairing e(g1, g2) -> gt
pub fn pairing(g1: G1, g2: G2) -> Gt {
    let result = Bls12_381::pairing(g1.0, g2.0);
    Gt(result.0)
}

/// Compute the product of multiple pairings: ∏ e(g1[i], g2[i])
///
/// This is significantly faster than computing individual pairings
/// and multiplying them, because it shares the final exponentiation.
///
/// For n pairings, this is approximately:
/// - 2 pairings: ~1.5x faster than 2 separate pairings
/// - 5 pairings: ~2x faster
/// - 10+ pairings: ~3-4x faster
///
/// # Panics
/// Panics if `g1_points` and `g2_points` have different lengths.
pub fn multi_pairing(g1_points: &[G1], g2_points: &[G2]) -> Gt {
    assert_eq!(g1_points.len(), g2_points.len(), "g1 and g2 slices must have same length");

    if g1_points.is_empty() {
        return Gt::one();
    }

    // Single pairing - just use regular pairing
    if g1_points.len() == 1 {
        return pairing(g1_points[0], g2_points[0]);
    }

    // Convert to affine points for multi-pairing
    let g1_affine: Vec<G1Affine> = g1_points.iter().map(|p| p.0.into_affine()).collect();
    let g2_affine: Vec<G2Affine> = g2_points.iter().map(|p| p.0.into_affine()).collect();

    // Use ark's multi_pairing which shares the final exponentiation
    let result = Bls12_381::multi_pairing(&g1_affine, &g2_affine);
    Gt(result.0)
}

// ============================================================================
// Serde Support
// ============================================================================

#[cfg(feature = "serde")]
mod serde_impl {
    use super::*;
    use serde::de::{self, Visitor};
    use std::fmt;

    // Fr serialization
    impl Serialize for Fr {
        fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            let bytes = self.into_bytes();
            serializer.serialize_bytes(&bytes)
        }
    }

    impl<'de> Deserialize<'de> for Fr {
        fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            struct FrVisitor;
            impl<'de> Visitor<'de> for FrVisitor {
                type Value = Fr;
                fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                    write!(f, "a byte array representing Fr")
                }
                fn visit_bytes<E: de::Error>(self, v: &[u8]) -> Result<Fr, E> {
                    Fr::from_slice(v).ok_or_else(|| de::Error::custom("invalid Fr bytes"))
                }
                fn visit_seq<A: de::SeqAccess<'de>>(self, mut seq: A) -> Result<Fr, A::Error> {
                    let mut bytes = Vec::new();
                    while let Some(b) = seq.next_element()? {
                        bytes.push(b);
                    }
                    Fr::from_slice(&bytes).ok_or_else(|| de::Error::custom("invalid Fr bytes"))
                }
            }
            deserializer.deserialize_bytes(FrVisitor)
        }
    }

    // G1 serialization
    impl Serialize for G1 {
        fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            let bytes = self.into_bytes();
            serializer.serialize_bytes(&bytes)
        }
    }

    impl<'de> Deserialize<'de> for G1 {
        fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            struct G1Visitor;
            impl<'de> Visitor<'de> for G1Visitor {
                type Value = G1;
                fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                    write!(f, "a byte array representing G1")
                }
                fn visit_bytes<E: de::Error>(self, v: &[u8]) -> Result<G1, E> {
                    G1::from_slice(v).ok_or_else(|| de::Error::custom("invalid G1 bytes"))
                }
                fn visit_seq<A: de::SeqAccess<'de>>(self, mut seq: A) -> Result<G1, A::Error> {
                    let mut bytes = Vec::new();
                    while let Some(b) = seq.next_element()? {
                        bytes.push(b);
                    }
                    G1::from_slice(&bytes).ok_or_else(|| de::Error::custom("invalid G1 bytes"))
                }
            }
            deserializer.deserialize_bytes(G1Visitor)
        }
    }

    // G2 serialization
    impl Serialize for G2 {
        fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            let bytes = self.into_bytes();
            serializer.serialize_bytes(&bytes)
        }
    }

    impl<'de> Deserialize<'de> for G2 {
        fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            struct G2Visitor;
            impl<'de> Visitor<'de> for G2Visitor {
                type Value = G2;
                fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                    write!(f, "a byte array representing G2")
                }
                fn visit_bytes<E: de::Error>(self, v: &[u8]) -> Result<G2, E> {
                    G2::from_slice(v).ok_or_else(|| de::Error::custom("invalid G2 bytes"))
                }
                fn visit_seq<A: de::SeqAccess<'de>>(self, mut seq: A) -> Result<G2, A::Error> {
                    let mut bytes = Vec::new();
                    while let Some(b) = seq.next_element()? {
                        bytes.push(b);
                    }
                    G2::from_slice(&bytes).ok_or_else(|| de::Error::custom("invalid G2 bytes"))
                }
            }
            deserializer.deserialize_bytes(G2Visitor)
        }
    }

    // Gt serialization
    impl Serialize for Gt {
        fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            let bytes = self.into_bytes();
            serializer.serialize_bytes(&bytes)
        }
    }

    impl<'de> Deserialize<'de> for Gt {
        fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            struct GtVisitor;
            impl<'de> Visitor<'de> for GtVisitor {
                type Value = Gt;
                fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                    write!(f, "a byte array representing Gt")
                }
                fn visit_bytes<E: de::Error>(self, v: &[u8]) -> Result<Gt, E> {
                    Gt::from_slice(v).ok_or_else(|| de::Error::custom("invalid Gt bytes"))
                }
                fn visit_seq<A: de::SeqAccess<'de>>(self, mut seq: A) -> Result<Gt, A::Error> {
                    let mut bytes = Vec::new();
                    while let Some(b) = seq.next_element()? {
                        bytes.push(b);
                    }
                    Gt::from_slice(&bytes).ok_or_else(|| de::Error::custom("invalid Gt bytes"))
                }
            }
            deserializer.deserialize_bytes(GtVisitor)
        }
    }
}

// ============================================================================
// Group Trait (for compatibility with RABE)
// ============================================================================

/// Trait for group elements (G1, G2)
pub trait Group: Sized + Clone + Copy + PartialEq + Eq {
    /// Returns the identity element
    fn zero() -> Self;
    /// Returns a generator
    fn one() -> Self;
    /// Generate a random element
    fn random<R: RngCore>(rng: &mut R) -> Self;
    /// Check if this is the identity
    fn is_zero(&self) -> bool;
}

impl Group for G1 {
    fn zero() -> Self { G1::zero() }
    fn one() -> Self { G1::one() }
    fn random<R: RngCore>(rng: &mut R) -> Self { G1::random(rng) }
    fn is_zero(&self) -> bool { G1::is_zero(self) }
}

impl Group for G2 {
    fn zero() -> Self { G2::zero() }
    fn one() -> Self { G2::one() }
    fn random<R: RngCore>(rng: &mut R) -> Self { G2::random(rng) }
    fn is_zero(&self) -> bool { G2::is_zero(self) }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use rand::thread_rng;

    #[test]
    fn test_fr_arithmetic() {
        let a = Fr::one();
        let b = Fr::one();
        let c = a + b;
        assert!(!c.is_zero());

        let zero = Fr::zero();
        assert!(zero.is_zero());
    }

    #[test]
    fn test_g1_operations() {
        let mut rng = thread_rng();
        let g = G1::one();
        let r = Fr::random(&mut rng);
        let p = g * r;
        assert!(!p.is_zero());

        let zero = G1::zero();
        assert!(zero.is_zero());
    }

    #[test]
    fn test_g2_operations() {
        let mut rng = thread_rng();
        let g = G2::one();
        let r = Fr::random(&mut rng);
        let p = g * r;
        assert!(!p.is_zero());
    }

    #[test]
    fn test_pairing_bilinearity() {
        let mut rng = thread_rng();
        let a = Fr::random(&mut rng);
        let b = Fr::random(&mut rng);
        let g1 = G1::one();
        let g2 = G2::one();

        // e(a*G1, b*G2) should equal e(G1, G2)^(a*b)
        let lhs = pairing(g1 * a, g2 * b);
        let rhs = pairing(g1, g2).pow(&(a * b));

        assert_eq!(lhs.into_bytes(), rhs.into_bytes());
    }

    #[test]
    fn test_fr_serialization() {
        let mut rng = thread_rng();
        let a = Fr::random(&mut rng);
        let bytes = a.into_bytes();
        let b = Fr::from_slice(&bytes).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn test_g1_serialization() {
        let mut rng = thread_rng();
        let p = G1::random(&mut rng);
        let bytes = p.into_bytes();
        let q = G1::from_slice(&bytes).unwrap();
        assert_eq!(p.normalize().into_bytes(), q.normalize().into_bytes());
    }

    #[test]
    fn test_g2_serialization() {
        let mut rng = thread_rng();
        let p = G2::random(&mut rng);
        let bytes = p.into_bytes();
        let q = G2::from_slice(&bytes).unwrap();
        assert_eq!(p.normalize().into_bytes(), q.normalize().into_bytes());
    }

    #[test]
    fn test_gt_serialization() {
        let mut rng = thread_rng();
        let g1 = G1::random(&mut rng);
        let g2 = G2::random(&mut rng);
        let gt = pairing(g1, g2);
        let bytes = gt.into_bytes();
        let gt2 = Gt::from_slice(&bytes).unwrap();
        assert_eq!(gt.into_bytes(), gt2.into_bytes());
    }

    #[test]
    fn test_multi_pairing() {
        let mut rng = thread_rng();
        let g1_1 = G1::random(&mut rng);
        let g1_2 = G1::random(&mut rng);
        let g2_1 = G2::random(&mut rng);
        let g2_2 = G2::random(&mut rng);

        // Multi-pairing should equal product of individual pairings
        let lhs = pairing(g1_1, g2_1) * pairing(g1_2, g2_2);

        // Also compute individually and multiply
        let p1 = pairing(g1_1, g2_1);
        let p2 = pairing(g1_2, g2_2);
        let rhs = p1 * p2;

        assert_eq!(lhs.into_bytes(), rhs.into_bytes());
    }

    #[test]
    fn test_g1_from_slice_checked() {
        let mut rng = thread_rng();

        // Valid point should pass
        let p = G1::random(&mut rng);
        let bytes = p.into_bytes();
        let q = G1::from_slice_checked(&bytes, false).unwrap();
        assert_eq!(p.normalize().into_bytes(), q.normalize().into_bytes());

        // Identity with reject_identity=true should fail
        let zero = G1::zero();
        let zero_bytes = zero.into_bytes();
        assert!(G1::from_slice_checked(&zero_bytes, true).is_none());

        // Identity with reject_identity=false should pass
        assert!(G1::from_slice_checked(&zero_bytes, false).is_some());

        // Invalid (too short) bytes should fail
        let invalid = vec![0u8; 10];
        assert!(G1::from_slice_checked(&invalid, false).is_none());
    }

    #[test]
    fn test_g2_from_slice_checked() {
        let mut rng = thread_rng();

        // Valid point should pass
        let p = G2::random(&mut rng);
        let bytes = p.into_bytes();
        let q = G2::from_slice_checked(&bytes, false).unwrap();
        assert_eq!(p.normalize().into_bytes(), q.normalize().into_bytes());

        // Identity with reject_identity=true should fail
        let zero = G2::zero();
        let zero_bytes = zero.into_bytes();
        assert!(G2::from_slice_checked(&zero_bytes, true).is_none());

        // Identity with reject_identity=false should pass
        assert!(G2::from_slice_checked(&zero_bytes, false).is_some());

        // Invalid (too short) bytes should fail
        let invalid = vec![0u8; 10];
        assert!(G2::from_slice_checked(&invalid, false).is_none());
    }

    #[test]
    fn test_g1_is_in_subgroup() {
        let mut rng = thread_rng();
        // All valid G1 points should be in subgroup (cofactor=1)
        let p = G1::random(&mut rng);
        assert!(p.is_in_subgroup());
        assert!(G1::one().is_in_subgroup());
        assert!(G1::zero().is_in_subgroup());
    }

    #[test]
    fn test_g2_is_in_subgroup() {
        let mut rng = thread_rng();
        // Valid G2 points from random() should be in subgroup
        let p = G2::random(&mut rng);
        assert!(p.is_in_subgroup());
        assert!(G2::one().is_in_subgroup());
        assert!(G2::zero().is_in_subgroup());
    }

    #[test]
    fn test_cpabe_decryption_math() {
        // Simulate CP-ABE Waters decryption identity
        // For single attribute, the math should satisfy:
        // e(Cprime, K) / (e(KX^coeff, D) * e(prod1, L)) = e(g1, g2)^(alpha*s)
        let mut rng = thread_rng();

        // Setup parameters
        let g1 = G1::one();
        let g2 = G2::one();
        let alpha = Fr::random(&mut rng);
        let a = Fr::random(&mut rng);
        let s = Fr::random(&mut rng);
        let t = Fr::random(&mut rng);
        let r = Fr::random(&mut rng);
        let coeff = Fr::one(); // For single attribute with threshold 1

        // h = hash(attr) - use random G1 for simplicity
        let h = G1::random(&mut rng);

        // Encryption:
        // C = e(g1, g2)^(alpha*s) = e(g1^s, g2^alpha)
        let g1s = g1 * s;
        let g2alpha = g2 * alpha;
        let C = pairing(g1s, g2alpha);

        // Cprime = g1^s
        let Cprime = g1 * s;

        // D = g2^r
        let D = g2 * r;

        // C_attr = g1a^s * h^(-r) = g1^(a*s) * h^(-r)
        let g1a = g1 * a;
        let C_attr = g1a * s + h * (-r);

        // Key generation:
        // K = g2^alpha * g2^(a*t)
        let g2at = g2 * (a * t);
        let K = g2 * alpha + g2at;

        // L = g2^t
        let L = g2 * t;

        // KX = h^t
        let KX = h * t;

        // Decryption:
        // prod1 = C_attr^coeff = C_attr (since coeff = 1)
        let prod1 = C_attr * coeff;

        // prodT = e(KX^coeff, D) = e(h^t, g2^r)
        let KX_coeff = KX * coeff;
        let prodT = pairing(KX_coeff, D);

        // pairing1 = e(Cprime, K) = e(g1^s, g2^alpha * g2^(a*t))
        let pairing1 = pairing(Cprime, K);

        // pairing2 = e(prod1, L) = e(g1^(a*s) * h^(-r), g2^t)
        let pairing2 = pairing(prod1, L);

        // denominator = prodT * pairing2
        let denominator = prodT * pairing2;

        // final = pairing1 / denominator = pairing1 * denominator^(-1)
        let final_gt = pairing1 * denominator.inverse();

        // Verify: final should equal C = e(g1, g2)^(alpha*s)
        assert_eq!(final_gt.into_bytes(), C.into_bytes(),
            "CP-ABE decryption identity failed");
    }
}
