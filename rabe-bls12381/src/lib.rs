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
use ark_ec::{pairing::Pairing, CurveGroup, Group as ArkGroup};
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
// Pairing Function
// ============================================================================

/// Compute the bilinear pairing e(g1, g2) -> gt
pub fn pairing(g1: G1, g2: G2) -> Gt {
    let result = Bls12_381::pairing(g1.0, g2.0);
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
}
