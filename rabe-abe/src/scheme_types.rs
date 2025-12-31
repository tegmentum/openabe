//! Type-Safe Scheme System
//!
//! This module provides compile-time enforcement to prevent accidentally mixing
//! different ABE schemes (Waters, AC17, GPSW, BSW, DABE) across operations.
//!
//! # Design
//!
//! Uses phantom types (zero-sized marker types) to tag scheme-specific types:
//! - `TypedMpk<S>` - Master public key tagged with scheme `S`
//! - `TypedMsk<S>` - Master secret key tagged with scheme `S`
//! - `TypedSecretKey<S>` - User secret key tagged with scheme `S`
//! - `TypedCiphertext<S>` - Ciphertext tagged with scheme `S`
//!
//! Functions require matching scheme markers, so mixing schemes causes
//! compile-time errors:
//!
//! ```compile_fail
//! use rabe_abe::schemes::{waters, ac17};
//!
//! let (mpk, msk) = waters::setup(&mut rng);  // TypedMpk<Waters>
//! let sk = ac17::keygen(&mut rng, &ac17_mpk, &ac17_msk, &attrs);  // TypedSecretKey<Ac17>
//! waters::decrypt(&mpk, &sk, &ct);  // ERROR: type mismatch!
//! ```
//!
//! # Zero Runtime Cost
//!
//! Phantom types are zero-sized, so this adds no runtime overhead.

use std::marker::PhantomData;
use std::ops::{Deref, DerefMut};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize, Serializer, Deserializer};

// ============================================================================
// Scheme Trait and Markers
// ============================================================================

mod private {
    /// Sealed trait to prevent external implementations
    pub trait Sealed {}
}

/// Marker trait for ABE scheme families.
///
/// This is a sealed trait - only the scheme markers defined in this module
/// can implement it.
pub trait Scheme: private::Sealed + Clone + Copy + 'static {
    /// Scheme identifier for serialization and debugging
    const ID: &'static str;
}

// ----------------------------------------------------------------------------
// Scheme Family Markers (zero-sized types)
// ----------------------------------------------------------------------------

/// Waters '11 CP-ABE scheme marker
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Waters;

/// Waters CCA-secure CP-ABE scheme marker
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WatersCca;

/// AC17 (Agrawal-Chase) CP-ABE scheme marker
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Ac17;

/// GPSW KP-ABE scheme marker
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Gpsw;

/// BSW CP-ABE scheme marker
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Bsw;

/// DABE (Decentralized Multi-Authority ABE) scheme marker
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Dabe;

// Seal all scheme markers
impl private::Sealed for Waters {}
impl private::Sealed for WatersCca {}
impl private::Sealed for Ac17 {}
impl private::Sealed for Gpsw {}
impl private::Sealed for Bsw {}
impl private::Sealed for Dabe {}

// Implement Scheme trait with identifiers
impl Scheme for Waters { const ID: &'static str = "waters"; }
impl Scheme for WatersCca { const ID: &'static str = "waters-cca"; }
impl Scheme for Ac17 { const ID: &'static str = "ac17"; }
impl Scheme for Gpsw { const ID: &'static str = "gpsw"; }
impl Scheme for Bsw { const ID: &'static str = "bsw"; }
impl Scheme for Dabe { const ID: &'static str = "dabe"; }

// ============================================================================
// Typed Wrappers
// ============================================================================

/// Master Public Key with scheme type marker.
///
/// Wraps any raw MPK type and tags it with the scheme type `S`.
#[derive(Clone, Debug)]
pub struct TypedMpk<S: Scheme, T> {
    inner: T,
    _marker: PhantomData<S>,
}

/// Master Secret Key with scheme type marker.
///
/// Wraps any raw MSK type and tags it with the scheme type `S`.
#[derive(Clone)]
pub struct TypedMsk<S: Scheme, T> {
    inner: T,
    _marker: PhantomData<S>,
}

/// User Secret Key with scheme type marker.
///
/// Wraps any raw secret key type and tags it with the scheme type `S`.
#[derive(Clone)]
pub struct TypedSecretKey<S: Scheme, T> {
    inner: T,
    _marker: PhantomData<S>,
}

/// Ciphertext with scheme type marker.
///
/// Wraps any raw ciphertext type and tags it with the scheme type `S`.
#[derive(Clone, Debug)]
pub struct TypedCiphertext<S: Scheme, T> {
    inner: T,
    _marker: PhantomData<S>,
}

/// Full Ciphertext (with symmetric payload) with scheme type marker.
#[derive(Clone, Debug)]
pub struct TypedFullCiphertext<S: Scheme, T> {
    inner: T,
    _marker: PhantomData<S>,
}

/// Re-encryption Key with source and target scheme markers.
///
/// Used for PRE operations where source and target may be different schemes.
#[derive(Clone)]
pub struct TypedReKey<Source: Scheme, Target: Scheme, T> {
    inner: T,
    _source: PhantomData<Source>,
    _target: PhantomData<Target>,
}

/// Re-encrypted Ciphertext with scheme type marker.
#[derive(Clone, Debug)]
pub struct TypedReEncryptedCiphertext<S: Scheme, T> {
    inner: T,
    _marker: PhantomData<S>,
}

// ============================================================================
// TypedMpk Implementation
// ============================================================================

impl<S: Scheme, T> TypedMpk<S, T> {
    /// Create a new typed MPK from a raw MPK.
    pub fn new(inner: T) -> Self {
        Self { inner, _marker: PhantomData }
    }

    /// Get the scheme identifier.
    pub fn scheme_id(&self) -> &'static str {
        S::ID
    }

    /// Unwrap to get the inner raw type.
    pub fn into_inner(self) -> T {
        self.inner
    }

    /// Get a reference to the inner raw type.
    pub fn inner(&self) -> &T {
        &self.inner
    }

    /// Get a mutable reference to the inner raw type.
    pub fn inner_mut(&mut self) -> &mut T {
        &mut self.inner
    }
}

impl<S: Scheme, T> Deref for TypedMpk<S, T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<S: Scheme, T> DerefMut for TypedMpk<S, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl<S: Scheme, T> From<T> for TypedMpk<S, T> {
    fn from(inner: T) -> Self {
        Self::new(inner)
    }
}

// ============================================================================
// TypedMsk Implementation
// ============================================================================

impl<S: Scheme, T> TypedMsk<S, T> {
    /// Create a new typed MSK from a raw MSK.
    pub fn new(inner: T) -> Self {
        Self { inner, _marker: PhantomData }
    }

    /// Get the scheme identifier.
    pub fn scheme_id(&self) -> &'static str {
        S::ID
    }

    /// Unwrap to get the inner raw type.
    pub fn into_inner(self) -> T {
        self.inner
    }

    /// Get a reference to the inner raw type.
    pub fn inner(&self) -> &T {
        &self.inner
    }

    /// Get a mutable reference to the inner raw type.
    pub fn inner_mut(&mut self) -> &mut T {
        &mut self.inner
    }
}

impl<S: Scheme, T> Deref for TypedMsk<S, T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<S: Scheme, T> DerefMut for TypedMsk<S, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl<S: Scheme, T> From<T> for TypedMsk<S, T> {
    fn from(inner: T) -> Self {
        Self::new(inner)
    }
}

// ============================================================================
// TypedSecretKey Implementation
// ============================================================================

impl<S: Scheme, T> TypedSecretKey<S, T> {
    /// Create a new typed secret key from a raw secret key.
    pub fn new(inner: T) -> Self {
        Self { inner, _marker: PhantomData }
    }

    /// Get the scheme identifier.
    pub fn scheme_id(&self) -> &'static str {
        S::ID
    }

    /// Unwrap to get the inner raw type.
    pub fn into_inner(self) -> T {
        self.inner
    }

    /// Get a reference to the inner raw type.
    pub fn inner(&self) -> &T {
        &self.inner
    }

    /// Get a mutable reference to the inner raw type.
    pub fn inner_mut(&mut self) -> &mut T {
        &mut self.inner
    }
}

impl<S: Scheme, T> Deref for TypedSecretKey<S, T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<S: Scheme, T> DerefMut for TypedSecretKey<S, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl<S: Scheme, T> From<T> for TypedSecretKey<S, T> {
    fn from(inner: T) -> Self {
        Self::new(inner)
    }
}

// ============================================================================
// TypedCiphertext Implementation
// ============================================================================

impl<S: Scheme, T> TypedCiphertext<S, T> {
    /// Create a new typed ciphertext from a raw ciphertext.
    pub fn new(inner: T) -> Self {
        Self { inner, _marker: PhantomData }
    }

    /// Get the scheme identifier.
    pub fn scheme_id(&self) -> &'static str {
        S::ID
    }

    /// Unwrap to get the inner raw type.
    pub fn into_inner(self) -> T {
        self.inner
    }

    /// Get a reference to the inner raw type.
    pub fn inner(&self) -> &T {
        &self.inner
    }

    /// Get a mutable reference to the inner raw type.
    pub fn inner_mut(&mut self) -> &mut T {
        &mut self.inner
    }
}

impl<S: Scheme, T> Deref for TypedCiphertext<S, T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<S: Scheme, T> DerefMut for TypedCiphertext<S, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl<S: Scheme, T> From<T> for TypedCiphertext<S, T> {
    fn from(inner: T) -> Self {
        Self::new(inner)
    }
}

// ============================================================================
// TypedFullCiphertext Implementation
// ============================================================================

impl<S: Scheme, T> TypedFullCiphertext<S, T> {
    /// Create a new typed full ciphertext from a raw ciphertext.
    pub fn new(inner: T) -> Self {
        Self { inner, _marker: PhantomData }
    }

    /// Get the scheme identifier.
    pub fn scheme_id(&self) -> &'static str {
        S::ID
    }

    /// Unwrap to get the inner raw type.
    pub fn into_inner(self) -> T {
        self.inner
    }

    /// Get a reference to the inner raw type.
    pub fn inner(&self) -> &T {
        &self.inner
    }

    /// Get a mutable reference to the inner raw type.
    pub fn inner_mut(&mut self) -> &mut T {
        &mut self.inner
    }
}

impl<S: Scheme, T> Deref for TypedFullCiphertext<S, T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<S: Scheme, T> DerefMut for TypedFullCiphertext<S, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl<S: Scheme, T> From<T> for TypedFullCiphertext<S, T> {
    fn from(inner: T) -> Self {
        Self::new(inner)
    }
}

// ============================================================================
// TypedReKey Implementation
// ============================================================================

impl<Source: Scheme, Target: Scheme, T> TypedReKey<Source, Target, T> {
    /// Create a new typed re-encryption key.
    pub fn new(inner: T) -> Self {
        Self { inner, _source: PhantomData, _target: PhantomData }
    }

    /// Get the source scheme identifier.
    pub fn source_scheme_id(&self) -> &'static str {
        Source::ID
    }

    /// Get the target scheme identifier.
    pub fn target_scheme_id(&self) -> &'static str {
        Target::ID
    }

    /// Unwrap to get the inner raw type.
    pub fn into_inner(self) -> T {
        self.inner
    }

    /// Get a reference to the inner raw type.
    pub fn inner(&self) -> &T {
        &self.inner
    }

    /// Get a mutable reference to the inner raw type.
    pub fn inner_mut(&mut self) -> &mut T {
        &mut self.inner
    }
}

impl<Source: Scheme, Target: Scheme, T> Deref for TypedReKey<Source, Target, T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<Source: Scheme, Target: Scheme, T> DerefMut for TypedReKey<Source, Target, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl<Source: Scheme, Target: Scheme, T> From<T> for TypedReKey<Source, Target, T> {
    fn from(inner: T) -> Self {
        Self::new(inner)
    }
}

// ============================================================================
// TypedReEncryptedCiphertext Implementation
// ============================================================================

impl<S: Scheme, T> TypedReEncryptedCiphertext<S, T> {
    /// Create a new typed re-encrypted ciphertext.
    pub fn new(inner: T) -> Self {
        Self { inner, _marker: PhantomData }
    }

    /// Get the scheme identifier.
    pub fn scheme_id(&self) -> &'static str {
        S::ID
    }

    /// Unwrap to get the inner raw type.
    pub fn into_inner(self) -> T {
        self.inner
    }

    /// Get a reference to the inner raw type.
    pub fn inner(&self) -> &T {
        &self.inner
    }

    /// Get a mutable reference to the inner raw type.
    pub fn inner_mut(&mut self) -> &mut T {
        &mut self.inner
    }
}

impl<S: Scheme, T> Deref for TypedReEncryptedCiphertext<S, T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<S: Scheme, T> DerefMut for TypedReEncryptedCiphertext<S, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl<S: Scheme, T> From<T> for TypedReEncryptedCiphertext<S, T> {
    fn from(inner: T) -> Self {
        Self::new(inner)
    }
}

// ============================================================================
// Debug implementations for secret types (omit sensitive data)
// ============================================================================

impl<S: Scheme, T> std::fmt::Debug for TypedMsk<S, T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TypedMsk")
            .field("scheme", &S::ID)
            .field("inner", &"<redacted>")
            .finish()
    }
}

impl<S: Scheme, T> std::fmt::Debug for TypedSecretKey<S, T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TypedSecretKey")
            .field("scheme", &S::ID)
            .field("inner", &"<redacted>")
            .finish()
    }
}

impl<Source: Scheme, Target: Scheme, T> std::fmt::Debug for TypedReKey<Source, Target, T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TypedReKey")
            .field("source_scheme", &Source::ID)
            .field("target_scheme", &Target::ID)
            .field("inner", &"<redacted>")
            .finish()
    }
}

// ============================================================================
// Serde Implementations (transparent - just serialize inner type)
// ============================================================================

#[cfg(feature = "serde")]
impl<S: Scheme, T: Serialize> Serialize for TypedMpk<S, T> {
    fn serialize<Ser>(&self, serializer: Ser) -> Result<Ser::Ok, Ser::Error>
    where
        Ser: Serializer,
    {
        self.inner.serialize(serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de, S: Scheme, T: Deserialize<'de>> Deserialize<'de> for TypedMpk<S, T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let inner = T::deserialize(deserializer)?;
        Ok(Self::new(inner))
    }
}

#[cfg(feature = "serde")]
impl<S: Scheme, T: Serialize> Serialize for TypedMsk<S, T> {
    fn serialize<Ser>(&self, serializer: Ser) -> Result<Ser::Ok, Ser::Error>
    where
        Ser: Serializer,
    {
        self.inner.serialize(serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de, S: Scheme, T: Deserialize<'de>> Deserialize<'de> for TypedMsk<S, T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let inner = T::deserialize(deserializer)?;
        Ok(Self::new(inner))
    }
}

#[cfg(feature = "serde")]
impl<S: Scheme, T: Serialize> Serialize for TypedSecretKey<S, T> {
    fn serialize<Ser>(&self, serializer: Ser) -> Result<Ser::Ok, Ser::Error>
    where
        Ser: Serializer,
    {
        self.inner.serialize(serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de, S: Scheme, T: Deserialize<'de>> Deserialize<'de> for TypedSecretKey<S, T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let inner = T::deserialize(deserializer)?;
        Ok(Self::new(inner))
    }
}

#[cfg(feature = "serde")]
impl<S: Scheme, T: Serialize> Serialize for TypedCiphertext<S, T> {
    fn serialize<Ser>(&self, serializer: Ser) -> Result<Ser::Ok, Ser::Error>
    where
        Ser: Serializer,
    {
        self.inner.serialize(serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de, S: Scheme, T: Deserialize<'de>> Deserialize<'de> for TypedCiphertext<S, T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let inner = T::deserialize(deserializer)?;
        Ok(Self::new(inner))
    }
}

#[cfg(feature = "serde")]
impl<S: Scheme, T: Serialize> Serialize for TypedFullCiphertext<S, T> {
    fn serialize<Ser>(&self, serializer: Ser) -> Result<Ser::Ok, Ser::Error>
    where
        Ser: Serializer,
    {
        self.inner.serialize(serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de, S: Scheme, T: Deserialize<'de>> Deserialize<'de> for TypedFullCiphertext<S, T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let inner = T::deserialize(deserializer)?;
        Ok(Self::new(inner))
    }
}

#[cfg(feature = "serde")]
impl<Source: Scheme, Target: Scheme, T: Serialize> Serialize for TypedReKey<Source, Target, T> {
    fn serialize<Ser>(&self, serializer: Ser) -> Result<Ser::Ok, Ser::Error>
    where
        Ser: Serializer,
    {
        self.inner.serialize(serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de, Source: Scheme, Target: Scheme, T: Deserialize<'de>> Deserialize<'de> for TypedReKey<Source, Target, T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let inner = T::deserialize(deserializer)?;
        Ok(Self::new(inner))
    }
}

#[cfg(feature = "serde")]
impl<S: Scheme, T: Serialize> Serialize for TypedReEncryptedCiphertext<S, T> {
    fn serialize<Ser>(&self, serializer: Ser) -> Result<Ser::Ok, Ser::Error>
    where
        Ser: Serializer,
    {
        self.inner.serialize(serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de, S: Scheme, T: Deserialize<'de>> Deserialize<'de> for TypedReEncryptedCiphertext<S, T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let inner = T::deserialize(deserializer)?;
        Ok(Self::new(inner))
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scheme_ids() {
        assert_eq!(Waters::ID, "waters");
        assert_eq!(WatersCca::ID, "waters-cca");
        assert_eq!(Ac17::ID, "ac17");
        assert_eq!(Gpsw::ID, "gpsw");
        assert_eq!(Bsw::ID, "bsw");
        assert_eq!(Dabe::ID, "dabe");
    }

    #[test]
    fn test_typed_mpk_basic() {
        let raw = 42u32;
        let typed: TypedMpk<Waters, u32> = TypedMpk::new(raw);

        assert_eq!(typed.scheme_id(), "waters");
        assert_eq!(*typed, 42);
        assert_eq!(typed.into_inner(), 42);
    }

    #[test]
    fn test_typed_from_impl() {
        let raw = "test";
        let typed: TypedCiphertext<Ac17, &str> = raw.into();

        assert_eq!(typed.scheme_id(), "ac17");
        assert_eq!(*typed, "test");
    }

    #[test]
    fn test_typed_rekey_dual_schemes() {
        let raw = vec![1u8, 2, 3];
        let rekey: TypedReKey<Waters, Waters, Vec<u8>> = TypedReKey::new(raw);

        assert_eq!(rekey.source_scheme_id(), "waters");
        assert_eq!(rekey.target_scheme_id(), "waters");
    }

    #[test]
    fn test_deref_allows_field_access() {
        #[derive(Clone)]
        struct RawMpk {
            value: u32,
        }

        let typed: TypedMpk<Waters, RawMpk> = TypedMpk::new(RawMpk { value: 100 });

        // Deref allows accessing inner fields
        assert_eq!(typed.value, 100);
    }

    #[test]
    fn test_deref_mut_allows_mutation() {
        #[derive(Clone)]
        struct RawMpk {
            value: u32,
        }

        let mut typed: TypedMpk<Waters, RawMpk> = TypedMpk::new(RawMpk { value: 100 });

        // DerefMut allows mutating inner fields
        typed.value = 200;
        assert_eq!(typed.value, 200);
    }

    #[test]
    fn test_debug_redacts_secrets() {
        let msk: TypedMsk<Waters, u32> = TypedMsk::new(12345);
        let debug_str = format!("{:?}", msk);

        // Should show scheme but not the actual value
        assert!(debug_str.contains("waters"));
        assert!(debug_str.contains("<redacted>"));
        assert!(!debug_str.contains("12345"));
    }

    // Compile-time test: This should NOT compile if uncommented
    // #[test]
    // fn test_scheme_mismatch_fails() {
    //     fn needs_waters(_: &TypedMpk<Waters, u32>) {}
    //     let ac17_mpk: TypedMpk<Ac17, u32> = TypedMpk::new(42);
    //     needs_waters(&ac17_mpk);  // ERROR: expected Waters, found Ac17
    // }
}
