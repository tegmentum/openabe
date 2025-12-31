//! Memory protection utilities for sensitive data
//!
//! Provides memory locking (mlock) to prevent sensitive data from being
//! swapped to disk. Only available with the `memory-protection` feature.

use zeroize::Zeroize;
use std::ops::{Deref, DerefMut};

/// A wrapper that protects sensitive data in memory
///
/// On Unix systems with the `memory-protection` feature, this will:
/// - Lock the memory pages containing the data (prevent swapping)
/// - Zeroize the data when dropped
/// - Unlock the memory pages after zeroization
///
/// Without the feature, it just provides zeroization on drop.
pub struct ProtectedMemory<T: Zeroize> {
    data: Box<T>,
    #[cfg(all(unix, feature = "memory-protection"))]
    locked: bool,
}

impl<T: Zeroize> ProtectedMemory<T> {
    /// Create a new protected memory region
    pub fn new(data: T) -> Self {
        let boxed = Box::new(data);

        #[cfg(all(unix, feature = "memory-protection"))]
        let locked = {
            let ptr = boxed.as_ref() as *const T as *const libc::c_void;
            let size = std::mem::size_of::<T>();
            unsafe { libc::mlock(ptr, size) == 0 }
        };

        Self {
            data: boxed,
            #[cfg(all(unix, feature = "memory-protection"))]
            locked,
        }
    }

    /// Check if memory is locked (Unix with feature only)
    #[cfg(all(unix, feature = "memory-protection"))]
    pub fn is_locked(&self) -> bool {
        self.locked
    }

    /// Check if memory is locked (always false without feature)
    #[cfg(not(all(unix, feature = "memory-protection")))]
    pub fn is_locked(&self) -> bool {
        false
    }
}

impl<T: Zeroize> Deref for ProtectedMemory<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

impl<T: Zeroize> DerefMut for ProtectedMemory<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.data
    }
}

impl<T: Zeroize> Drop for ProtectedMemory<T> {
    fn drop(&mut self) {
        // Always zeroize
        self.data.zeroize();

        // Unlock memory if it was locked
        #[cfg(all(unix, feature = "memory-protection"))]
        if self.locked {
            let ptr = self.data.as_ref() as *const T as *const libc::c_void;
            let size = std::mem::size_of::<T>();
            unsafe {
                libc::munlock(ptr, size);
            }
        }
    }
}

/// A protected byte array of fixed size
pub type ProtectedKey = ProtectedMemory<[u8; 32]>;

/// Create a protected 32-byte key
pub fn protect_key(key: [u8; 32]) -> ProtectedKey {
    ProtectedMemory::new(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protected_memory_access() {
        let protected = ProtectedMemory::new([1u8, 2, 3, 4]);
        assert_eq!(&*protected, &[1u8, 2, 3, 4]);
    }

    #[test]
    fn test_protected_memory_mut() {
        let mut protected = ProtectedMemory::new([0u8; 4]);
        protected[0] = 42;
        assert_eq!(protected[0], 42);
    }

    #[test]
    fn test_protect_key() {
        let key = [0x42u8; 32];
        let protected = protect_key(key);
        assert_eq!(&*protected, &[0x42u8; 32]);
    }
}
