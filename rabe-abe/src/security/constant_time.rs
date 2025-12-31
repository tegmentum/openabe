//! Constant-time operations to prevent timing side-channel attacks

use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

/// Constant-time byte slice comparison
///
/// Returns true if and only if the two slices are equal.
/// The comparison time is independent of the slice contents.
pub fn secure_compare(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

/// Constant-time table lookup
///
/// Returns the element at `index` without revealing which index was accessed
/// through timing. All elements are accessed in constant time.
pub fn ct_select<T: ConditionallySelectable + Copy>(table: &[T], index: usize) -> T {
    assert!(!table.is_empty(), "Table cannot be empty");
    let mut result = table[0];
    for (i, item) in table.iter().enumerate() {
        let choice = Choice::from((i == index) as u8);
        result.conditional_assign(item, choice);
    }
    result
}

/// Constant-time conditional select between two values
pub fn ct_select_pair<T: ConditionallySelectable>(a: T, b: T, choice: bool) -> T {
    T::conditional_select(&a, &b, Choice::from(choice as u8))
}

/// Constant-time equality check for fixed-size arrays
pub fn ct_eq_array<const N: usize>(a: &[u8; N], b: &[u8; N]) -> bool {
    a.ct_eq(b).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_compare_equal() {
        let a = b"hello world";
        let b = b"hello world";
        assert!(secure_compare(a, b));
    }

    #[test]
    fn test_secure_compare_different() {
        let a = b"hello world";
        let b = b"hello worle";
        assert!(!secure_compare(a, b));
    }

    #[test]
    fn test_secure_compare_different_lengths() {
        let a = b"hello";
        let b = b"hello world";
        assert!(!secure_compare(a, b));
    }

    #[test]
    fn test_ct_select() {
        let table = [1u8, 2, 3, 4, 5];
        assert_eq!(ct_select(&table, 0), 1);
        assert_eq!(ct_select(&table, 2), 3);
        assert_eq!(ct_select(&table, 4), 5);
    }

    #[test]
    fn test_ct_select_pair() {
        assert_eq!(ct_select_pair(10u32, 20u32, false), 10);
        assert_eq!(ct_select_pair(10u32, 20u32, true), 20);
    }

    #[test]
    fn test_ct_eq_array() {
        let a = [1u8, 2, 3, 4];
        let b = [1u8, 2, 3, 4];
        let c = [1u8, 2, 3, 5];
        assert!(ct_eq_array(&a, &b));
        assert!(!ct_eq_array(&a, &c));
    }
}
