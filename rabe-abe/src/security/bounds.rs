//! Bounds checking utilities to prevent integer overflow and out-of-bounds access

use crate::error::AbeError;

/// Trait for checked arithmetic operations that return Result
pub trait CheckedArithmetic: Sized {
    /// Checked addition that returns an error on overflow
    fn checked_add_err(self, rhs: Self) -> Result<Self, AbeError>;
    /// Checked subtraction that returns an error on underflow
    fn checked_sub_err(self, rhs: Self) -> Result<Self, AbeError>;
    /// Checked multiplication that returns an error on overflow
    fn checked_mul_err(self, rhs: Self) -> Result<Self, AbeError>;
}

impl CheckedArithmetic for usize {
    fn checked_add_err(self, rhs: Self) -> Result<Self, AbeError> {
        self.checked_add(rhs)
            .ok_or_else(|| AbeError::InternalError("Integer overflow in addition".into()))
    }

    fn checked_sub_err(self, rhs: Self) -> Result<Self, AbeError> {
        self.checked_sub(rhs)
            .ok_or_else(|| AbeError::InternalError("Integer underflow in subtraction".into()))
    }

    fn checked_mul_err(self, rhs: Self) -> Result<Self, AbeError> {
        self.checked_mul(rhs)
            .ok_or_else(|| AbeError::InternalError("Integer overflow in multiplication".into()))
    }
}

impl CheckedArithmetic for u64 {
    fn checked_add_err(self, rhs: Self) -> Result<Self, AbeError> {
        self.checked_add(rhs)
            .ok_or_else(|| AbeError::InternalError("Integer overflow in addition".into()))
    }

    fn checked_sub_err(self, rhs: Self) -> Result<Self, AbeError> {
        self.checked_sub(rhs)
            .ok_or_else(|| AbeError::InternalError("Integer underflow in subtraction".into()))
    }

    fn checked_mul_err(self, rhs: Self) -> Result<Self, AbeError> {
        self.checked_mul(rhs)
            .ok_or_else(|| AbeError::InternalError("Integer overflow in multiplication".into()))
    }
}

/// Safe array indexing that returns a Result instead of panicking
pub fn safe_index<T>(slice: &[T], index: usize) -> Result<&T, AbeError> {
    slice.get(index).ok_or_else(|| {
        AbeError::InternalError(format!(
            "Index {} out of bounds for slice of length {}",
            index,
            slice.len()
        ))
    })
}

/// Safe mutable array indexing
pub fn safe_index_mut<T>(slice: &mut [T], index: usize) -> Result<&mut T, AbeError> {
    let len = slice.len();
    slice.get_mut(index).ok_or_else(|| {
        AbeError::InternalError(format!(
            "Index {} out of bounds for slice of length {}",
            index, len
        ))
    })
}

/// Safe slice range extraction
pub fn safe_slice<T>(slice: &[T], start: usize, end: usize) -> Result<&[T], AbeError> {
    if start > end {
        return Err(AbeError::InternalError(format!(
            "Invalid range: start {} > end {}",
            start, end
        )));
    }
    if end > slice.len() {
        return Err(AbeError::InternalError(format!(
            "Range end {} exceeds slice length {}",
            end,
            slice.len()
        )));
    }
    Ok(&slice[start..end])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_checked_add() {
        assert_eq!(5usize.checked_add_err(3).unwrap(), 8);
        assert!(usize::MAX.checked_add_err(1).is_err());
    }

    #[test]
    fn test_checked_sub() {
        assert_eq!(5usize.checked_sub_err(3).unwrap(), 2);
        assert!(0usize.checked_sub_err(1).is_err());
    }

    #[test]
    fn test_checked_mul() {
        assert_eq!(5usize.checked_mul_err(3).unwrap(), 15);
        assert!(usize::MAX.checked_mul_err(2).is_err());
    }

    #[test]
    fn test_safe_index() {
        let arr = [1, 2, 3, 4, 5];
        assert_eq!(*safe_index(&arr, 2).unwrap(), 3);
        assert!(safe_index(&arr, 10).is_err());
    }

    #[test]
    fn test_safe_slice() {
        let arr = [1, 2, 3, 4, 5];
        assert_eq!(safe_slice(&arr, 1, 4).unwrap(), &[2, 3, 4]);
        assert!(safe_slice(&arr, 3, 2).is_err()); // start > end
        assert!(safe_slice(&arr, 0, 10).is_err()); // end > len
    }
}
