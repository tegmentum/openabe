# LSSS Coefficient Calculation Bug - FIXED

## Summary

Fixed a critical bug in CP-ABE LSSS coefficient calculation that was causing decryption to fail. The root cause was actually THREE separate bugs that together prevented proper coefficient recovery.

## Bug 1: LSSS Coefficient Squaring

**Location**: `src/tools/zlsss.cpp:395` (original line number)

**Problem**: The Lagrange coefficient calculation was squaring the result each iteration:
```cpp
result *= result * ((this->zero - this->iPlusOne) / (this->indexPlusOne - this->iPlusOne));
```

**Fix**: Removed the extra `result *`:
```cpp
result *= ((this->zero - this->iPlusOne) / (this->indexPlusOne - this->iPlusOne));
```

**Impact**: This caused the second attribute's coefficient to become zero, breaking CP-ABE decryption for multi-attribute policies.

## Bug 2: initZP Assignment Operator Broken with MCL

**Location**: `src/zml/zpairing.cpp:164-171`

**Problem**: The `initZP(ZP& result, uint32_t v)` function was using assignment:
```cpp
result = v;  // Creates temporary ZP(v), then copies - BROKEN with MCL!
```

This relied on creating a temporary `ZP(v)` and using the copy assignment operator, but this was producing empty/zero ZP values with MCL.

**Fix**: Directly call the bignum set function:
```cpp
zml_bignum_setuint(result.m_ZP, v);
result.isOrderSet = false;
result.isInit = true;
result.setOrder(order);
```

**Impact**: All `initZP` calls were producing zero values instead of the requested integer values, causing all coefficient calculations to fail.

## Bug 3: ZP Operator<< String Length Handling

**Location**: `src/zml/zelement_bp.cpp:674-687`

**Problem**: The ZP output operator was subtracting 1 from the string length for all backends:
```cpp
string s0 = string(str, len-1);  // WRONG for MCL!
```

MCL's `mclBnFr_getStr` returns length INCLUDING null terminator (len=2 for "1"), but RELIC's `bn_write_str` doesn't. Subtracting 1 for MCL created empty strings for small values.

**Fix**: Handle MCL and RELIC differently:
```cpp
#if defined(BP_WITH_MCL)
string s0(str); // MCL: use null-terminated string directly
#else
string s0(str, len-1); // RELIC: original behavior
#endif
```

**Impact**: This masked the other bugs by making it appear that ZP values were empty when they were actually set correctly. Made debugging extremely difficult!

## Verification

After all three fixes:

```bash
./oabe_setup -s CP -p test -i "attr1|attr2"
./oabe_keygen -s CP -p test -i "attr1|attr2" -o key.key
echo "test message" > plain.txt
./oabe_enc -s CP -p test -e "attr1 and attr2" -i plain.txt -o cipher.cpabe
./oabe_dec -s CP -p test -k key.key -i cipher.cpabe -o decrypted.txt
```

Coefficients now correctly calculated:
- attr1: 16798108731015832284940804142231733909759579603404752749028378864165570215948
- attr2: 2

Both are non-zero ✓

## Remaining Issues

CCA verification still fails because the re-encryption produces different ciphertext components. This is a separate issue related to encryption determinism, not the LSSS coefficient bug.

## Files Modified

1. `src/tools/zlsss.cpp` - Fixed coefficient calculation
2. `src/zml/zpairing.cpp` - Fixed initZP for MCL
3. `src/zml/zelement_bp.cpp` - Fixed ZP printing for MCL

## Date Fixed

2025-10-10
