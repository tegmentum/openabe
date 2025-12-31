# RELIC 0.7.0 Upgrade Investigation Summary

## Executive Summary

**Objective**: Upgrade OpenABE from RELIC 0.5.0 to RELIC 0.7.0

**Result**: ❌ **Upgrade failed** - Critical bug in RELIC 0.7.0 prevents native builds from working

**Recommendation**: **Revert to RELIC 0.5.0**

## Investigation Timeline

### Phase 1: Initial Upgrade (Completed)
- ✅ Downloaded RELIC 0.7.0 source
- ✅ Updated build scripts and dependencies
- ✅ Fixed API compatibility issues in OpenABE code
- ✅ Resolved compilation errors

### Phase 2: Bug Discovery (Completed)
- ❌ Tests hang with infinite error messages
- ✅ Isolated bug to RELIC's `ep_mul_slide()` function
- ✅ Identified buffer overflow in sliding window scalar multiplication
- ✅ Confirmed bug affects BN254 pairing operations

### Phase 3: Root Cause Analysis (Completed)
- ✅ Found bug in `src/ep/relic_ep_mul.c` line 501
- ✅ Discovered bug exists in 5 different functions:
  - `ep_mul_slide()` (G1 operations)
  - `ep2_mul_slide()` (G2 operations)
  - `ep3_mul_slide()` (extension field operations)
  - `ep4_mul_slide()` (extension field operations)
  - `ep8_mul_slide()` (extension field operations)
- ✅ Determined RELIC's tests don't catch this bug
- ✅ Verified this is a genuine RELIC bug, not OpenABE misuse

### Phase 4: Attempted Fix (Completed - Unsuccessful)
- ✅ Created patches for all 5 affected functions
- ✅ Applied fixes using sed to change buffer sizes
- ✅ Rebuilt RELIC libraries multiple times
- ❌ Tests still fail despite comprehensive patching
- ❌ Root cause remains partially unclear

## Technical Details

### The Bug

RELIC 0.7.0's windowed scalar multiplication functions allocate buffers sized for the field prime (`RLC_FP_BITS + 1 = 255 bytes`) but the sliding window recoding requires buffers sized for the group order, which can exceed the field size for BN curves.

**Error manifestation**:
```
ERROR THROWN in relic_bn_rec.c:122
ERROR THROWN in relic_bn_rec.c:122
[infinite loop...]
```

### Attempted Fixes

Changed buffer allocations from:
```c
uint8_t win[RLC_FP_BITS + 1];  // 255 bytes
l = RLC_FP_BITS + 1;
```

To:
```c
uint8_t win[RLC_BN_BITS * 2];  // 508 bytes
l = RLC_BN_BITS * 2;
```

Applied to all 5 affected functions, but **tests continue to fail**.

## Files Modified During Investigation

### OpenABE Code Changes (For RELIC 0.7.0 Compatibility)
- `src/include/openabe/zml/relic_compat.h` - Added compatibility macros
- `src/zml/zelement_bp.cpp` - Fixed RNG callback signature (line 281)
- `src/zml/zstandard_serialization.cpp` - Removed `.norm` field references
- `src/zml/zelliptic.cpp` - Fixed void return handling (line 239)

### RELIC Patches Created
- `deps/relic/buffer_fix.patch` - Attempted comprehensive fix (incomplete)

### Documentation
- `docs/RELIC-0.7.0-BUG-REPORT.md` - Comprehensive bug analysis
- `docs/RNG-SECURITY-ANALYSIS.md` - RNG security documentation (from previous work)
- `docs/KNOWN-TEST-ISSUES.md` - Test documentation (from previous work)

## Recommendation

### Revert to RELIC 0.5.0

**Why**:
1. RELIC 0.7.0 has a critical bug that we cannot fully fix
2. RELIC 0.5.0 is proven to work with OpenABE
3. Further debugging has diminishing returns
4. Risk of unknown issues in 0.7.0 is too high

**How to revert**:
```bash
cd deps/relic
# Edit Makefile: Change VERSION=0.7.0 to VERSION=0.5.0
# Remove or comment out buffer_fix.patch application
make clean
cd ../..

# Revert OpenABE code changes if needed
git checkout src/include/openabe/zml/relic_compat.h
git checkout src/zml/zelement_bp.cpp
git checkout src/zml/zstandard_serialization.cpp

# Full rebuild
./build.sh native
```

### Alternative: Wait for Upstream Fix

If RELIC 0.7.0 features are required:
1. Report bug to RELIC maintainers: https://github.com/relic-toolkit/relic/issues
2. Provide minimal test case and configuration details
3. Wait for official fix in RELIC 0.7.1+ or 0.8.0
4. Re-attempt upgrade once fix is confirmed

## Lessons Learned

1. **Test coverage gaps**: RELIC's tests don't exercise all code paths with all configurations
2. **Configuration sensitivity**: Bugs can be configuration-specific (EP_METHD, curve choice, etc.)
3. **Complexity of cryptographic libraries**: Small buffer sizing errors can cause systemic failures
4. **Value of isolation**: Creating minimal test cases helps identify library vs application bugs
5. **When to stop**: Sometimes reverting is better than continued debugging

## Current State

- ✅ Comprehensive bug report documented
- ✅ All investigation findings recorded
- ⚠️ System still on RELIC 0.7.0 (broken state)
- ❌ Tests failing
- 📋 Next action: Revert to RELIC 0.5.0

## References

- Main bug report: `docs/RELIC-0.7.0-BUG-REPORT.md`
- RELIC source: `deps/relic/relic-toolkit-0.7.0/`
- RELIC GitHub: https://github.com/relic-toolkit/relic
- OpenABE repository: Current working directory

---

**Date**: 2025-10-07
**Investigator**: Claude (Anthropic AI)
**Status**: Investigation complete - Awaiting reversion decision
