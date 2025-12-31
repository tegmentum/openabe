# MCL Bug Clarification: Where Was The Bug?

## TL;DR

**There is NO bug in MCL library.** The bug was in OpenABE's wrapper code that calls MCL functions.

## The Question

"So there is a bug in MCL but we worked around it?"

## The Answer

**NO.** There is no bug in MCL. We fixed a bug in OpenABE's code.

## What Happened

### MCL Library Status: ✅ CORRECT

MCL library functions work perfectly:
- `mclBn_pairing(result, P, Q)` - Correctly computes e(P, Q) = finalExp(millerLoop(P, Q))
- `mclBn_millerLoop(result, P, Q)` - Correctly computes the miller loop
- `mclBn_finalExp(result, f)` - Correctly computes the final exponentiation
- `mclBnGT_mul(result, a, b)` - Correctly multiplies GT elements

**Evidence**: We wrote `test-mcl-negative-fix.cpp` that calls MCL directly, and it works perfectly.

### OpenABE Wrapper Status: ❌ HAD A BUG (NOW FIXED)

The bug was in OpenABE's `multi_bp_map_op()` function in `src/zml/zelement_bp.cpp`.

**Original buggy wrapper code** (lines 327-345):
```c
#else /* BP_WITH_MCL */
  // For MCL, compute multi-pairing
  mclBnGT temp;
  if (n == 0) {
    mclBnGT_clear(gt.m_GT);
  } else {
    for (size_t i = 0; i < n; i++) {
      mclBn_pairing(&temp, ps[i], qs[i]);  // ❌ BUG: Wrong algorithm!
      if (i == 0) {
        mclBnGT_copy(gt.m_GT, &temp);
      } else {
        mclBnGT_mul(gt.m_GT, gt.m_GT, &temp);
      }
    }
  }
#endif
```

**Problem**: This computes `prod(pairing(Pi, Qi))` incorrectly by doing:
1. For each pair (Pi, Qi): compute full pairing = millerLoop + finalExp
2. Multiply the results

This gives: `prod(finalExp(millerLoop(Pi, Qi)))` ❌ WRONG

**Fixed wrapper code** (lines 327-351):
```c
#else /* BP_WITH_MCL */
  // For MCL, we need to use the correct multi-pairing algorithm:
  // Compute all miller loops, then do ONE final exponentiation
  if (n == 0) {
    mclBnGT_clear(gt.m_GT);
  } else if (n == 1) {
    mclBn_pairing(gt.m_GT, ps[0], qs[0]);
  } else {
    // For multiple pairings, compute miller loops then final exp
    mclBnGT temp;
    mclBn_millerLoop(&temp, ps[0], qs[0]);  // ✅ Just miller loop
    mclBnGT_copy(gt.m_GT, &temp);

    for (size_t i = 1; i < n; i++) {
      mclBn_millerLoop(&temp, ps[i], qs[i]);  // ✅ Just miller loop
      mclBnGT_mul(gt.m_GT, gt.m_GT, &temp);
    }

    mclBn_finalExp(gt.m_GT, gt.m_GT);  // ✅ ONE final exp at end
  }
#endif
```

**Solution**: Now correctly computes:
1. For each pair (Pi, Qi): compute ONLY miller loop
2. Multiply all miller loop results
3. Do ONE final exponentiation at the end

This gives: `finalExp(prod(millerLoop(Pi, Qi)))` ✅ CORRECT

## What Did We Fix?

We fixed **how OpenABE calls MCL functions**, not MCL itself.

| Component | Status | Action |
|-----------|--------|--------|
| MCL Library | ✅ Always worked correctly | None needed |
| OpenABE wrapper | ❌ Had bug → ✅ Fixed | Changed algorithm in `multi_bp_map_op()` |

## Comparison: Why RELIC Worked

RELIC has a **native multi-pairing function** `pp_map_sim_oatep_k12()` that implements the correct algorithm internally:

```c
void pp_map_sim_oatep_k12(fp12_t r, const ep_t *p, const ep2_t *q, int m) {
    pp_mil_k12(r, t, _q, _p, j, a);           // All miller loops
    for (i = 0; i < j; i++) {
        pp_fin_k12_oatep(r, t[i], _q[i], _p[i]);  // Finalization
    }
    pp_exp_k12(r, r);                          // ONE final exp
}
```

So when OpenABE calls `pp_map_sim_oatep_k12()` with RELIC, it gets the correct multi-pairing automatically.

MCL doesn't have a built-in multi-pairing function, so OpenABE has to implement it manually. The manual implementation was wrong - we fixed it.

## What About Other RELIC Bugs?

The RELIC 0.7.0 buffer overflow bug and global state bug are **completely unrelated** to multi-pairing:

| Bug | Location | Nature | Relation to Multi-Pairing |
|-----|----------|--------|---------------------------|
| RELIC 0.7.0 buffer overflow | `ep_mul_slide()` | Scalar multiplication buffer sizing | **NONE** - different operation |
| RELIC global state | Curve parameter management | State corruption when switching curves | **NONE** - different subsystem |
| OpenABE MCL wrapper | `multi_bp_map_op()` | Wrong multi-pairing algorithm | **THIS** is what we fixed |

## Summary

- ✅ MCL library: No bug, works correctly
- ❌ OpenABE wrapper: Had a bug in multi-pairing algorithm
- ✅ Fix: Changed how OpenABE calls MCL functions
- ✅ Result: CP-ABE now works perfectly with MCL

**We did NOT work around an MCL bug. We fixed a bug in OpenABE's code.**

## Date

Clarification written: October 9, 2025
