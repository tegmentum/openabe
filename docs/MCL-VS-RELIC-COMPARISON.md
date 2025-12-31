# MCL vs RELIC Multi-Pairing Comparison

## Why RELIC Worked and MCL Didn't

### RELIC Implementation ✅

RELIC has a **native multi-pairing function** that implements the correct algorithm:

**Function**: `pp_map_sim_oatep_k12()` in `src/pp/relic_pp_map_k12.c`

```c
void pp_map_sim_oatep_k12(fp12_t r, const ep_t *p, const ep2_t *q, int m) {
    // ... setup ...

    // Step 1: Compute ALL miller loops together
    pp_mil_k12(r, t, _q, _p, j, a);

    // Step 2: Finalization steps for each pair
    for (i = 0; i < j; i++) {
        pp_fin_k12_oatep(r, t[i], _q[i], _p[i]);
    }

    // Step 3: Final exponentiation ONCE
    pp_exp_k12(r, r);
}
```

**Key Points**:
1. Uses a specialized multi-miller-loop function (`pp_mil_k12`)
2. Performs finalization steps in the loop
3. Does **ONE** final exponentiation at the end

This implements the correct formula:
```
prod(e(P_i, Q_i)) = finalExp(prod(millerLoop(P_i, Q_i)))
```

### Original MCL Implementation ❌

The original OpenABE implementation for MCL was:

```c
for (size_t i = 0; i < n; i++) {
    mclBn_pairing(&temp, ps[i], qs[i]);  // Each pairing = millerLoop + finalExp
    if (i == 0) {
        mclBnGT_copy(gt.m_GT, &temp);
    } else {
        mclBnGT_mul(gt.m_GT, gt.m_GT, &temp);
    }
}
```

**Problem**: Each call to `mclBn_pairing()` does:
1. Miller loop
2. **Final exponentiation**
3. Then multiplies the results

This implements the **WRONG** formula:
```
prod(finalExp(millerLoop(P_i, Q_i)))
```

### Why The Difference Matters

The final exponentiation is a **non-linear** operation that maps from an intermediate field to the target group GT. It **cannot be distributed** over multiplication:

```
finalExp(A * B) ≠ finalExp(A) * finalExp(B)
```

Therefore:
```
finalExp(millerLoop(P1,Q1) * millerLoop(P2,Q2)) ≠ finalExp(millerLoop(P1,Q1)) * finalExp(millerLoop(P2,Q2))
```

The left side is correct, the right side gives wrong results!

### Fixed MCL Implementation ✅

```c
if (n == 0) {
    mclBnGT_clear(gt.m_GT);
} else if (n == 1) {
    mclBn_pairing(gt.m_GT, ps[0], qs[0]);
} else {
    // Compute all miller loops
    mclBnGT temp;
    mclBn_millerLoop(&temp, ps[0], qs[0]);
    mclBnGT_copy(gt.m_GT, &temp);

    for (size_t i = 1; i < n; i++) {
        mclBn_millerLoop(&temp, ps[i], qs[i]);
        mclBnGT_mul(gt.m_GT, gt.m_GT, &temp);
    }

    // Final exponentiation ONCE
    mclBn_finalExp(gt.m_GT, gt.m_GT);
}
```

Now it matches RELIC's approach!

## RELIC Bugs: Unrelated to Multi-Pairing

### RELIC 0.7.0 Buffer Overflow Bug

**Nature**: Buffer sizing bug in scalar multiplication
**Location**: `src/ep/relic_ep_mul.c` - `ep_mul_slide()` function
**Cause**: Fixed buffer size based on field prime size, but scalar can be larger (group order)
**Impact**: Infinite error loops during G1 scalar multiplication
**Relation to multi-pairing**: **NONE** - completely different operation

### RELIC Global State Corruption

**Nature**: Curve parameter state management issue
**Location**: Global RELIC state for curve configuration
**Cause**: Tests switching between EC curves (NIST_P256) and pairing curves (BN_P254)
**Impact**: Deserialization failures when wrong curve is configured
**Solution**: `bp_ensure_curve_params()` helper to reset curve state before operations
**Relation to multi-pairing**: **NONE** - about curve selection, not pairing computation

## Summary Table

| Aspect | RELIC | MCL (Original) | MCL (Fixed) |
|--------|-------|----------------|-------------|
| Multi-pairing API | Native `pp_map_sim_*` | Manual loop | Manual loop |
| Miller loops | Batched together | Individual | Batched together |
| Final exp | Once at end ✅ | After each pairing ❌ | Once at end ✅ |
| Correctness | Correct ✅ | Wrong ❌ | Correct ✅ |
| CP-ABE | Works ✅ | Broken ❌ | Works ✅ |

## Why This Bug Was Hard to Find

1. **Single pairings work fine**: The bug only manifests in multi-pairing operations
2. **Mathematical subtlety**: The error requires understanding that final exponentiation is non-distributive
3. **RELIC masked the issue**: RELIC's native implementation was always correct
4. **No obvious symptoms**: The code didn't crash, it just computed wrong results
5. **Test coverage gap**: No direct unit tests for multi-pairing mathematical correctness

## Lessons Learned

1. **Use native library functions when available**: RELIC's `pp_map_sim_*` functions implement the correct algorithm
2. **Don't assume operations are distributive**: Final exponentiation is NOT
3. **Test pairing properties**: Verify bilinearity and multi-pairing correctness
4. **Reference standard algorithms**: Multi-pairing has a well-known correct implementation pattern

## References

- **RELIC multi-pairing**: `deps/relic/relic-toolkit-0.7.0.orig/src/pp/relic_pp_map_k12.c`
- **MCL miller loop**: `mclBn_millerLoop()` in MCL library
- **MCL final exp**: `mclBn_finalExp()` in MCL library
- **Pairing computation**: Miller loop + final exponentiation
- **Multi-pairing optimization**: Batch miller loops, then one final exp

## Date

Analysis completed: October 9, 2025
