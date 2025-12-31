# MCL CP-ABE Status

**Date:** October 9, 2025
**Status:** ❌ **NOT WORKING** - Bug Confirmed
**Severity:** Critical - CP-ABE unusable with MCL backend

---

## Quick Summary

**CP-ABE does NOT work with the MCL cryptographic library backend.**

After extensive investigation, the issue has been isolated to the Waters CP-ABE decryption formula producing an incorrect target group (GT) element. This causes all CP-ABE decryption operations to fail CCA (Chosen Ciphertext Attack) verification.

**Workaround:** Use RELIC backend for CP-ABE operations (confirmed working).

---

## What Works ✅

- **KP-ABE** (Key-Policy ABE) - Works with MCL
- **PKE** (Public Key Encryption) - Works with MCL
- **PKSig** (Public Key Signatures) - Works with MCL
- **All primitive operations** - Pairing, GT ops, G1/G2 ops all work individually
- **CP-ABE with RELIC backend** - Fully functional

## What Doesn't Work ❌

- **CP-ABE with MCL backend** - Completely broken
  - Encryption succeeds
  - Decryption fails with: "Failed ABE decryption verification check"
  - Affects all policies (simple AND, complex threshold, etc.)
  - Affects all attribute counts (single, multiple)

---

## Technical Details

### The Bug

The Waters CP-ABE decryption formula:

```
final_GT = e(C', K) / (prodT * e(prod1, L))
```

Should recover the original encrypted GT element `C = e(g1, g2)^(α*s)`, but with MCL it produces an incorrect value.

### Evidence

Test with policy `(attr1 AND attr2)`:

```
Expected C (from encryption):      4608159FD1123398...
Computed final (from decryption):  3C33E34181980A73...
```

These values differ, causing CCA verification to fail when re-encrypting for comparison.

### What We Tested

Over 10+ test programs verified these components work correctly:

1. ✅ Multi-pairing computation
2. ✅ GT multiplication and division
3. ✅ GT serialization/deserialization
4. ✅ Pairing bilinearity: `e(g1^a, g2) == e(g1, g2)^a`
5. ✅ Chained operations: `e(g1, g2)^alpha`
6. ✅ Deterministic RNG
7. ✅ G1/G2 scalar multiplication
8. ✅ Element copy constructors

**All individual MCL operations work correctly!** The bug only manifests when operations are combined in the CP-ABE decryption formula.

---

## Impact

### For Users

- **Cannot use CP-ABE with MCL** - Must use RELIC backend
- All CP-ABE test cases fail with MCL
- Production systems must avoid MCL for CP-ABE

### For Developers

- MCL integration is incomplete
- CP-ABE code is correct (works with RELIC)
- Issue is in MCL library or OpenABE's MCL wrapper

---

## Investigation History

**Total Time:** ~8 hours of systematic debugging
**Test Programs Created:** 10+
**Components Verified:** 15+
**Hypotheses Tested:** 6+

See detailed documentation:
- [`MCL-INVESTIGATION-FINDINGS.md`](./MCL-INVESTIGATION-FINDINGS.md) - Chronological log
- [`MCL-CP-ABE-BUG-SUMMARY.md`](./MCL-CP-ABE-BUG-SUMMARY.md) - Executive summary
- [`CP-ABE-DEBUG-LOGGING.md`](./CP-ABE-DEBUG-LOGGING.md) - Debug instrumentation

---

## Recommendations

### For Production Use

**Use RELIC backend for CP-ABE:**
```bash
# Build with RELIC (default configuration)
./build.sh native
```

**Avoid MCL for CP-ABE:**
```bash
# MCL is not suitable for CP-ABE at this time
# Use for KP-ABE, PKE, or PKSig only
```

### For Fixing the Bug

Priority options:

1. **Report to MCL developers** - Provide minimal reproduction case
2. **Compare with RELIC** - Trace exact operation differences
3. **Debug MCL internals** - Deep dive into GT operations source
4. **Accept limitation** - Document CP-ABE as RELIC-only

---

## File Locations

### Source Code with Debug Logging
- `src/abe/zcontextcpwaters.cpp:206-427` - CP-ABE encrypt/decrypt
- `src/abe/zcontextcca.cpp:300-450` - CCA verification wrapper
- `src/zml/zelement_bp.cpp:830-1320` - Element operations
- `src/zml/zelement_mcl.c:300-440` - MCL wrapper functions

### Test Programs
- `src/test-mcl-multipairing.cpp` - Multi-pairing verification
- `src/test-mcl-gt-serialization.cpp` - GT serialization tests
- `src/test-mcl-gt-chained-ops.cpp` - Chained operations
- Plus 7 more test programs in `src/test-mcl-*.cpp`

### Documentation
- `docs/MCL-INVESTIGATION-FINDINGS.md` - Detailed investigation log
- `docs/MCL-CP-ABE-BUG-SUMMARY.md` - Executive summary
- `docs/CP-ABE-DEBUG-LOGGING.md` - Debug guide
- `MCL-INVESTIGATION-SUMMARY.txt` - Quick reference

---

## Questions?

**Q: Can I use MCL for anything in OpenABE?**
A: Yes! MCL works fine for KP-ABE, PKE, and PKSig. Only CP-ABE is affected.

**Q: Will this be fixed?**
A: Unknown. This requires either fixing the MCL library bug or finding a workaround in OpenABE's MCL integration.

**Q: Can I help debug this?**
A: Yes! Start with the test programs and documentation listed above. The bug is reproducible and well-documented.

**Q: Should I use RELIC or MCL?**
A: For CP-ABE: **Use RELIC**. For other schemes: Either works.

---

## Version Info

- **OpenABE:** Current development version (October 2025)
- **MCL:** v1.x (bundled)
- **RELIC:** v0.7.0 (upgraded from v0.5.0)
- **Issue Status:** Confirmed, documented, awaiting fix

---

**Last Updated:** October 9, 2025
**Investigator:** System debugging team
**Status:** Open issue - workaround available (use RELIC)
