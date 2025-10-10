# MCL CP-ABE Investigation - Documentation Index

This index helps you navigate the comprehensive documentation from the MCL CP-ABE investigation.

---

## 📋 Start Here

**🆕 LATEST UPDATE:** → [`MCL-BUG-2-COMPLETE.md`](MCL-BUG-2-COMPLETE.md) - **✅ BUG #2 FIXED AND VERIFIED! All tests passing!**

**Complete summary:** → [`MCL-BUG-2-COMPLETE.md`](MCL-BUG-2-COMPLETE.md) - Full investigation & fix summary with test results

**Bug #2 fix details:** → [`MCL-BUG-2-FIX.md`](MCL-BUG-2-FIX.md) - Complete fix implementation and testing

**Bug #2 smoking gun:** → [`MCL-BUG-2-SMOKING-GUN.md`](MCL-BUG-2-SMOKING-GUN.md) - Exact code location that caused the bug

**Bug #2 root cause:** → [`MCL-BUG-2-ROOT-CAUSE-ANALYSIS.md`](MCL-BUG-2-ROOT-CAUSE-ANALYSIS.md) - Detailed technical analysis

**Bug #2 summary:** → [`MCL-BUG-2-FOUND.md`](MCL-BUG-2-FOUND.md) - Overview of non-determinism issue

**Bug #1 workaround results:** → [`MCL-WORKAROUND-TEST-RESULTS.md`](MCL-WORKAROUND-TEST-RESULTS.md) - Workaround verified, Bug #2 discovered

**Executive summary:** → [`MCL-WORKAROUND-SUMMARY.md`](MCL-WORKAROUND-SUMMARY.md) - Workaround overview

**Implementation details:** → [`MCL-PAIRING-WORKAROUND-STATUS.md`](MCL-PAIRING-WORKAROUND-STATUS.md) - Technical implementation

**New to this investigation?** → [`MCL-INVESTIGATION-README.md`](MCL-INVESTIGATION-README.md)

**Just need to know what works?** → [`docs/MCL-CPABE-STATUS.md`](docs/MCL-CPABE-STATUS.md)

**Quick reference?** → [`MCL-INVESTIGATION-SUMMARY.txt`](MCL-INVESTIGATION-SUMMARY.txt)

---

## 📚 Documentation by Audience

### For Users
**Want to know if you can use MCL for CP-ABE?**

1. [`docs/MCL-CPABE-STATUS.md`](docs/MCL-CPABE-STATUS.md) - Current status, workarounds, FAQ
2. [`MCL-INVESTIGATION-README.md`](MCL-INVESTIGATION-README.md) - Quick start guide

**Answer:** No, use RELIC for CP-ABE. MCL works for KP-ABE, PKE, PKSig.

---

### For Developers  
**Need to understand the bug for development?**

1. [`docs/MCL-CP-ABE-BUG-SUMMARY.md`](docs/MCL-CP-ABE-BUG-SUMMARY.md) - Executive summary
2. [`MCL-INVESTIGATION-README.md`](MCL-INVESTIGATION-README.md) - Complete overview
3. Test programs in `src/test-mcl-*.cpp`

**Key Finding:** CP-ABE decryption formula produces wrong GT element with MCL.

---

### For Investigators
**Want to fix the bug or continue investigation?**

1. [`docs/MCL-INVESTIGATION-FINDINGS.md`](docs/MCL-INVESTIGATION-FINDINGS.md) - Detailed chronological log
2. [`docs/MCL-CP-ABE-BUG-SUMMARY.md`](docs/MCL-CP-ABE-BUG-SUMMARY.md) - Evidence summary
3. [`docs/CP-ABE-DEBUG-LOGGING.md`](docs/CP-ABE-DEBUG-LOGGING.md) - Debug instrumentation
4. Test programs in `src/test-mcl-*.cpp`
5. Modified source files with debug logging

**Evidence:** All MCL primitives work individually; bug appears when combined.

---

## 📁 Document Descriptions

### Main Documentation

| Document | Purpose | Length | Audience |
|----------|---------|--------|----------|
| [`MCL-BUG-2-COMPLETE.md`](MCL-BUG-2-COMPLETE.md) | 🆕 **✅ Complete Bug #2 fix & verification** | Long | All |
| [`MCL-BUG-2-FIX.md`](MCL-BUG-2-FIX.md) | Bug #2 fix implementation details | Long | Developers |
| [`MCL-BUG-2-SMOKING-GUN.md`](MCL-BUG-2-SMOKING-GUN.md) | Bug #2 root cause evidence | Medium | Investigators |
| [`MCL-WORKAROUND-TEST-RESULTS.md`](MCL-WORKAROUND-TEST-RESULTS.md) | Test results & 2nd bug confirmed | Long | All |
| [`MCL-WORKAROUND-SUMMARY.md`](MCL-WORKAROUND-SUMMARY.md) | Workaround executive summary | Medium | Executives/Leads |
| [`MCL-PAIRING-WORKAROUND-STATUS.md`](MCL-PAIRING-WORKAROUND-STATUS.md) | Workaround implementation details | Medium | Developers |
| [`MCL-INVESTIGATION-README.md`](MCL-INVESTIGATION-README.md) | Complete overview & guide | Long | All |
| [`MCL-INVESTIGATION-SUMMARY.txt`](MCL-INVESTIGATION-SUMMARY.txt) | Quick reference | 1 page | All |
| [`INVESTIGATION-INDEX.md`](INVESTIGATION-INDEX.md) | This file | Short | All |

### Technical Documentation (in `docs/`)

| Document | Purpose | Length | Audience |
|----------|---------|--------|----------|
| [`MCL-CPABE-STATUS.md`](docs/MCL-CPABE-STATUS.md) | User-friendly status | Medium | Users |
| [`MCL-CP-ABE-BUG-SUMMARY.md`](docs/MCL-CP-ABE-BUG-SUMMARY.md) | Executive summary | Medium | Developers |
| [`MCL-INVESTIGATION-FINDINGS.md`](docs/MCL-INVESTIGATION-FINDINGS.md) | Detailed investigation | Long | Investigators |
| [`CP-ABE-DEBUG-LOGGING.md`](docs/CP-ABE-DEBUG-LOGGING.md) | Debug guide | Short | Developers |

### Bug Reports

| Document | Purpose | Length | Audience |
|----------|---------|--------|----------|
| [`MCL-BUG-FOUND.md`](MCL-BUG-FOUND.md) | 🐛 GT identity multiplication bug | Medium | MCL Developers |
| [`MCL-INVESTIGATION-BREAKTHROUGH.md`](MCL-INVESTIGATION-BREAKTHROUGH.md) | Bug discovery process | Long | Investigators |
| [`MCL-MULTI-PAIRING-ANALYSIS.md`](docs/MCL-MULTI-PAIRING-ANALYSIS.md) | Implementation comparison | Medium | Developers |
| [`MCL-INVESTIGATION-UPDATE.md`](MCL-INVESTIGATION-UPDATE.md) | Analysis leading to discovery | Medium | Investigators |

---

## 🧪 Test Programs

All located in `src/`, each with detailed comments:

### Verification Tests (✅ All Passed)
- `test-mcl-multipairing.cpp` - Multi-pairing verification
- `test-mcl-gt-serialization.cpp` - GT serialization tests
- `test-mcl-gt-chained-ops.cpp` - Chained operation tests

### Formula Tests (For further investigation)
- `test-mcl-cpabe-formula.cpp` - Waters formula isolation
- `test-cpabe-math.cpp` - Mathematical verification
- `test-mcl-inplace.c` - In-place operation tests

### Other Tests
- Plus 7 more specialized test programs
- Each tests specific MCL functionality
- All demonstrate correct operation in isolation

---

## 🔍 Finding Specific Information

### "What schemes work with MCL?"
→ [`docs/MCL-CPABE-STATUS.md`](docs/MCL-CPABE-STATUS.md) - "What Works" section

### "What exactly is broken?"
→ [`docs/MCL-CP-ABE-BUG-SUMMARY.md`](docs/MCL-CP-ABE-BUG-SUMMARY.md) - "Root Cause" section

### "What was tested?"
→ [`docs/MCL-INVESTIGATION-FINDINGS.md`](docs/MCL-INVESTIGATION-FINDINGS.md) - "Key Findings" section

### "How do I work around this?"
→ [`docs/MCL-CPABE-STATUS.md`](docs/MCL-CPABE-STATUS.md) - "Recommendations" section

### "Where is the debug logging?"
→ [`docs/CP-ABE-DEBUG-LOGGING.md`](docs/CP-ABE-DEBUG-LOGGING.md)

### "How do I reproduce the bug?"
→ [`MCL-INVESTIGATION-README.md`](MCL-INVESTIGATION-README.md) - "Evidence" section

### "What are the intermediate values?"
→ [`docs/MCL-INVESTIGATION-FINDINGS.md`](docs/MCL-INVESTIGATION-FINDINGS.md) - Debug output sections

---

## 🎯 Common Use Cases

### Case 1: I just want to use OpenABE
**Read:** [`docs/MCL-CPABE-STATUS.md`](docs/MCL-CPABE-STATUS.md)
**Answer:** Use RELIC for CP-ABE, MCL for other schemes

### Case 2: I need to report this to stakeholders
**Read:** [`docs/MCL-CP-ABE-BUG-SUMMARY.md`](docs/MCL-CP-ABE-BUG-SUMMARY.md)
**Key Points:** Confirmed bug, workaround available, low priority fix

### Case 3: I want to fix the bug
**Read (in order):**
1. [`docs/MCL-CP-ABE-BUG-SUMMARY.md`](docs/MCL-CP-ABE-BUG-SUMMARY.md)
2. [`docs/MCL-INVESTIGATION-FINDINGS.md`](docs/MCL-INVESTIGATION-FINDINGS.md)
3. Test programs in `src/test-mcl-*.cpp`
4. Source files with debug logging

### Case 4: I'm curious about the investigation process
**Read:** [`docs/MCL-INVESTIGATION-FINDINGS.md`](docs/MCL-INVESTIGATION-FINDINGS.md)
**Highlights:** 8 hours, 10+ tests, 15+ components verified

---

## 📊 Quick Statistics

- **Documentation Files:** 5 main + 4 technical = 9 total
- **Test Programs:** 10+
- **Components Verified:** 15+
- **Hypotheses Tested:** 6+
- **Investigation Time:** ~8 hours
- **Result:** Bug confirmed, documented, workaround available

---

## 🔗 Related Files

### Modified Source (with debug logging)
- `src/abe/zcontextcpwaters.cpp` - CP-ABE implementation
- `src/abe/zcontextcca.cpp` - CCA verification
- `src/zml/zelement_bp.cpp` - Element operations
- `src/tools/zprng.cpp` - RNG operations

### Build Artifacts
- Test executables in `src/`
- Test data in `/tmp/oabe_fresh_test/`
- CLI test data in `cli/`

---

## 💡 Key Takeaways

1. **CP-ABE does NOT work with MCL** ❌
2. **All other schemes work fine** ✅
3. **Use RELIC for CP-ABE** (workaround) ✅
4. **Bug is well-documented** 📚
5. **All primitives work individually** ✅
6. **Bug appears in combination** 🐛

---

## 📮 Where to Go From Here

**For production use:**
→ Use RELIC backend for CP-ABE

**For bug reports:**
→ Share [`docs/MCL-CP-ABE-BUG-SUMMARY.md`](docs/MCL-CP-ABE-BUG-SUMMARY.md)

**For investigation:**
→ Start with [`docs/MCL-INVESTIGATION-FINDINGS.md`](docs/MCL-INVESTIGATION-FINDINGS.md)

**For questions:**
→ Check FAQ in [`docs/MCL-CPABE-STATUS.md`](docs/MCL-CPABE-STATUS.md)

---

**Last Updated:** October 9, 2025
**Status:** Documentation Complete
**Recommendation:** Use RELIC for CP-ABE
