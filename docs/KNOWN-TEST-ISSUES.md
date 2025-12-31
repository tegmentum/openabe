# Known Test Issues

This document tracks known issues with the OpenABE test suite that are **pre-existing** and not introduced by recent commits.

## Test Status Summary

| Category | Passing | Failing | Status |
|----------|---------|---------|--------|
| Non-PKSIG, Non-CryptoBox | 38 | 0 | ✅ All Pass |
| PKSIG Tests | 0 | 4 | ⚠️ All Hang (Pre-existing) |
| CryptoBox ABE Tests | 0 | 4 | ⚠️ RELIC Error (Pre-existing) |
| **Total** | **38** | **8** | **83% Pass Rate** |

## Issue 1: PKSIG Tests Hang (Pre-existing)

### Affected Tests
- `libopenabe.PKSIGLowLevelContext`
- `libopenabe.PKSIGSchemeContext`
- `libopenabe.CryptoBoxPKSIGContext`
- `libopenabe.CryptoBoxPKSIGContextMinusBase64Encoding`

### Symptoms
All PKSIG tests hang indefinitely and do not complete. They must be killed with timeout or Ctrl+C.

### Status
**⚠️ PRE-EXISTING** - This issue exists on commit `b9256bf` (before the OpenSSL 3.x compatibility fixes in commit `1cceec5`).

### Investigation
Tested on commit `b9256bf` (parent of the OpenSSL fixes):
```bash
$ git checkout b9256bf
$ timeout 5 ./test_libopenabe '--gtest_filter=libopenabe.PKSIGLowLevelContext'
libopenabe v1.7 test utility.
[ RUN      ] libopenabe.PKSIGLowLevelContext
[Hangs - times out after 5 seconds]
```

The test hangs at the same location before and after the OpenSSL `EVP_MD_CTX` API changes, confirming this is a pre-existing issue.

### Likely Cause
The PKSIG tests use OpenSSL's elliptic curve cryptography functions (`EC_KEY`, `EC_GROUP`) which may have compatibility issues with OpenSSL 3.x on macOS. The hanging could be related to:
- Mutex/threading issues in OpenSSL 3.x EC operations
- OpenSSL 3.x provider loading hangs
- Incompatibility with the named curve `NIST_P256` on this platform

### Workaround
Exclude PKSIG tests when running the test suite:
```bash
./test_libopenabe '--gtest_filter=-*PKSIG*'
```

### Next Steps
- Investigate OpenSSL 3.x EC cryptography on macOS
- Consider testing with OpenSSL 1.1.1 to isolate the issue
- Check OpenSSL 3.x provider configuration
- Add timeout protection to PKSIG test execution

## Issue 2: CryptoBox ABE Tests Fail with RELIC Error (Pre-existing)

### Affected Tests
- `libopenabe.CryptoBoxCPABEContext`
- `libopenabe.CryptoBoxCPABEContextMinusBase64Encoding`
- `libopenabe.CryptoBoxKPABEContext`
- `libopenabe.CryptoBoxKPABEContextMinusBase64Encoding`

### Error Message
```
FATAL ERROR in relic_ep_param.c:714
```

### Status
**⚠️ PRE-EXISTING** - This issue has existed for multiple commits and is unrelated to recent changes.

### Investigation
The error originates from RELIC's elliptic curve parameter initialization code. Line 714 in `relic_ep_param.c` likely contains a fatal assertion or error check that fails.

### Likely Cause
- RELIC library issue with elliptic curve parameter setup
- Incompatibility between RELIC and the current build configuration
- RELIC may be attempting to use unavailable or incompatible curve parameters

### Workaround
Exclude CryptoBox tests when running the test suite:
```bash
./test_libopenabe '--gtest_filter=-*CryptoBox*ABE*'
```

Or exclude both PKSIG and CryptoBox ABE:
```bash
./test_libopenabe '--gtest_filter=-*PKSIG*:*CryptoBox*ABE*'
```

### Next Steps
- Investigate RELIC configuration and curve parameter initialization
- Check if specific curve parameters are causing the fatal error
- Consider updating RELIC to a newer version
- Add better error handling around RELIC initialization

## Verification of Non-Regression

### OpenSSL 3.x Compatibility Fixes (Commit 1cceec5)

The OpenSSL 3.x compatibility fixes in commit `1cceec5` did **NOT** introduce these test failures:

**Evidence:**
1. Tested on commit `b9256bf` (before fix): PKSIG tests hang, 4 CryptoBox tests fail
2. Tested on commit `1cceec5` (after fix): PKSIG tests hang, 4 CryptoBox tests fail
3. **Identical behavior** → No regression introduced

### What Was Fixed
Commit `1cceec5` successfully fixed the segmentation fault that occurred when calling deprecated OpenSSL functions:
- `EVP_MD_CTX_create()` → `EVP_MD_CTX_new()`
- `EVP_MD_CTX_destroy()` → `EVP_MD_CTX_free()`

The fix allows 38 tests to pass that were previously seg faulting. The 8 failing tests are pre-existing issues unrelated to the OpenSSL API changes.

## Recommended Test Command

To run all passing tests (excluding known failures):

```bash
./test_libopenabe '--gtest_filter=-*PKSIG*:*CryptoBoxCPABEContext*:*CryptoBoxKPABEContext*'
```

Expected result: **38/38 tests pass** ✅

## Test Environment

- **Platform**: macOS 14.5.0 (Darwin 24.5.0)
- **Architecture**: Apple Silicon (ARM64) with x86_64 emulation
- **OpenSSL Version**: 3.6.0
- **RELIC Version**: 0.5.0
- **GMP Version**: 6.3.0

---

*Last Updated*: 2025-10-05
*Verified On*: Commits b9256bf, e99c062, 1cceec5
