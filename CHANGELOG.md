# Changelog

All notable changes to OpenABE will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.1.0] - 2025-10-22

### Added
- **BLS12-381 curve support** with 128-bit security level
- **RELIC 0.7.0** cryptographic backend support
- Automated build system for RELIC with BLS12-381 fixes
- Comprehensive `.gitignore` for clean repository structure
- Parallel build support (`make -j8`) with race condition fixes
- Comprehensive documentation for bug fixes and improvements

### Fixed
- **Bug #18**: GT API compatibility for RELIC 0.7.0 with BLS12-381
  - Fixed multidimensional array type handling in GT operations
  - Unified GT function signatures between RELIC and MCL backends
  - Resolves compilation failures with RELIC 0.7.0 + BLS12-381

- **Bug #19**: Sliding window buffer size for BLS12-381
  - Fixed runtime crashes (`ERR_NO_BUFFER`) during encryption/decryption
  - Automated script corrects buffer sizing during RELIC build
  - Uses scalar order (255 bits) instead of field size (381 bits)

- **Bug #15**: CCA-security implementation
  - Fixed MCL backend PRNG usage for CCA-secured ciphertexts
  - Implemented canonical policy string hashing for consistent transforms
  - Resolves decryption failures with CCA-secured schemes

- **Bug #13/14**: LSSS coefficient calculation and curve recognition
  - Corrected MCL bignum byte count for LSSS coefficient calculation
  - Added BLS12-381 curve ID recognition
  - Fixed zero share handling in LSSS reconstruction

- **Build System**: Makefile race conditions
  - Fixed parallel build race conditions in RELIC Makefile
  - Added `.NOTPARALLEL` directive for proper dependency ordering
  - Corrected dependency chain to prevent CMake timing issues

### Changed
- Updated README with BLS12-381 support information
- Enhanced benchmarking section to document both BN-254 and BLS12-381 curves
- Improved documentation structure and organization

### Security
- **Enhanced security levels**: Now supports both 100-bit (BN-254) and 128-bit (BLS12-381) security
- **Fixed CCA-security**: Properly implemented chosen-ciphertext attack protection
- **Deterministic PRNG**: Ensures consistent CCA transform behavior

## [1.0.0] - Previous Release

### Added
- Initial OpenABE implementation
- CP-ABE (Ciphertext-Policy ABE) support
- KP-ABE (Key-Policy ABE) support
- RELIC 0.5.0 and 0.6.0 backend support
- MCL 3.04 backend support
- BN-254 curve support (100-bit security)
- WebAssembly (WASM) build support
- Comprehensive API documentation
- CLI utilities for encryption/decryption
- Benchmark infrastructure

---

## Detailed Changes by Category

### Cryptographic Improvements

#### BLS12-381 Support
- Full pairing-based operations on BLS12-381 curve
- 128-bit security level (vs 100-bit for BN-254)
- Compatible with both RELIC 0.7.0 and MCL 3.04 backends
- Automated build-time fixes for RELIC compatibility

#### CCA Security Fixes
- Deterministic PRNG for CCA transform generation
- Canonical policy string representation for consistent hashing
- Fixes apply to both RELIC and MCL backends
- Ensures decryption success for CCA-secured ciphertexts

### Build System Improvements

#### Automated Build Process
- **RELIC Bug #19 Fix**: Automated script (`apply_bls12_381_scalar_fix.sh`) runs during build
- **Parallel Builds**: Fixed Makefile race conditions, reliable `make -j8` builds
- **Dependency Management**: Corrected dependency chains in all Makefiles
- **Cross-Platform**: Continues to support macOS (Intel, Apple Silicon) and Linux

#### Repository Organization
- Comprehensive `.gitignore` for investigation notes and build artifacts
- Clean separation of source code, documentation, and test artifacts
- Preserved local investigation notes while keeping repository clean

### Documentation Improvements

#### Bug Fix Documentation
- 14+ markdown files documenting Bug #18 and Bug #19 fixes
- Getting started guides and quick reference documentation
- Technical deep-dives with root cause analysis
- Session summaries and completion reports

#### Updated README
- Added "Recent Improvements" section
- Documented BLS12-381 support and security levels
- Updated benchmarking section with curve information
- Clarified RELIC and MCL backend capabilities

#### Project Documentation
- `PROJECT-STATUS.md`: Current project status and capabilities
- `DOCUMENTATION-CLEANUP-PLAN.md`: Repository organization guidelines
- `SESSION-FINAL-SUMMARY.md`: Complete work session summary
- `CHANGELOG.md`: This file

### Code Quality

#### Bug Fixes
- **5 major bugs** fixed (Bug #13 through #19)
- **20+ files** modified with improvements
- **Comprehensive testing** for all fixes
- **Production-ready** code quality

#### Compatibility
- **RELIC Versions**: 0.5.0, 0.6.0, 0.7.0
- **MCL Version**: 3.04
- **Curves**: BN-254, BLS12-381
- **Platforms**: macOS, Linux, WebAssembly
- **Build Tools**: make, cmake, clang, gcc

---

## Migration Guide

### Upgrading from 1.0.0 to 1.1.0

**No Breaking Changes**: Version 1.1.0 is fully backward compatible with 1.0.0.

**New Capabilities**:
1. **BLS12-381 Support**: Rebuild with RELIC 0.7.0 or MCL 3.04 to enable 128-bit security
2. **CCA Security**: Existing code automatically benefits from CCA security fixes
3. **Build Performance**: Parallel builds now work reliably (`make -j8`)

**Recommended Actions**:
1. Rebuild dependencies: `make -C deps/relic clean && make -C deps/relic -j8`
2. Rebuild OpenABE: `make -C src -j8 && make -C cli -j8`
3. Test with BLS12-381: See `GETTING-STARTED-BUG-18-19.md` for testing instructions

**No API Changes**: All existing code continues to work without modification.

---

## Known Issues

None currently reported for version 1.1.0.

---

## Contributors

- Zachary Whitley <zachary.whitley@tegmentum.ai>
- Original OpenABE development team

---

## Links

- [Repository](https://github.com/tegmentum/openabe)
- [Bug #18 Documentation](BUG-18-19-RELIC-BLS12-381-FIXES.md)
- [Bug #19 Documentation](BUG-18-19-RELIC-BLS12-381-FIXES.md)
- [Project Status](PROJECT-STATUS.md)
- [API Documentation](docs/libopenabe-v1.0.0-api-doc.pdf)
- [CLI Documentation](docs/libopenabe-v1.0.0-cli-doc.pdf)
- [Design Documentation](docs/libopenabe-v1.0.0-design-doc.pdf)

---

## Commit Summary

**Version 1.1.0 Commits**:
```
6d22feb docs(readme): update with BLS12-381 support and recent improvements
2647f9d chore: add comprehensive .gitignore for investigation notes and build artifacts
f3ffe3e fix(relic): correct sliding window buffer size and fix build race conditions
b4b6d47 fix(relic): resolve BLS12-381 GT API compatibility for RELIC 0.7.0
9254763 fix(cca): fix MCL backend PRNG usage for CCA security
7d3e984 fix: use canonical policy strings in CCA transform to ensure consistent hashing
056e802 fix: correct MCL bignum byte count for LSSS coefficient calculation
169460f fix: resolve LSSS zero shares and curve ID recognition for BLS12-381
```

---

**Last Updated**: October 22, 2025
