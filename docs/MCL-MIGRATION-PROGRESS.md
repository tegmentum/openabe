# MCL Migration Progress

## Status: Phase 2 Complete ✓ (Core Wrapper Layer Implemented)

### Completed Tasks

1. **MCL Library Integration** ✓
   - Downloaded MCL v1.61 from https://github.com/herumi/mcl
   - Extracted to `deps/mcl/mcl-1.61/`
   - Created Makefile for building MCL without GMP dependency
   - Successfully built `libmcl.a` (1.0MB)
   - Installed to `root/include/mcl/` and `root/lib/`

2. **Build System** ✓
   - Created `deps/mcl/Makefile` with:
     - `MCL_USE_GMP=0` (no external dependencies)
     - `MCL_USE_OPENSSL=0` (standalone)
     - Builds successfully on macOS ARM64

### MCL Build Output
```
lib/libmcl.a: 1,043,176 bytes
Headers installed: 35 files in root/include/mcl/
```

### Key Files Installed
- `root/lib/libmcl.a` - Core library
- `root/include/mcl/bn.hpp` - Main pairing API (BN254)
- `root/include/mcl/bn.h` - C API
- `root/include/mcl/bls12_381.hpp` - BLS12-381 support

2. **MCL Core Wrapper Implementation** ✓
   - Created `src/zml/zelement_mcl.c` (500+ lines)
   - Implemented all 47 wrapper functions:
     - 22 bignum operations (Fr field)
     - 11 G1 operations
     - 6 G2 operations
     - 8 GT operations
     - Pairing computation
   - Modified `root/include/openabe/zml/zelement.h`:
     - Added `BP_WITH_MCL` preprocessor blocks
     - Added MCL type definitions
     - Added MCL macros
   - **Compilation: SUCCESS** ✓

---

## Next Steps: Integration Phase

### Phase 3: C++ Layer Update (2-3 days estimated) - IN PROGRESS

**Priority 1: Create MCL wrapper header**
- File: `src/include/openabe/zml/zelement.h`
- Add `#ifdef BP_WITH_MCL` sections
- Define MCL-based types:
  ```c
  #if defined(BP_WITH_MCL)
  // Use MCL C++ objects via extern "C++" or C API
  typedef ... bignum_t;  // MCL Fr (scalar field)
  typedef ... g1_ptr;     // MCL G1
  typedef ... g2_ptr;     // MCL G2
  typedef ... gt_ptr;     // MCL GT (Fp12)
  typedef ... bp_group_t; // MCL curve context
  #endif
  ```

**Priority 2: Implement bignum operations**
- File: `src/zml/zelement.c`
- Implement `zml_bignum_*` functions using MCL's Fr class:
  - `zml_bignum_init()` → `Fr x;`
  - `zml_bignum_add()` → `Fr::add()`
  - `zml_bignum_mul()` → `Fr::mul()`
  - `zml_bignum_div()` → `Fr::div()`
  - `zml_bignum_mod_inv()` → `Fr::inv()`
  - Binary I/O using `Fr::serialize()` / `Fr::deserialize()`

**Priority 3: Implement G1/G2/GT operations**
- File: `src/zml/zelement.c`
- Functions to implement:
  - `g1_init()`, `g1_mul_op()`, `g1_add_op()`, `g1_map_op()`
  - `g2_init()`, `g2_mul_op()`
  - `gt_init()`, `gt_exp_op()`, `gt_mul_op()`, `gt_div_op()`
- Use MCL's `G1`, `G2`, `Fp12` classes

**Priority 4: Implement pairing**
- Functions:
  - `bp_map_op()` → `mcl::bn::pairing()`
  - `multi_bp_map_op()` → Loop + product of pairings

---

### Phase 3: C++ Layer Update (2-3 days)

**File: `src/zml/zelement_bp.cpp`**
- Update serialization converters:
  - `g1_convert_to_bytestring()` - Use MCL's `G1::serialize()`
  - `g1_convert_to_point()` - Use MCL's `G1::deserialize()`
  - Similar for G2, GT
- Handle potential endianness differences
- Create format conversion if needed for backward compatibility

**Classes to update:**
- `BPGroup` - Wrapper for MCL curve initialization
- `ZP` - Scalar field element (already abstract)
- `G1`, `G2`, `GT` - Curve point classes

---

### Phase 4: Testing (2-3 days)

1. **Unit tests**
   - Run `src/test_libopenabe` with MCL backend
   - Verify all ABE schemes work (CP-ABE, KP-ABE)
   - Test CCA schemes
   - Test PKE and PKSig

2. **Compatibility testing**
   - Ensure serialization is compatible
   - Test cross-scheme operations
   - Verify deterministic operations remain deterministic

3. **Performance benchmarking**
   - Compare MCL vs RELIC 0.5.0 performance
   - Measure pairing, scalar mult, serialization times

---

### Phase 5: Integration (1 day)

**Update main Makefile:**
```makefile
# Add MCL to dependencies
DEPS = gmp gtest openssl mcl

# Compiler flags
CXXFLAGS += -DBP_WITH_MCL
LDFLAGS += -L$(PREFIX)/lib -lmcl
```

**Build script updates:**
- `deps/Makefile` - Add mcl target
- `build.sh` - Build mcl before openabe

---

## Technical Decision Log

### Why MCL?

1. **Modern C++ API** - Operator overloading, RAII, exception handling
2. **No buffer overflow bugs** - STL containers, proper bounds checking
3. **Better performance** - Optimized assembly for x86-64, ARM, M1
4. **Active maintenance** - Regular updates from Cybozu
5. **No GMP dependency** - Standalone build possible
6. **Future-proof** - Supports BLS12-381 for higher security

### Why not fix RELIC 0.7.0?

After 7+ fix attempts, RELIC 0.7.0 proved unfixable due to:
- Fundamental architecture issues with AUTO allocation mode
- Circular dependencies between buffer sizes and field parameters
- Configuration-specific bugs not caught by RELIC's test suite
- Every fix created new incompatibilities

---

## File Locations

### MCL Files
- Source: `deps/mcl/mcl-1.61/`
- Library: `root/lib/libmcl.a`
- Headers: `root/include/mcl/*.hpp`

### OpenABE Files to Modify
- `src/include/openabe/zml/zelement.h` - Add MCL types
- `src/zml/zelement.c` - Core C wrappers
- `src/zml/zelement_bp.cpp` - C++ implementation
- `src/include/openabe/zml/zelement_bp.h` - C++ headers
- `src/Makefile` - Build integration
- `deps/Makefile` - Dependency build order

---

## Estimated Completion Time

- **Phase 1 (Setup)**: ✓ Complete
- **Phase 2 (Core wrappers)**: 3-4 days
- **Phase 3 (C++ layer)**: 2-3 days
- **Phase 4 (Testing)**: 2-3 days
- **Phase 5 (Integration)**: 1 day

**Total**: 8-11 days for full migration

---

## Current Blockers

None - ready to proceed with Phase 2 implementation.

---

## Notes

- MCL uses C++11, compatible with OpenABE's existing C++ codebase
- BN254 curve parameters match RELIC's BN_P254 settings
- MCL's serialization format may differ from RELIC - need compatibility layer
- Consider keeping RELIC 0.5.0 support as fallback during migration
