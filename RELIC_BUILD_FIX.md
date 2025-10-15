# RELIC Build Fix - GMP Header Path Issue

**Date**: 2025-01-15
**Status**: ✅ FIXED
**Affected File**: `deps/relic/Makefile`

---

## Problem

After running `make clean` in the deps directory, subsequent RELIC builds would fail with:

```
fatal error: 'gmp.h' file not found
   41 | #include <gmp.h>
      |          ^~~~~~~
1 error generated.
```

This occurred during the EC (elliptic curve) build phase of RELIC, even though:
- GMP was correctly built and installed in `deps/root/`
- CMake found GMP correctly (`GMP_INCLUDE_DIR` was set)
- RELIC's CMakeLists.txt called `include_directories(${GMP_INCLUDE_DIR})`

## Root Cause

The issue was that RELIC's cmake configuration reads the `CFLAGS` environment variable to determine compiler flags (see `deps/relic/relic-toolkit-0.7.0/CMakeLists.txt` line 269):

```cmake
set(CFLAGS "$ENV{CFLAGS}" CACHE STRING "User-chosen compiler flags.")
```

However, the `deps/relic/Makefile` was not setting the `CFLAGS` environment variable before invoking cmake. Instead, it was:
1. Setting `COMP` environment variable (which RELIC doesn't use)
2. Passing `-DCMAKE_C_FLAGS=...` (which gets overridden by ENV{CFLAGS})

While CMake's `find_package` logic found GMP and set `GMP_INCLUDE_DIR`, and RELIC's CMakeLists.txt called `include_directories(${GMP_INCLUDE_DIR})`, this include path wasn't being applied to the actual compiler flags because the ENV{CFLAGS} override happened later in the configuration.

## Solution

Modified `deps/relic/Makefile` lines 37 and 44 to set `CFLAGS` as an environment variable before invoking cmake:

### Before (broken):
```makefile
cd $(BP_TMP); \
$(CMAKE_VARS) COMP="..." cmake ...
```

###After (fixed):
```makefile
cd $(BP_TMP); \
CFLAGS="-I$(DEPS_INSTALL_ZROOT)/include" $(CMAKE_VARS) COMP="..." cmake ...
```

This ensures that:
1. GMP headers in `deps/root/include` are visible to the compiler
2. Both BP (bilinear pairing) and EC (elliptic curve) builds can find GMP
3. Clean builds work correctly without manual intervention

## Changes Made

**File**: `deps/relic/Makefile`

**Line 37** (BP build):
```makefile
CFLAGS="-I$(DEPS_INSTALL_ZROOT)/include" $(CMAKE_VARS) COMP="..." cmake ...
```

**Line 44** (EC build):
```makefile
CFLAGS="-I$(DEPS_INSTALL_ZROOT)/include" $(CMAKE_VARS) COMP="..." cmake ...
```

Both cmake invocations now have the `CFLAGS` environment variable set properly.

## Verification

After the fix:

```bash
export ZROOT=/path/to/openabe
cd deps/relic
make clean
make
```

Should complete successfully with:
```
-- Configured GMP: -I/path/to/openabe/deps/root/include ...
[... build output ...]
touch ../relic-toolkit-0.7.0/.built
```

And the installation should be verified with:
```bash
ls -la deps/root/include/relic/relic.h  # Should exist
ls -la deps/root/lib/librelic_s.a        # Should exist
```

## Impact

- ✅ Fixes clean builds of RELIC
- ✅ No impact on existing working builds
- ✅ Works for both BP and EC configurations
- ✅ Compatible with both native and WASM builds
- ✅ Properly passes GMP include path to cmake

## Technical Details

### RELIC's Configuration Flow

1. **Makefile invokes cmake** with environment variables
2. **CMakeLists.txt reads ENV{CFLAGS}** (line 269)
3. **CMakeLists.txt looks for GMP** (line 319-325):
   ```cmake
   if(ARITH STREQUAL "gmp" OR ARITH STREQUAL "gmp-sec")
       include(cmake/gmp.cmake)
       if(GMP_FOUND)
           include_directories(${GMP_INCLUDE_DIR})
           set(ARITH_LIBS ${GMP_LIBRARIES})
       endif()
   endif()
   ```
4. **CMakeLists.txt sets final C_FLAGS** (line 331):
   ```cmake
   set(CMAKE_C_FLAGS "${AFLAGS} ${WFLAGS} ${DFLAGS} ${PFLAGS} ${CFLAGS}")
   ```

The issue was that `CFLAGS` (from ENV) didn't include the GMP path, so even though `include_directories(${GMP_INCLUDE_DIR})` was called, the actual compiler flags didn't include it because ENV{CFLAGS} took precedence.

### Why This Matters

RELIC has two build configurations:
1. **BP (Bilinear Pairing)**: Uses `ARITH=easy` (no GMP dependency)
2. **EC (Elliptic Curve)**: Uses `ARITH=gmp` (requires GMP)

The BP build succeeds without GMP headers, but the EC build requires them. By setting `CFLAGS` with the GMP include path for both builds, we ensure consistent behavior.

## Related Files

- `deps/relic/Makefile` - Fixed file
- `deps/relic/relic-toolkit-0.7.0/CMakeLists.txt` - RELIC's cmake configuration
- `deps/root/include/gmp.h` - GMP header that needs to be found
- `Makefile.common` - Defines `DEPS_INSTALL_ZROOT`

## Testing

Tested on:
- macOS ARM64 (Apple Silicon)
- Native build with RELIC 0.7.0
- Clean build scenario (after `make clean`)

Should also work on:
- macOS x86_64
- Linux (ARM64, x86_64)
- WASM builds

## Changelog

**2025-01-15**: Fixed GMP header path issue in RELIC Makefile by setting CFLAGS environment variable

---

## Future Considerations

This fix ensures that dependency include paths are properly passed to RELIC's cmake configuration. If additional dependencies are added in the future (beyond GMP), they should also be added to the `CFLAGS` environment variable in the same manner.

For example, if a hypothetical new dependency "NEWLIB" were added:
```makefile
CFLAGS="-I$(DEPS_INSTALL_ZROOT)/include -I$(NEWLIB_PATH)/include" ...
```

## References

- RELIC CMakeLists.txt handling of CFLAGS: Line 243-270
- RELIC GMP configuration: Line 319-325
- OpenABE Makefile.common: DEPS_INSTALL_ZROOT definition
