# EC Library Configuration Guide

## Overview

OpenABE now supports configurable elliptic curve (EC) backends, allowing you to choose between MCL's secp256k1 implementation and OpenSSL's NIST curve support at build time.

## Architecture

### Dual Backend Support

OpenABE has been refactored to support two independent library choices:

1. **Bilinear Pairing Library** (`ZML_LIB`):
   - `with_mcl` - MCL 3.04 for pairing operations (BN254)
   - `with_relic` - RELIC 0.7.0 for pairing operations (default)

2. **Elliptic Curve Library** (`EC_LIB`):
   - `with_mcl` - MCL's secp256k1 for EC operations
   - `with_openssl` - OpenSSL's NIST curves (P-256, P-384, P-521) for EC operations
   - Auto-detect (default) - Uses MCL for EC when `ZML_LIB=with_mcl`, otherwise OpenSSL

### Library Combinations

| ZML_LIB | EC_LIB | BP Operations | EC Operations | Use Case |
|---------|---------|---------------|---------------|----------|
| (default/relic) | (auto/openssl) | RELIC | OpenSSL NIST | Legacy build |
| with_mcl | (auto/with_mcl) | MCL BN254 | MCL secp256k1 | Pure MCL build |
| with_mcl | with_openssl | MCL BN254 | OpenSSL NIST | Hybrid MCL/OpenSSL |
| (relic) | with_mcl | RELIC | MCL secp256k1 | RELIC/MCL hybrid |

## Build Configuration

### Environment Variables

```bash
# Choose pairing library
export ZML_LIB=with_mcl       # Use MCL for pairings (recommended)
# or
export ZML_LIB=with_relic     # Use RELIC for pairings (legacy)

# Choose EC library (optional - will auto-detect if not set)
export EC_LIB=with_mcl        # Use MCL secp256k1
# or
export EC_LIB=with_openssl    # Use OpenSSL NIST curves
```

### Build Examples

#### 1. Pure MCL Build (Recommended)
Uses MCL for both pairings and EC operations:

```bash
export ZML_LIB=with_mcl
# EC_LIB will auto-detect and use MCL
make clean
cd deps && make
cd ../src && make
```

#### 2. MCL Pairing + OpenSSL EC (Hybrid)
Uses MCL for pairings but OpenSSL for EC/ECDSA:

```bash
export ZML_LIB=with_mcl
export EC_LIB=with_openssl
make clean
cd deps && make
cd ../src && make
```

#### 3. RELIC Build (Legacy)
Traditional build with RELIC:

```bash
# Don't set ZML_LIB (or set it to empty)
# EC_LIB will auto-detect and use OpenSSL
make clean
cd deps && make
cd ../src && make
```

## Implementation Files

### EC Implementation Files

- `src/zml/zelement_ec_mcl.cpp` - MCL secp256k1 implementation
- `src/zml/zelement_ec_openssl.cpp` - OpenSSL NIST curves implementation

The correct file is compiled based on compile-time flags:
- `-DEC_WITH_MCL` triggers compilation of `zelement_ec_mcl.cpp`
- `-DEC_WITH_OPENSSL` triggers compilation of `zelement_ec_openssl.cpp`

### Conditional Compilation

In `Makefile.common`, lines 185-205:

```makefile
# Auto-detect: use MCL for EC if using MCL for pairing, otherwise OpenSSL
ifeq ($(EC_LIB), with_mcl)
  CXXFLAGS += -DEC_WITH_MCL
  CCFLAGS += -DEC_WITH_MCL
else ifeq ($(EC_LIB), with_openssl)
  CXXFLAGS += -DEC_WITH_OPENSSL
  CCFLAGS += -DEC_WITH_OPENSSL
else
  ifeq ($(ZML_LIB), with_mcl)
    CXXFLAGS += -DEC_WITH_MCL
    CCFLAGS += -DEC_WITH_MCL
  else
    CXXFLAGS += -DEC_WITH_OPENSSL
    CCFLAGS += -DEC_WITH_OPENSSL
  endif
endif
```

## Supported Curves

### MCL EC Backend (`EC_WITH_MCL`)
- **secp256k1** - Bitcoin/Ethereum curve
- Optimized implementation with GLV endomorphism
- Full ECDSA support via `mcl/ecdsa.h`

### OpenSSL EC Backend (`EC_WITH_OPENSSL`)
- **NIST P-256** (secp256r1) - OpenABE default
- **NIST P-384** (secp384r1)
- **NIST P-521** (secp521r1)
- Industry-standard NIST curves
- FIPS 140-2 compliant

## PKSIG/ECDSA

OpenABE's PKSIG (Public Key Signature) scheme uses ECDSA. The implementation depends on the EC backend:

- **With `EC_WITH_MCL`**: Uses MCL's secp256k1 ECDSA (`mcl/ecdsa.hpp`)
- **With `EC_WITH_OPENSSL`**: Uses OpenSSL's ECDSA (EC_KEY) with NIST curves

**Note**: The current PKSIG implementation in `zcontextpksig.cpp` uses OpenSSL's EC_KEY directly, so it will continue to use OpenSSL regardless of the EC_LIB setting. Full MCL EC integration for PKSIG would require additional refactoring.

## API Compatibility

The EC abstraction layer in `zelement.h` provides a uniform C API regardless of backend:

```c
// EC group initialization
int ec_group_init(ec_group_t *group, uint8_t id);
void ec_get_order(ec_group_t group, bignum_t order);

// EC point operations
void ec_point_init(ec_group_t group, ec_point_t *e);
void ec_point_add(ec_group_t g, ec_point_t r, const ec_point_t x, const ec_point_t y);
void ec_point_mul(ec_group_t g, ec_point_t r, const ec_point_t x, const bignum_t y);
void ec_get_coordinates(ec_group_t group, bignum_t x, bignum_t y, const ec_point_t p);

// Serialization
size_t ec_point_elem_len(const ec_point_t g);
void ec_point_elem_in(ec_point_t g, uint8_t *in, size_t len);
void ec_point_elem_out(const ec_point_t g, uint8_t *out, size_t len);
```

## Testing

Test both backends:

```bash
# Test MCL backend
export ZML_LIB=with_mcl
export EC_LIB=with_mcl
make clean && cd deps && make && cd ../src && make test

# Test OpenSSL backend
export ZML_LIB=with_mcl
export EC_LIB=with_openssl
make clean && cd deps && make && cd ../src && make test
```

## Performance Considerations

### MCL secp256k1
- **Advantages**:
  - Highly optimized for secp256k1
  - GLV endomorphism acceleration
  - Pure C++ implementation
  - Single library dependency

- **Limitations**:
  - Only supports secp256k1
  - Not FIPS certified

### OpenSSL NIST Curves
- **Advantages**:
  - Supports multiple NIST curves
  - FIPS 140-2 compliance
  - Widely audited and tested
  - Hardware acceleration (AES-NI, etc.)

- **Limitations**:
  - Slightly slower than specialized implementations
  - Larger library size

## Migration Guide

### From Pure RELIC

```bash
# Old build
make

# New MCL build (recommended)
export ZML_LIB=with_mcl
make clean
cd deps && make
cd ../src && make
```

### Troubleshooting

**Issue**: Compilation errors about missing MCL headers

**Solution**: Ensure MCL is built and installed:
```bash
cd deps
env ZROOT=$(pwd)/.. make mcl
```

**Issue**: Linker errors about EC functions

**Solution**: Verify EC_LIB is set correctly and rebuild:
```bash
echo "EC_LIB=$EC_LIB"
echo "ZML_LIB=$ZML_LIB"
make clean
cd deps && make
cd ../src && make
```

## Future Work

Potential enhancements:

1. **Full MCL EC Integration for PKSIG**: Refactor `zcontextpksig.cpp` to use the EC abstraction layer instead of OpenSSL EC_KEY directly
2. **Additional Curve Support**: Add support for more curves in MCL backend (e.g., Ed25519, Curve25519)
3. **Runtime Selection**: Allow EC backend selection at runtime instead of compile-time
4. **Benchmark Suite**: Comparative performance testing between backends

## References

- MCL Documentation: https://github.com/herumi/mcl
- OpenSSL EC Documentation: https://www.openssl.org/docs/man3.0/man7/EVP_PKEY-EC.html
- secp256k1 Specification: https://www.secg.org/sec2-v2.pdf
- NIST Curves: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf
