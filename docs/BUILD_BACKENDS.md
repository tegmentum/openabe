# OpenABE Build Backends

## Backend Directory Structure

OpenABE supports multiple cryptographic backends. Each backend has its own isolated build directory:

- `deps/root-mcl/` - MCL backend (BLS12-381 curve)
  - Bilinear pairings: MCL library
  - Elliptic curves: OpenSSL
  - Curve support: BLS12-381 only (compiled in)

- `deps/root-relic/` - RELIC backend (BN254 curve) 
  - Bilinear pairings: RELIC library (BP build)
  - Elliptic curves: OpenSSL
  - Curve support: BN254, BLS12-381

- `deps/root-openssl/` - Pure OpenSSL backend
  - Bilinear pairings: OpenSSL BP library
  - Elliptic curves: OpenSSL
  - Curve support: Depends on OpenSSL BP support

## Active Backend

The active backend is controlled by symlinking `deps/root/` to one of the above:

```bash
ln -sf root-mcl deps/root    # Use MCL backend
ln -sf root-relic deps/root  # Use RELIC backend
```

## Building a Backend

```bash
# Build MCL backend
ZML_LIB=with_mcl make -C deps

# Build RELIC backend  
unset ZML_LIB && make -C deps
```

## Verification

```bash
./verify-build.sh
```
