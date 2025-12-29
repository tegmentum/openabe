# Performance Improvements - Future Work

This document lists performance optimizations that could be implemented in the library.

## Current Status

The library prioritizes correctness and clarity over performance. Many optimizations
are possible without changing the API.

---

## Completed

The following optimizations have been implemented:

### ✅ Multi-Scalar Multiplication (MSM)
- **Status**: Implemented in `rabe-bls12381` using arkworks `VariableBaseMSM`
- **Functions**: `G1::multi_scalar_mul()`, `G2::multi_scalar_mul()`
- **Impact**: 2-4x speedup for computing sums of scaled points
- **Used in**: Waters decrypt for ciphertext component sum

### ✅ Multi-Pairing
- **Status**: Implemented in `rabe-bls12381`
- **Function**: `multi_pairing()` - shares final exponentiation
- **Impact**: 2-3x speedup for 5+ pairings
- **Used in**: Waters, AC17, GPSW decryption

### ✅ Lazy Policy Evaluation
- **Status**: Implemented in `lsss.rs`
- **Function**: `PolicyNode::can_satisfy()`, `can_satisfy_attrs()`
- **Impact**: O(n) quick check before expensive LSSS computation
- **Used in**: All decrypt functions

### ✅ Parallel Processing (Rayon)
- **Status**: Implemented with `parallel` feature flag
- **Impact**: Near-linear speedup with cores for multi-attribute operations
- **Used in**: keygen, encrypt, decrypt for all schemes

### ✅ Attribute Hash Caching
- **Status**: Implemented in `utils.rs`
- **Function**: `hash_to_g1_keyed_cached()`
- **Impact**: 10-20% speedup for repeated attributes
- **Cache**: LRU cache with 1000 entry capacity

### ✅ LSSS Policy Caching
- **Status**: Implemented in `lsss.rs`
- **Function**: `get_or_compute_lsss()`
- **Impact**: Significant for repeated policies
- **Cache**: LRU cache with 256 entry capacity

### ✅ Montgomery Batch Inversion
- **Status**: Implemented in `lsss.rs`
- **Function**: `batch_inverse()`
- **Impact**: 10-30% speedup for LSSS reconstruction
- **Note**: Reduces n inversions to 1 inversion + 3n multiplications

---

## High Priority (Remaining)

### 1. Precomputed Pairing Tables

**Impact**: 2-5x speedup for repeated pairings
**Complexity**: Medium
**Files**: `rabe-bls12381/src/lib.rs`, all scheme files

Precompute fixed-base pairing tables for generators and public key elements.

```rust
pub struct PrecomputedMpk {
    pub base: Mpk,
    /// Precomputed pairing table for e(g, h)
    pub pairing_table: PairingTable,
    /// Precomputed multiples of g for faster scalar multiplication
    pub g_table: G1Table,
}

impl PrecomputedMpk {
    pub fn from_mpk(mpk: &Mpk) -> Self {
        // Build tables during setup (one-time cost)
    }
}
```

---

## Medium Priority

### 2. Optimized Serialization

**Impact**: 20-40% reduction in serialization time
**Complexity**: Medium
**Files**: `src/cbor.rs`

Use more efficient serialization:

```rust
// Current: Debug format for G1/G2/Gt (very slow)
format!("{:?}", point)

// Optimized: Direct byte serialization
impl Serialize for G1 {
    fn serialize(&self) -> Vec<u8> {
        self.to_compressed_bytes()  // 48 bytes for G1
    }
}

// Even better: Zero-copy with serde_bytes
#[derive(Serialize, Deserialize)]
struct CompactCiphertext {
    #[serde(with = "serde_bytes")]
    c: [u8; 48],
    #[serde(with = "serde_bytes")]
    components: Vec<u8>,  // Pre-serialized
}
```

---

### 3. Streaming Encryption for Large Messages

**Impact**: Reduced memory for large plaintexts
**Complexity**: Medium
**Files**: All scheme encrypt functions

Stream-based encryption for large messages:

```rust
pub struct StreamingEncryptor {
    aes_key: [u8; 32],
    nonce: [u8; 12],
    counter: u64,
}

impl StreamingEncryptor {
    pub fn encrypt_chunk(&mut self, chunk: &[u8]) -> Vec<u8> {
        // Encrypt chunk with current counter
        let ct = aes_ctr_encrypt(&self.aes_key, &self.nonce, self.counter, chunk);
        self.counter += chunk.len() as u64;
        ct
    }
}

pub fn encrypt_streaming<R: RngCore, W: Write>(
    rng: &mut R,
    mpk: &Mpk,
    policy: &PolicyNode,
    reader: &mut impl Read,
    writer: &mut W,
) -> Result<(), AbeError>;
```

---

## Low Priority

### 4. SIMD Acceleration

**Impact**: 2-4x for field operations (platform-dependent)
**Complexity**: High
**Files**: `rabe-bls12381/`

Use SIMD instructions for parallel field arithmetic:

```rust
#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::*;

// Parallel limb operations using AVX2
#[target_feature(enable = "avx2")]
unsafe fn add_limbs_simd(a: &[u64; 6], b: &[u64; 6]) -> [u64; 6] {
    // Use _mm256 instructions
}
```

---

### 5. Endomorphism Acceleration for BLS12-381

**Impact**: 20-30% speedup for scalar multiplication
**Complexity**: High
**Files**: `rabe-bls12381/`

Use GLV/GLS endomorphisms for faster scalar multiplication:

```rust
/// Scalar multiplication using GLV decomposition
/// k * P = k1 * P + k2 * φ(P) where φ is the endomorphism
pub fn scalar_mul_glv(k: &Fr, p: &G1) -> G1 {
    let (k1, k2) = decompose_scalar(k);
    let phi_p = apply_endomorphism(p);
    multi_scalar_mul(&[*p, phi_p], &[k1, k2])
}
```

---

### 6. Memory Pool for Group Elements

**Impact**: Reduced allocation overhead
**Complexity**: Medium
**Files**: All scheme files

Pool allocator for temporary group elements:

```rust
thread_local! {
    static G1_POOL: RefCell<Vec<G1>> = RefCell::new(Vec::with_capacity(100));
}

pub fn with_temp_g1<F, R>(f: F) -> R
where
    F: FnOnce(&mut G1) -> R
{
    let mut elem = G1_POOL.with(|pool| pool.borrow_mut().pop()).unwrap_or_default();
    let result = f(&mut elem);
    G1_POOL.with(|pool| pool.borrow_mut().push(elem));
    result
}
```

---

### 7. Compressed Ciphertexts

**Impact**: 50% size reduction
**Complexity**: Low
**Files**: CBOR serialization

Use point compression for serialization:

```rust
// G1: 96 bytes uncompressed -> 48 bytes compressed
// G2: 192 bytes uncompressed -> 96 bytes compressed

pub fn serialize_compressed(ct: &Ciphertext) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend(ct.c.to_compressed());
    for comp in &ct.components {
        out.extend(comp.c1.to_compressed());
        out.extend(comp.c2.to_compressed());
    }
    out
}
```

---

### 8. Async/Concurrent Multi-Authority

**Impact**: Significant for DABE with many authorities
**Complexity**: Medium
**Files**: `schemes/dabe*.rs`

Concurrent key requests to multiple authorities:

```rust
use tokio::join;

pub async fn fetch_keys_concurrent(
    authorities: &[AuthorityClient],
    user_id: &UserId,
    attributes: &HashMap<String, Vec<String>>,
) -> Result<UserSecretKey, AbeError> {
    let futures: Vec<_> = authorities
        .iter()
        .map(|auth| auth.request_key(user_id, &attributes[&auth.id]))
        .collect();

    let results = futures::future::join_all(futures).await;
    aggregate_keys(results)
}
```

---

## Benchmarking Infrastructure

### Current Gaps

1. No systematic benchmarks for different policy sizes
2. No comparison with other ABE libraries
3. No profiling data for hotspots

### Proposed Benchmark Suite

```rust
// benches/abe_benchmarks.rs
use criterion::{criterion_group, criterion_main, Criterion, BenchmarkId};

fn bench_encrypt(c: &mut Criterion) {
    let mut group = c.benchmark_group("encrypt");

    for num_attrs in [1, 5, 10, 20, 50] {
        group.bench_with_input(
            BenchmarkId::new("waters", num_attrs),
            &num_attrs,
            |b, &n| b.iter(|| encrypt_with_n_attrs(n)),
        );
    }
    group.finish();
}

fn bench_decrypt(c: &mut Criterion) { /* ... */ }
fn bench_keygen(c: &mut Criterion) { /* ... */ }
fn bench_pairing(c: &mut Criterion) { /* ... */ }

criterion_group!(benches, bench_encrypt, bench_decrypt, bench_keygen, bench_pairing);
criterion_main!(benches);
```

---

## Performance Targets

| Operation | Current (est.) | Target | Notes |
|-----------|---------------|--------|-------|
| Setup | ~10ms | ~5ms | Precomputation |
| Keygen (10 attrs) | ~50ms | ~20ms | Multi-exp |
| Encrypt (10 attrs) | ~100ms | ~30ms | Parallel + multi-exp |
| Decrypt (10 attrs) | ~150ms | ~50ms | Batch pairing |
| Pairing | ~2ms | ~1ms | Assembly optimizations |

---

## Dependencies to Consider

| Crate | Purpose | Notes |
|-------|---------|-------|
| `rayon` | Parallel iteration | Easy parallelism |
| `criterion` | Benchmarking | Already common |
| `lru` | Caching | Small, no-std compatible |
| `parking_lot` | Better mutexes | Faster than std |
| `crossbeam` | Concurrent data structures | For parallel ops |
