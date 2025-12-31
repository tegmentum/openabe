# Traitor Tracing - Future Implementation

This document lists traitor tracing schemes that could be added to the library.

## Currently Implemented

- **White-box tracing**: Waters, AC17, DABE with identity commitments
- **Black-box tracing**: Binary search, adaptive trace (`black_box.rs`)
- **Fingerprinting**: Boneh-Shaw codes, Tardos codes (`fingerprint_codes.rs`)
- **Trace-and-Revoke ABE**: Waters, AC17, DABE with embedded revocation
- **Accountable ABE**: Non-repudiable evidence with user/authority signatures
- **Broadcast Encryption**: Complete Subtree (NNL) method (`broadcast.rs`)
- **Dynamic Tracing**: Sequential elimination, adaptive phases (`dynamic.rs`)
- **Group Testing**: Binary splitting, Hwang's algorithm, disjunct matrices (`group_testing.rs`)
- **KP-ABE Tracing**: GPSW traceable with identity commitments (`gpsw_traceable.rs`) ✓
- **Threshold Authority Tracing**: t-of-n threshold using Shamir secret sharing (`threshold_trace.rs`) ✓
- **Hidden Policies ABE**: CP-ABE with hidden access policies (`hidden_policy.rs`) ✓

---

## Unimplemented Schemes

### 1. Subset Difference (SD) Method

**Priority**: High
**Complexity**: Medium
**File**: `src/tracing/broadcast.rs` (extend existing)

More efficient broadcast revocation than Complete Subtree. Instead of covering non-revoked users with subtrees, SD uses differences between subtrees.

**Complexity**: O(2r-1) ciphertext size vs O(r log n) for Complete Subtree, where r = revoked users.

**References**:
- Naor, Naor, Lotspiech. "Revocation and Tracing Schemes for Stateless Receivers" (2001)

**Implementation Notes**:
```rust
pub struct SubsetDifferenceParams {
    pub num_users: usize,
    pub height: usize,
}

pub struct SDCover {
    /// Each element is (ancestor, descendant) representing S_{ancestor} \ S_{descendant}
    pub differences: Vec<(NodeId, NodeId)>,
}

pub fn compute_sd_cover(params: &SubsetDifferenceParams, revoked: &[usize]) -> SDCover;
```

---

### 2. Public Traceability

**Priority**: Medium
**Complexity**: Medium
**File**: `src/schemes/waters_public_trace.rs` (new)

Allows anyone to trace a leaked key without the tracing secret key. Uses publicly verifiable identity commitments.

**Key Idea**: Instead of `H(user_id)^τ` where τ is secret, use a structure where the commitment can be verified against a public verification key without revealing τ.

**References**:
- Liu, Au, Susilo. "Self-Generated-Certificate Public Key Encryption Without Pairing" (2007)
- Boneh, Naor. "Traitor Tracing with Constant Size Ciphertext" (2008)

**Implementation Notes**:
```rust
pub struct PublicTraceableMpk {
    pub base: Mpk,
    pub trace_vk: G2,           // Public verification key
    pub commitment_base: G1,     // For public verification
}

/// Anyone can call this - no tracing key needed
pub fn public_trace(
    mpk: &PublicTraceableMpk,
    leaked_key: &PublicTraceableSecretKey,
    known_users: &[UserId],
) -> TraceResult;
```

---

### 3. Short Ciphertext Traitor Tracing (BSW06)

**Priority**: Medium
**Complexity**: High
**File**: `src/schemes/short_ciphertext_tt.rs` (new)

Achieves constant-size ciphertexts regardless of the number of users or revocation set size. Based on bilinear groups and algebraic techniques.

**References**:
- Boneh, Sahai, Waters. "Fully Collusion Resistant Traitor Tracing with Short Ciphertexts and Private Keys" (2006)

**Implementation Notes**:
- Ciphertext size: O(1) group elements
- Secret key size: O(√n) group elements
- Tracing time: O(n) pairings
- Uses algebraic structure to encode user identities

---

### 4. Lattice-Based Traitor Tracing

**Priority**: Low (post-quantum)
**Complexity**: High
**File**: `src/schemes/lattice_tt.rs` (new)

Post-quantum secure traitor tracing based on Learning With Errors (LWE) or Ring-LWE.

**References**:
- Goyal, Koppula, Waters. "Lockable Obfuscation" (2017)
- Boneh, Zhandry. "Multiparty Key Exchange, Efficient Traitor Tracing, and More from Indistinguishability Obfuscation" (2014)

**Implementation Notes**:
- Requires lattice crypto library (e.g., lattice-rs)
- Significantly larger keys/ciphertexts than pairing-based
- Different security assumptions

---

### 5. ~~KP-ABE Traitor Tracing~~ ✅ IMPLEMENTED

See `src/schemes/gpsw_traceable.rs`

---

### 6. Asymmetric Fingerprinting

**Priority**: Low
**Complexity**: Medium
**File**: `src/tracing/asymmetric_fingerprint.rs` (new)

Buyer-seller protocol where the seller cannot frame an honest buyer. Uses commitment schemes and zero-knowledge proofs.

**Key Properties**:
- Seller cannot create valid fingerprint without buyer's cooperation
- Buyer cannot deny if fingerprint is found in leaked content
- Requires interactive protocol or trusted third party

**References**:
- Pfitzmann, Schunter. "Asymmetric Fingerprinting" (1996)
- Boneh, Shaw. "Collusion-Secure Fingerprinting for Digital Data" (1998) - Section 5

**Implementation Notes**:
```rust
pub struct FingerprintCommitment {
    pub commitment: G1,
    pub blinding: Fr,
}

pub struct AsymmetricFingerprintProtocol {
    /// Phase 1: Buyer commits to random bits
    pub fn buyer_commit<R: RngCore>(rng: &mut R, code_length: usize) -> (Vec<FingerprintCommitment>, Vec<Fr>);

    /// Phase 2: Seller generates fingerprinted content
    pub fn seller_generate(commitments: &[FingerprintCommitment], content: &[u8]) -> FingerprintedContent;

    /// Phase 3: Buyer reveals to get final content
    pub fn buyer_reveal(content: &FingerprintedContent, openings: &[Fr]) -> Vec<u8>;
}
```

---

### 7. Pirate Evolution Model

**Priority**: Low
**Complexity**: High
**File**: `src/tracing/pirate_evolution.rs` (new)

Handles "self-protecting pirates" that adapt their decoder based on observed tracing queries. The decoder may refuse to decrypt if it detects a tracing attempt.

**Key Challenge**: Tracing queries must be indistinguishable from legitimate content.

**References**:
- Kiayias, Yung. "Self-Protecting Pirates and Black-Box Traitor Tracing" (2001)
- Kiayias, Yung. "Traitor Tracing with Constant Transmission Rate" (2002)

**Implementation Notes**:
```rust
pub trait EvolvingPirateDecoder {
    /// Decoder may update internal state based on each query
    fn decode_and_evolve(&mut self, ciphertext: &[u8]) -> Option<Vec<u8>>;

    /// Decoder may detect tracing patterns
    fn is_suspicious(&self, ciphertext: &[u8]) -> bool;
}

pub struct StealthyTracingConfig {
    /// Mix tracing queries with legitimate-looking content
    pub decoy_ratio: f64,
    /// Randomize query timing
    pub timing_variance: Duration,
}
```

---

### 8. ~~Threshold Authority Tracing~~ ✅ IMPLEMENTED

See `src/schemes/threshold_trace.rs`

---

### 9. Revocable Storage

**Priority**: Low
**Complexity**: High
**File**: `src/schemes/revocable_storage.rs` (new)

Retroactively revoke access to old ciphertexts. Even if a user had valid keys when content was encrypted, revocation removes their access.

**Approaches**:
1. **Time-based key updates**: Keys expire, require periodic refresh
2. **Proxy re-encryption**: Re-encrypt old ciphertexts with new keys
3. **Server-aided decryption**: Decryption requires server check

**References**:
- Boldyreva, Goyal, Kumar. "Identity-based Encryption with Efficient Revocation" (2008)
- Sahai, Seyalioglu, Waters. "Dynamic Credentials and Ciphertext Delegation for ABE" (2012)

---

## Implementation Priority

| Priority | Schemes |
|----------|---------|
| High | Subset Difference |
| Medium | Public Traceability, ~~KP-ABE Tracing~~ ✅, ~~Threshold Authority~~ ✅ |
| Low | Short Ciphertext TT, Lattice-based, Asymmetric Fingerprinting, Pirate Evolution, Revocable Storage |

## Dependencies

Some schemes require additional crates:
- **Lattice-based**: Would need `lattice` or similar post-quantum crypto crate
- **Threshold**: ✅ Implemented using native Shamir secret sharing with Lagrange interpolation
- **ZK proofs**: Could use `bellman` or `ark-snark` for asymmetric fingerprinting

## Testing Strategy

Each new scheme should include:
1. Unit tests for core functionality
2. Integration tests with existing ABE schemes
3. Property-based tests for security properties (collusion resistance, etc.)
4. Performance benchmarks for comparison
