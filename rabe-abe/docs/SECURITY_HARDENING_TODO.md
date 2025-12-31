# Security Hardening - Future Work

This document lists security improvements and hardening measures for the library.

## Current Status

The library implements cryptographic primitives correctly but lacks some
production-hardening features. This document prioritizes security improvements.

---

## Critical Priority

### 1. Constant-Time Operations

**Risk**: Timing side-channel attacks
**Complexity**: High
**Files**: All cryptographic operations

Ensure all secret-dependent operations are constant-time:

```rust
// BAD: Variable-time comparison
if secret_key.d == expected {
    // ...
}

// GOOD: Constant-time comparison
use subtle::ConstantTimeEq;
if secret_key.d.ct_eq(&expected).into() {
    // ...
}
```

**Areas requiring attention**:
- Scalar multiplication (already mostly constant-time in BLS12-381)
- Field inversions
- Conditional branches on secret data
- Array indexing with secret indices
- Early returns based on secret values

**Implementation**:
```rust
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

impl ConstantTimeEq for Fr {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.to_bytes().ct_eq(&other.to_bytes())
    }
}

/// Constant-time table lookup
fn ct_select<T: ConditionallySelectable + Copy>(table: &[T], index: usize) -> T {
    let mut result = table[0];
    for (i, item) in table.iter().enumerate() {
        let choice = Choice::from((i == index) as u8);
        result.conditional_assign(item, choice);
    }
    result
}
```

---

### 2. Zeroization of Secrets

**Risk**: Secret keys remaining in memory after use
**Complexity**: Low
**Files**: All key structures

Implement `Zeroize` and `ZeroizeOnDrop` for all secret types:

```rust
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Msk {
    #[zeroize(skip)]  // Not secret
    pub g: G1,
    pub alpha: Fr,     // Secret - will be zeroized
    pub a: Fr,         // Secret - will be zeroized
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretKey {
    pub d: G2,
    pub attributes: Vec<String>,
    pub d_attrs: HashMap<String, G1>,
}

// Manual zeroization for types that can't derive
impl Drop for TracingKey {
    fn drop(&mut self) {
        self.trace_sk.zeroize();
    }
}
```

**Types requiring zeroization**:
- `Msk` (all schemes)
- `SecretKey` (all schemes)
- `TracingKey`, `TraceRevokeTracingKey`
- `UserSigningKey`
- `SDMasterKey`, `BroadcastMasterKey`
- All PRE re-encryption keys
- Session keys in encryption

---

### 3. Secure Random Number Generation

**Risk**: Weak randomness leading to key compromise
**Complexity**: Low
**Files**: All functions using `RngCore`

Enforce cryptographically secure RNG:

```rust
use rand::{CryptoRng, RngCore};

// Require CryptoRng bound
pub fn setup<R: RngCore + CryptoRng>(rng: &mut R) -> (Mpk, Msk) {
    // ...
}

// Document RNG requirements
/// # Security
///
/// The `rng` parameter MUST be a cryptographically secure random number
/// generator (implementing `CryptoRng`). Using a weak RNG will result
/// in predictable keys and complete loss of security.
pub fn keygen<R: RngCore + CryptoRng>(/* ... */) { }

// Provide secure default
pub fn setup_secure() -> (Mpk, Msk) {
    let mut rng = rand::rngs::OsRng;
    setup(&mut rng)
}
```

---

### 4. Input Validation

**Risk**: Malformed inputs causing undefined behavior or panics
**Complexity**: Medium
**Files**: All public API functions

Validate all inputs before processing:

```rust
pub fn encrypt<R: RngCore>(
    rng: &mut R,
    mpk: &Mpk,
    policy: &PolicyNode,
    plaintext: &[u8],
) -> Result<FullCiphertext, AbeError> {
    // Validate policy
    policy.validate()?;

    // Check policy doesn't exceed limits
    if policy.attribute_count() > MAX_POLICY_ATTRIBUTES {
        return Err(AbeError::PolicyTooLarge);
    }

    // Validate plaintext size
    if plaintext.len() > MAX_PLAINTEXT_SIZE {
        return Err(AbeError::PlaintextTooLarge);
    }

    // Check for empty plaintext
    if plaintext.is_empty() {
        return Err(AbeError::EmptyPlaintext);
    }

    // ... rest of encryption
}

impl PolicyNode {
    pub fn validate(&self) -> Result<(), AbeError> {
        match self {
            PolicyNode::Attr(name) => {
                if name.is_empty() {
                    return Err(AbeError::InvalidPolicy("Empty attribute name".into()));
                }
                if name.len() > MAX_ATTRIBUTE_LENGTH {
                    return Err(AbeError::InvalidPolicy("Attribute name too long".into()));
                }
                Ok(())
            }
            PolicyNode::And(children) | PolicyNode::Or(children) => {
                if children.is_empty() {
                    return Err(AbeError::InvalidPolicy("Empty AND/OR node".into()));
                }
                for child in children {
                    child.validate()?;
                }
                Ok(())
            }
            PolicyNode::Threshold(k, children) => {
                if *k == 0 || *k > children.len() {
                    return Err(AbeError::InvalidPolicy("Invalid threshold".into()));
                }
                for child in children {
                    child.validate()?;
                }
                Ok(())
            }
        }
    }
}
```

---

### 5. Point Validation

**Risk**: Invalid curve points enabling attacks
**Complexity**: Medium
**Files**: Deserialization, all operations receiving external points

Validate all deserialized group elements:

```rust
impl G1 {
    /// Deserialize with full validation
    pub fn from_bytes_checked(bytes: &[u8]) -> Result<Self, CryptoError> {
        let point = Self::from_bytes(bytes)?;

        // Check point is on curve
        if !point.is_on_curve() {
            return Err(CryptoError::PointNotOnCurve);
        }

        // Check point is in correct subgroup (crucial for BLS12-381!)
        if !point.is_in_subgroup() {
            return Err(CryptoError::PointNotInSubgroup);
        }

        // Check point is not identity (if required)
        if point.is_identity() {
            return Err(CryptoError::IdentityPoint);
        }

        Ok(point)
    }
}

// Use in CBOR deserialization
fn deserialize_g1(bytes: &[u8]) -> Result<G1, AbeError> {
    G1::from_bytes_checked(bytes)
        .map_err(|e| AbeError::DeserializeError(format!("Invalid G1 point: {}", e)))
}
```

---

## High Priority

### 6. Error Message Sanitization

**Risk**: Information leakage through error messages
**Complexity**: Low
**Files**: All error returns

Ensure error messages don't leak sensitive information:

```rust
// BAD: Leaks which attribute failed
Err(AbeError::DecryptError(format!(
    "Missing key for attribute: {}", missing_attr
)))

// GOOD: Generic message
Err(AbeError::DecryptError(
    "Policy not satisfied by provided attributes".into()
))

// For debugging (only in debug builds)
#[cfg(debug_assertions)]
fn detailed_error(reason: &str) -> AbeError {
    AbeError::DecryptError(reason.into())
}

#[cfg(not(debug_assertions))]
fn detailed_error(_reason: &str) -> AbeError {
    AbeError::DecryptError("Decryption failed".into())
}
```

---

### 7. Bounds Checking and Integer Overflow

**Risk**: Memory corruption, panics, or logic errors
**Complexity**: Low
**Files**: All arithmetic operations

Use checked arithmetic for all size calculations:

```rust
// BAD: Can overflow
let size = num_users * key_size;

// GOOD: Checked arithmetic
let size = num_users
    .checked_mul(key_size)
    .ok_or(AbeError::Overflow)?;

// Use saturating/wrapping when appropriate
let index = offset.saturating_add(delta);

// Validate array indices
fn safe_index<T>(slice: &[T], index: usize) -> Result<&T, AbeError> {
    slice.get(index).ok_or(AbeError::IndexOutOfBounds)
}
```

---

### 8. Ciphertext Integrity

**Risk**: Ciphertext manipulation attacks
**Complexity**: Medium
**Files**: All encryption schemes

Add authentication to ciphertexts:

```rust
pub struct AuthenticatedCiphertext {
    /// The ABE ciphertext
    pub ct: Ciphertext,
    /// Authentication tag over the ciphertext
    pub tag: [u8; 16],
}

pub fn encrypt_authenticated<R: RngCore>(
    rng: &mut R,
    mpk: &Mpk,
    policy: &PolicyNode,
    plaintext: &[u8],
) -> Result<AuthenticatedCiphertext, AbeError> {
    let ct = encrypt(rng, mpk, policy, plaintext)?;

    // Compute MAC over serialized ciphertext
    let ct_bytes = ct.serialize();
    let tag = compute_mac(&session_key, &ct_bytes);

    Ok(AuthenticatedCiphertext { ct, tag })
}

pub fn decrypt_authenticated(
    mpk: &Mpk,
    sk: &SecretKey,
    ct: &AuthenticatedCiphertext,
) -> Result<Vec<u8>, AbeError> {
    // Verify tag before decryption
    let ct_bytes = ct.ct.serialize();

    // Recover session key first (partial decryption)
    let session_key = decrypt_kem(mpk, sk, &ct.ct)?;

    // Verify MAC
    let expected_tag = compute_mac(&session_key, &ct_bytes);
    if !constant_time_eq(&ct.tag, &expected_tag) {
        return Err(AbeError::AuthenticationFailed);
    }

    // Full decryption
    decrypt_dem(&session_key, &ct.ct.sym_ct)
}
```

---

### 9. Key Derivation Hardening

**Risk**: Weak key derivation enabling attacks
**Complexity**: Low
**Files**: All key derivation functions

Use proper KDFs instead of simple hashes:

```rust
use hkdf::Hkdf;
use sha2::Sha256;

/// Derive key material using HKDF
pub fn derive_key(
    ikm: &[u8],          // Input key material
    salt: &[u8],          // Optional salt
    info: &[u8],          // Context info
    output: &mut [u8],    // Output buffer
) {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    hk.expand(info, output).expect("HKDF expand failed");
}

// Use for session key derivation
fn derive_session_key(pairing_result: &Gt) -> [u8; 32] {
    let ikm = pairing_result.to_bytes();
    let mut session_key = [0u8; 32];
    derive_key(
        &ikm,
        b"rabe-abe-session-key-v1",  // Domain separation
        b"aes-256-gcm",               // Algorithm info
        &mut session_key,
    );
    session_key
}
```

---

### 10. Side-Channel Resistant Comparisons

**Risk**: Timing attacks on equality checks
**Complexity**: Low
**Files**: All comparison operations

Use constant-time comparisons for security-sensitive data:

```rust
use subtle::ConstantTimeEq;

/// Constant-time byte comparison
pub fn secure_compare(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;  // Length difference is usually not secret
    }
    a.ct_eq(b).into()
}

/// Constant-time MAC verification
pub fn verify_mac(expected: &[u8; 32], computed: &[u8; 32]) -> bool {
    expected.ct_eq(computed).into()
}
```

---

## Medium Priority

### 11. Memory Protection

**Risk**: Secrets readable from memory dumps
**Complexity**: High (platform-specific)
**Files**: Key storage

Lock sensitive memory pages:

```rust
#[cfg(unix)]
use libc::{mlock, munlock};

pub struct ProtectedKey {
    key: Box<[u8; 32]>,
}

impl ProtectedKey {
    pub fn new(key: [u8; 32]) -> Self {
        let boxed = Box::new(key);

        // Lock memory to prevent swapping
        #[cfg(unix)]
        unsafe {
            mlock(boxed.as_ptr() as *const _, 32);
        }

        ProtectedKey { key: boxed }
    }
}

impl Drop for ProtectedKey {
    fn drop(&mut self) {
        // Zeroize
        self.key.zeroize();

        // Unlock memory
        #[cfg(unix)]
        unsafe {
            munlock(self.key.as_ptr() as *const _, 32);
        }
    }
}
```

---

### 12. Audit Logging

**Risk**: Inability to detect attacks
**Complexity**: Low
**Files**: All key operations

Add security event logging:

```rust
use log::{info, warn, error};

pub fn keygen<R: RngCore>(/* ... */) -> Result<SecretKey, AbeError> {
    info!(
        target: "security",
        event = "keygen",
        user_id = %user_id,
        num_attributes = attributes.len(),
    );

    let result = keygen_inner(rng, mpk, msk, user_id, attributes);

    if result.is_err() {
        warn!(
            target: "security",
            event = "keygen_failed",
            user_id = %user_id,
        );
    }

    result
}

pub fn decrypt(/* ... */) -> Result<Vec<u8>, AbeError> {
    let result = decrypt_inner(mpk, sk, ct);

    match &result {
        Ok(_) => info!(target: "security", event = "decrypt_success"),
        Err(AbeError::PolicyNotSatisfied) => {
            warn!(target: "security", event = "decrypt_policy_failed");
        }
        Err(AbeError::RevocationError(_)) => {
            warn!(target: "security", event = "decrypt_revoked_user");
        }
        Err(_) => {
            error!(target: "security", event = "decrypt_error");
        }
    }

    result
}
```

---

### 13. Replay Protection

**Risk**: Ciphertext replay attacks
**Complexity**: Medium
**Files**: Encryption schemes

Add nonce/counter to prevent replay:

```rust
pub struct ReplayProtectedCiphertext {
    /// Unique message ID
    pub message_id: [u8; 16],
    /// Timestamp (for expiration)
    pub timestamp: u64,
    /// The ciphertext
    pub ct: FullCiphertext,
}

pub struct ReplayDetector {
    seen_ids: HashSet<[u8; 16]>,
    max_age_seconds: u64,
}

impl ReplayDetector {
    pub fn check(&mut self, ct: &ReplayProtectedCiphertext) -> Result<(), AbeError> {
        // Check for replay
        if self.seen_ids.contains(&ct.message_id) {
            return Err(AbeError::ReplayDetected);
        }

        // Check timestamp
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        if now > ct.timestamp + self.max_age_seconds {
            return Err(AbeError::MessageExpired);
        }

        // Record this message
        self.seen_ids.insert(ct.message_id);
        Ok(())
    }
}
```

---

### 14. Formal Verification Annotations

**Risk**: Subtle implementation bugs
**Complexity**: High
**Files**: Core cryptographic operations

Add annotations for formal verification tools:

```rust
// For Kani/CBMC verification
#[cfg(kani)]
mod verification {
    use super::*;

    #[kani::proof]
    fn verify_lsss_reconstruction() {
        let secret = Fr::any();
        let policy = PolicyNode::any_valid();
        let lsss = LsssMatrix::from_policy(&policy).unwrap();

        let shares = lsss.share_secret(&mut kani::any_rng(), secret);

        // For any satisfying assignment, reconstruction succeeds
        if let Some(assignment) = policy.any_satisfying_assignment() {
            let reconstructed = lsss.reconstruct(&shares, &assignment);
            kani::assert(reconstructed == secret);
        }
    }
}

// For HACL* / Vale verification (contracts)
/// # Safety Contract
/// - `key` must be exactly 32 bytes
/// - `nonce` must be exactly 12 bytes
/// - Output length equals input length plus 16 (tag)
#[requires(key.len() == 32)]
#[requires(nonce.len() == 12)]
#[ensures(result.len() == plaintext.len() + 16)]
pub fn aes_gcm_encrypt(key: &[u8], nonce: &[u8], plaintext: &[u8]) -> Vec<u8> {
    // ...
}
```

---

## Low Priority

### 15. Fuzzing Targets

**Risk**: Edge cases causing crashes or undefined behavior
**Complexity**: Low
**Files**: New `fuzz/` directory

Add fuzzing targets:

```rust
// fuzz/fuzz_targets/decrypt.rs
#![no_main]
use libfuzzer_sys::fuzz_target;
use rabe_abe::schemes::waters::*;

fuzz_target!(|data: &[u8]| {
    // Try to deserialize and decrypt
    if let Ok(ct) = Ciphertext::deserialize(data) {
        // Fixed test key
        let (mpk, msk) = setup_deterministic(SEED);
        let sk = keygen_deterministic(&mpk, &msk, &["test".into()], SEED);

        // Should not panic regardless of input
        let _ = decrypt(&mpk, &sk, &ct);
    }
});

// fuzz/fuzz_targets/policy_parse.rs
fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = parse_policy(s);
    }
});
```

---

### 16. Dependency Auditing

**Risk**: Vulnerabilities in dependencies
**Complexity**: Low
**Files**: CI configuration

Add automated dependency auditing:

```yaml
# .github/workflows/security.yml
name: Security Audit

on:
  schedule:
    - cron: '0 0 * * *'  # Daily
  push:
    paths:
      - '**/Cargo.toml'
      - '**/Cargo.lock'

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: rustsec/audit-check@v1
        with:
          token: ${{ secrets.GITHUB_TOKEN }}
```

---

## Security Testing Checklist

### Unit Tests
- [x] Constant-time comparison tests (in `security/constant_time.rs`)
- [x] Zeroization verification (`tests/crypto_security.rs`)
- [x] Input validation edge cases (`security/validation.rs`)
- [x] Point validation (invalid points) (`tests/crypto_security.rs`)
- [x] Integer overflow scenarios (`security/bounds.rs`)

### Integration Tests
- [x] Full encrypt/decrypt with malformed inputs (`tests/crypto_security.rs`)
- [ ] Replay attack simulation
- [x] Policy satisfaction edge cases (`tests/crypto_security.rs`)
- [x] Multi-authority key combination (`tests/dabe_roundtrip.rs`)

### Fuzzing Campaigns
- [x] Deserialization fuzzing (`fuzz/fuzz_targets/fuzz_cbor_decode.rs`)
- [x] Policy parsing fuzzing (`fuzz/fuzz_targets/fuzz_policy_parse.rs`)
- [x] LSSS reconstruction fuzzing (`fuzz/fuzz_targets/fuzz_lsss.rs`)

### Static Analysis
- [x] Clippy with all warnings (style warnings only, no security issues)
- [x] cargo-audit for dependencies (no vulnerabilities, 2 unmaintained warnings)
- [ ] cargo-deny for license/security

---

## Security Dependencies

| Crate | Purpose | Notes |
|-------|---------|-------|
| `zeroize` | Secret zeroization | Essential |
| `subtle` | Constant-time ops | Essential |
| `secrecy` | Secret wrapping | Recommended |
| `rand_core` | Secure RNG traits | Essential |
| `hkdf` | Key derivation | Recommended |
| `aes-gcm` | Authenticated encryption | Replace current AES |

---

## Compliance Considerations

### FIPS 140-3
- Approved algorithms (AES-256-GCM, SHA-256, etc.)
- Key management requirements
- Self-tests at startup

### Common Criteria
- Proper entropy sources
- Secure key storage
- Audit logging

### GDPR (for EU deployments)
- Key deletion capabilities (zeroization)
- Access logging
- Data minimization in error messages
