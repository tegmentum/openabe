# Key Revocation Schemes - Complete Implementation

This document lists all key revocation schemes implemented in the library.

## All Schemes Implemented

| Scheme | Location | Description |
|--------|----------|-------------|
| Revocation Lists | `src/tracing/revocation.rs` | Basic blacklist with `RevocationList`, `RevocationEntry` |
| Trace-and-Revoke ABE | `src/schemes/*_trace_revoke.rs` | Revocation embedded in ciphertext (Waters, AC17, DABE) |
| Complete Subtree (CS) | `src/tracing/broadcast.rs` | Tree-based broadcast revocation |
| Subset Difference (SD) | `src/tracing/subset_difference.rs` | More efficient tree-based revocation ✓ |
| Time-Based (BGM) | `src/schemes/time_revocation.rs` | Keys have validity periods, require periodic updates ✓ |
| Accumulator-Based | `src/tracing/accumulator.rs` | Bilinear accumulators for non-membership proofs ✓ |
| Direct Revocation | `src/schemes/direct_revocation.rs` | Revocation via user identities, checked at decrypt time ✓ |
| Mediator-Based (SEM) | `src/schemes/mediated_abe.rs` | Online mediator required for decryption, instant revocation ✓ |
| Server-Aided (Split Keys) | `src/schemes/split_key_abe.rs` | Cacheable server shares with epoch rotation ✓ |
| Attribute Expiration | `src/schemes/attribute_expiration.rs` | Attributes with validity periods, auto-expire ✓ |
| Revocable HIBE | `src/schemes/revocable_hibe.rs` | Hierarchical IBE with tree-based revocation ✓ |
| Binary Tree Encryption | `src/schemes/binary_tree_encryption.rs` | Forward-secure encryption with evolving keys ✓ |

---

## Unimplemented Schemes

### 1. Time-Based Revocation (BGM) ✅ IMPLEMENTED

**Priority**: High
**Complexity**: Medium
**File**: `src/schemes/time_revocation.rs`

Keys have validity periods and require periodic updates from the authority. Users who don't receive updates are effectively revoked.

**Key Properties**:
- No explicit revocation list needed
- Users must periodically contact authority
- Revocation takes effect at next time period

**References**:
- Boldyreva, Goyal, Kumar. "Identity-based Encryption with Efficient Revocation" (2008)

**Implementation Notes**:
```rust
pub struct TimePeriod(pub u64);

pub struct TimeBasedMpk {
    pub base: Mpk,
    pub time_base: G2,  // For time-based key derivation
}

pub struct TimeBasedSecretKey {
    pub base: SecretKey,
    pub valid_from: TimePeriod,
    pub valid_until: TimePeriod,
    pub update_key: G1,  // For deriving next period's key
}

/// Authority generates update for non-revoked users
pub fn generate_key_update(
    msk: &TimeBasedMsk,
    user_id: &UserId,
    new_period: TimePeriod,
) -> KeyUpdate;

/// User applies update to extend key validity
pub fn apply_key_update(
    sk: &mut TimeBasedSecretKey,
    update: &KeyUpdate,
) -> Result<(), AbeError>;

/// Encrypt for a specific time period
pub fn encrypt_for_period<R: RngCore>(
    rng: &mut R,
    mpk: &TimeBasedMpk,
    policy: &PolicyNode,
    period: TimePeriod,
    plaintext: &[u8],
) -> Result<TimeBasedCiphertext, AbeError>;
```

---

### 2. Mediator-Based Revocation (SEM) ✅ IMPLEMENTED

**Priority**: Medium
**Complexity**: Medium
**File**: `src/schemes/mediated_abe.rs`

Decryption requires assistance from an online Security Mediator (SEM). The mediator checks revocation status before providing its decryption share.

**Key Properties**:
- Instant revocation (mediator refuses to help)
- Requires online mediator for every decryption
- Split-key architecture

**References**:
- Boneh, Ding, Tsudik. "Identity-based Encryption with Security Mediators" (2003)
- Libert, Quisquater. "Efficient Revocation and Threshold Pairing Based Cryptosystems" (2003)

**Implementation Notes**:
```rust
pub struct MediatorPublicKey {
    pub mediator_id: String,
    pub pk: G2,
}

pub struct UserPartialKey {
    pub base: SecretKey,
    pub user_share: G1,  // User's portion of split key
}

pub struct MediatorShare {
    pub mediator_share: G1,  // Mediator's portion
    pub proof: MediatorProof,  // Proof of correct computation
}

/// Mediator checks revocation and provides share
pub fn mediator_assist(
    mediator_sk: &MediatorSecretKey,
    ct: &MediatedCiphertext,
    user_id: &UserId,
    revocation_list: &RevocationList,
) -> Result<MediatorShare, RevocationError>;

/// User combines shares to decrypt
pub fn decrypt_with_mediator(
    user_key: &UserPartialKey,
    mediator_share: &MediatorShare,
    ct: &MediatedCiphertext,
) -> Result<Vec<u8>, AbeError>;
```

---

### 3. Accumulator-Based Revocation ✅ IMPLEMENTED

**Priority**: Medium
**Complexity**: High
**File**: `src/tracing/accumulator.rs`

Uses cryptographic accumulators to efficiently prove membership or non-membership. Non-revoked users can prove they're not in the revocation set.

**Types**:
- RSA accumulators (based on strong RSA assumption)
- Bilinear accumulators (based on q-SDH assumption)

**Key Properties**:
- Constant-size revocation witness
- Efficient updates when users are revoked
- No need to enumerate all revoked users

**References**:
- Camenisch, Lysyanskaya. "Dynamic Accumulators and Application to Efficient Revocation" (2002)
- Nguyen. "Accumulators from Bilinear Pairings" (2005)

**Implementation Notes**:
```rust
/// Bilinear accumulator value
pub struct Accumulator {
    pub value: G1,
    pub aux: G2,  // For efficient witness updates
}

/// Witness proving non-membership (non-revocation)
pub struct NonMembershipWitness {
    pub d: G1,
    pub a: Fr,
    pub b: Fr,
}

/// Add user to revocation set (accumulator)
pub fn accumulate(
    acc: &mut Accumulator,
    revoked_id: &UserId,
    trapdoor: &AccumulatorTrapdoor,
) -> WitnessUpdate;

/// User updates their witness after revocation event
pub fn update_witness(
    witness: &mut NonMembershipWitness,
    update: &WitnessUpdate,
    user_id: &UserId,
) -> Result<(), AbeError>;

/// Verify non-revocation during decryption
pub fn verify_non_membership(
    acc: &Accumulator,
    user_id: &UserId,
    witness: &NonMembershipWitness,
) -> bool;
```

---

### 4. Direct Revocation in ABE ✅ IMPLEMENTED

**Priority**: Medium
**Complexity**: Low
**File**: `src/schemes/direct_revocation.rs`

Treat user identities as attributes. Revocation is expressed directly in the encryption policy using negation.

**Example**: Policy `"admin AND NOT revoked_user_123"`

**Key Properties**:
- Simple conceptually
- Policy size grows with revocation set
- Requires negation support in policies

**Implementation Notes**:
```rust
/// Convert user ID to revocation attribute
pub fn user_to_revocation_attr(user_id: &UserId) -> String {
    format!("REVOKED_{}", user_id.as_str())
}

/// Build policy that excludes revoked users
pub fn policy_with_revocation(
    base_policy: &PolicyNode,
    revoked_users: &[UserId],
) -> PolicyNode {
    let mut policy = base_policy.clone();
    for user in revoked_users {
        let revoke_attr = user_to_revocation_attr(user);
        policy = PolicyNode::And(vec![
            policy,
            PolicyNode::Not(Box::new(PolicyNode::Attr(revoke_attr))),
        ]);
    }
    policy
}
```

**Note**: Requires adding `PolicyNode::Not` variant to LSSS.

---

### 5. Indirect Revocation (Attribute Expiration) ✅ IMPLEMENTED

**Priority**: Low
**Complexity**: Medium
**File**: `src/schemes/attribute_expiration.rs`

Attributes have validity periods. Keys automatically become invalid when attributes expire unless renewed.

**Key Properties**:
- Natural model for role-based access
- Authority controls renewal
- No explicit revocation needed

**Implementation Notes**:
```rust
pub struct TimedAttribute {
    pub name: String,
    pub valid_from: u64,
    pub valid_until: u64,
}

pub struct ExpiringSecretKey {
    pub base: SecretKey,
    pub attribute_expiry: HashMap<String, u64>,
}

/// Check if key is valid at given time
pub fn is_key_valid(sk: &ExpiringSecretKey, current_time: u64) -> bool {
    sk.attribute_expiry.values().all(|&expiry| current_time < expiry)
}

/// Encrypt with time requirement
pub fn encrypt_with_time<R: RngCore>(
    rng: &mut R,
    mpk: &Mpk,
    policy: &PolicyNode,
    required_time: u64,
    plaintext: &[u8],
) -> Result<TimedCiphertext, AbeError>;
```

---

### 6. Revocable Hierarchical IBE ✅ IMPLEMENTED

**Priority**: Low
**Complexity**: High
**File**: `src/schemes/revocable_hibe.rs`

Combines hierarchical identity structure with revocation. Higher-level authorities can revoke lower-level users.

**References**:
- Boldyreva, Goyal, Kumar. "Identity-based Encryption with Efficient Revocation" (2008)
- Seo, Emura. "Revocable Hierarchical Identity-Based Encryption" (2013)

---

### 7. Binary Tree Encryption (BTE) ✅ IMPLEMENTED

**Priority**: Low
**Complexity**: High
**File**: `src/schemes/binary_tree_encryption.rs`

Forward-secure encryption where keys evolve over time. Compromising a key at time t doesn't reveal messages encrypted before t.

**References**:
- Canetti, Halevi, Katz. "A Forward-Secure Public-Key Encryption Scheme" (2003)

---

### 8. Server-Aided Revocation (Split Keys) ✅ IMPLEMENTED

**Priority**: Medium
**Complexity**: Medium
**File**: `src/schemes/split_key_abe.rs`

Keys are split between user and server. Server can instantly revoke by refusing to provide its share.

**Difference from SEM**: Server share is static, doesn't require per-decryption interaction (can be cached).

**Implementation Notes**:
```rust
pub struct SplitSecretKey {
    pub user_share: SecretKey,
    pub server_share_id: String,  // Reference to server's share
}

pub struct ServerKeyShare {
    pub share_id: String,
    pub share: G1,
    pub revoked: bool,
}

/// User requests server share (server checks revocation)
pub fn request_server_share(
    server: &KeyServer,
    share_id: &str,
    user_proof: &UserProof,
) -> Result<G1, RevocationError>;
```

---

## Implementation Status

All revocation schemes have been implemented!

| Priority | Schemes |
|----------|---------|
| High | ~~Time-Based (BGM)~~ ✅ |
| Medium | ~~Mediator-Based~~ ✅, ~~Accumulator-Based~~ ✅, ~~Direct Revocation~~ ✅, ~~Server-Aided~~ ✅ |
| Low | ~~Attribute Expiration~~ ✅, ~~Revocable HIBE~~ ✅, ~~BTE~~ ✅ |

## Comparison

| Scheme | Revocation Speed | User Storage | Authority Work | Online Requirement |
|--------|-----------------|--------------|----------------|-------------------|
| Revocation List | Instant | O(1) | O(r) | Check at decrypt |
| Complete Subtree | Instant | O(log n) | O(r log n) | None |
| Subset Difference | Instant | O(log² n) | O(r) | None |
| Time-Based | Next period | O(1) | O(n-r) per period | Periodic updates |
| Mediator | Instant | O(1) | O(1) per decrypt | Every decryption |
| Accumulator | Instant | O(1) | O(1) per revoke | Witness update |

Where: n = total users, r = revoked users
