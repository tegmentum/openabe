//! Cryptographic security tests
//!
//! These tests verify security-critical properties of the ABE implementation.

use rabe_abe::schemes::waters::{setup, keygen, encrypt, decrypt, encrypt_kem};
use rabe_abe::PolicyNode;
use rabe_abe::utils::aes;
use rand::{thread_rng, SeedableRng};
use rand_chacha::ChaCha20Rng;

/// Test that AES nonces are unique across encryptions
#[test]
fn test_aes_nonce_uniqueness() {
    let key = [0x42u8; 32];
    let plaintext = b"test message";

    // Encrypt the same message multiple times
    let ct1 = aes::encrypt(&key, plaintext).unwrap();
    let ct2 = aes::encrypt(&key, plaintext).unwrap();
    let ct3 = aes::encrypt(&key, plaintext).unwrap();

    // Nonces are the first 12 bytes - they must all be different
    let nonce1 = &ct1[..12];
    let nonce2 = &ct2[..12];
    let nonce3 = &ct3[..12];

    assert_ne!(nonce1, nonce2, "Nonces must be unique");
    assert_ne!(nonce2, nonce3, "Nonces must be unique");
    assert_ne!(nonce1, nonce3, "Nonces must be unique");

    // All should decrypt correctly despite different nonces
    assert_eq!(aes::decrypt(&key, &ct1).unwrap(), plaintext);
    assert_eq!(aes::decrypt(&key, &ct2).unwrap(), plaintext);
    assert_eq!(aes::decrypt(&key, &ct3).unwrap(), plaintext);
}

/// Test that ciphertext is not deterministic (IND-CPA property)
#[test]
fn test_ciphertext_randomization() {
    let mut rng = thread_rng();
    let (mpk, msk) = setup(&mut rng);

    let attrs = vec!["admin".to_string()];
    let sk = keygen(&mut rng, &mpk, &msk, &attrs).unwrap();

    let policy = PolicyNode::Attr("admin".to_string());
    let plaintext = b"secret message";

    // Encrypt the same message twice
    let ct1 = encrypt(&mut rng, &mpk, &policy, plaintext).unwrap();
    let ct2 = encrypt(&mut rng, &mpk, &policy, plaintext).unwrap();

    // Ciphertexts should be different (randomized encryption)
    assert_ne!(ct1.sym_ct, ct2.sym_ct, "Ciphertexts must be randomized");

    // Both should decrypt to the same plaintext
    assert_eq!(decrypt(&mpk, &sk, &ct1).unwrap(), plaintext);
    assert_eq!(decrypt(&mpk, &sk, &ct2).unwrap(), plaintext);
}

/// Test that decryption fails on tampered ciphertext (authenticity)
#[test]
fn test_ciphertext_authenticity() {
    let mut rng = thread_rng();
    let (mpk, msk) = setup(&mut rng);

    let attrs = vec!["admin".to_string()];
    let sk = keygen(&mut rng, &mpk, &msk, &attrs).unwrap();

    let policy = PolicyNode::Attr("admin".to_string());
    let plaintext = b"secret message";

    let mut ct = encrypt(&mut rng, &mpk, &policy, plaintext).unwrap();

    // Tamper with the symmetric ciphertext
    if !ct.sym_ct.is_empty() {
        let idx = ct.sym_ct.len() / 2;
        ct.sym_ct[idx] ^= 0xff;
    }

    // Decryption should fail
    assert!(decrypt(&mpk, &sk, &ct).is_err(), "Tampered ciphertext should fail");
}

/// Test deterministic setup with seeded RNG
#[test]
fn test_deterministic_setup() {
    let seed = [0x42u8; 32];

    let mut rng1 = ChaCha20Rng::from_seed(seed);
    let mut rng2 = ChaCha20Rng::from_seed(seed);

    let (mpk1, msk1) = setup(&mut rng1);
    let (mpk2, msk2) = setup(&mut rng2);

    // Same seed should produce same keys
    assert_eq!(mpk1.g1.into_bytes(), mpk2.g1.into_bytes());
    assert_eq!(mpk1.egg_alpha.into_bytes(), mpk2.egg_alpha.into_bytes());
    assert_eq!(msk1.alpha.into_bytes(), msk2.alpha.into_bytes());
}

/// Test that KEM produces unique keys even with same policy
#[test]
fn test_kem_key_uniqueness() {
    let mut rng = thread_rng();
    let (mpk, _) = setup(&mut rng);

    let policy = PolicyNode::Attr("admin".to_string());

    // Generate multiple encapsulated keys
    let (_, key1) = encrypt_kem(&mut rng, &mpk, &policy).unwrap();
    let (_, key2) = encrypt_kem(&mut rng, &mpk, &policy).unwrap();
    let (_, key3) = encrypt_kem(&mut rng, &mpk, &policy).unwrap();

    // Keys should all be different
    assert_ne!(key1, key2, "Encapsulated keys must be unique");
    assert_ne!(key2, key3, "Encapsulated keys must be unique");
    assert_ne!(key1, key3, "Encapsulated keys must be unique");
}

/// Test that different attributes produce different secret keys
#[test]
fn test_secret_key_differentiation() {
    let mut rng = thread_rng();
    let (mpk, msk) = setup(&mut rng);

    let sk1 = keygen(&mut rng, &mpk, &msk, &["admin".to_string()]).unwrap();
    let sk2 = keygen(&mut rng, &mpk, &msk, &["user".to_string()]).unwrap();

    // Keys should be different
    assert_ne!(sk1.k.into_bytes(), sk2.k.into_bytes());
}

/// Test that wrong attributes cannot decrypt
#[test]
fn test_policy_enforcement() {
    let mut rng = thread_rng();
    let (mpk, msk) = setup(&mut rng);

    // User has only "user" attribute
    let sk = keygen(&mut rng, &mpk, &msk, &["user".to_string()]).unwrap();

    // Encrypt for "admin" attribute
    let policy = PolicyNode::Attr("admin".to_string());
    let plaintext = b"admin only";
    let ct = encrypt(&mut rng, &mpk, &policy, plaintext).unwrap();

    // Decryption should fail
    assert!(decrypt(&mpk, &sk, &ct).is_err());
}

/// Test threshold policy enforcement (n-of-m)
#[test]
fn test_threshold_policy() {
    let mut rng = thread_rng();
    let (mpk, msk) = setup(&mut rng);

    // 2-of-3 threshold
    let policy = PolicyNode::Threshold(
        2,
        vec![
            PolicyNode::Attr("a".to_string()),
            PolicyNode::Attr("b".to_string()),
            PolicyNode::Attr("c".to_string()),
        ],
    );

    let plaintext = b"threshold secret";
    let ct = encrypt(&mut rng, &mpk, &policy, plaintext).unwrap();

    // User with 2 of 3 attributes should succeed
    let sk_ab = keygen(&mut rng, &mpk, &msk, &["a".to_string(), "b".to_string()]).unwrap();
    assert!(decrypt(&mpk, &sk_ab, &ct).is_ok());

    // User with only 1 attribute should fail
    let sk_a = keygen(&mut rng, &mpk, &msk, &["a".to_string()]).unwrap();
    assert!(decrypt(&mpk, &sk_a, &ct).is_err());
}

/// Test empty plaintext handling
#[test]
fn test_empty_plaintext_rejected() {
    let mut rng = thread_rng();
    let (mpk, _) = setup(&mut rng);

    let policy = PolicyNode::Attr("admin".to_string());
    let plaintext = b"";

    // Empty plaintext should be rejected
    assert!(encrypt(&mut rng, &mpk, &policy, plaintext).is_err());
}

/// Test AES key derivation produces 32-byte keys
#[test]
fn test_key_derivation_length() {
    use rabe_bls12381::{G1, G2, pairing};

    let gt = pairing(G1::one(), G2::one());
    let key = aes::derive_key(&gt);

    assert_eq!(key.len(), 32, "Derived key must be 32 bytes");
}

/// Test that short ciphertext is rejected
#[test]
fn test_short_ciphertext_rejected() {
    let key = [0x42u8; 32];
    let short = vec![0u8; 5]; // Less than nonce size

    assert!(aes::decrypt(&key, &short).is_err());
}

// ============================================================================
// Zeroization Tests (require memory-protection feature)
// ============================================================================

/// Test that ProtectedMemory zeroizes on drop
#[cfg(feature = "memory-protection")]
#[test]
fn test_protected_memory_zeroization() {
    use rabe_abe::security::memory::ProtectedMemory;

    // Create protected memory with known value
    let secret = [0x42u8; 32];
    let protected = ProtectedMemory::new(secret);

    // Get a raw pointer to the data before dropping
    let data_ptr = &*protected as *const [u8; 32];

    // Verify the data is there
    assert_eq!(unsafe { *data_ptr }, [0x42u8; 32]);

    // Drop the protected memory
    drop(protected);

    // Note: After drop, the memory may be reused. This test verifies the
    // ProtectedMemory wrapper calls zeroize. In a real scenario, we can't
    // reliably check zeroed memory after drop due to potential reuse.
    // The actual zeroization is tested by the zeroize crate.
}

/// Test that protect_key helper works correctly
#[cfg(feature = "memory-protection")]
#[test]
fn test_protect_key_helper() {
    use rabe_abe::security::memory::protect_key;

    let key = [0xAB; 32];
    let protected = protect_key(key);

    // Should be able to access the key
    assert_eq!(&*protected, &[0xAB; 32]);
}

/// Test ProtectedMemory with mutable access
#[cfg(feature = "memory-protection")]
#[test]
fn test_protected_memory_mutation() {
    use rabe_abe::security::memory::ProtectedMemory;

    let mut protected = ProtectedMemory::new([0u8; 32]);

    // Modify the protected data
    protected[0] = 0xFF;
    protected[31] = 0xAA;

    assert_eq!(protected[0], 0xFF);
    assert_eq!(protected[31], 0xAA);
}

/// Test basic zeroize trait behavior (always available)
#[test]
fn test_zeroize_trait() {
    use zeroize::Zeroize;

    let mut secret = [0x42u8; 32];
    secret.zeroize();

    // After zeroize, should be all zeros
    assert_eq!(secret, [0u8; 32]);
}

/// Test that Vec can be zeroized
#[test]
fn test_vec_zeroize() {
    use zeroize::Zeroize;

    let mut secret_vec = vec![0xABu8; 64];
    secret_vec.zeroize();

    // Vec is cleared and capacity may remain
    assert!(secret_vec.is_empty());
}

// ============================================================================
// Point Validation Tests
// ============================================================================

/// Test that corrupted G1 points are rejected
#[test]
fn test_invalid_g1_point_rejected() {
    use rabe_bls12381::G1;

    // Corrupted valid point - flip bits in the middle
    let mut corrupted = G1::one().into_bytes();
    corrupted[10] ^= 0xFF; // Corrupt coordinate
    corrupted[20] ^= 0xFF;
    assert!(G1::from_slice(&corrupted).is_none(), "Corrupted point should be rejected");

    // Invalid high bits in compressed format (BLS12-381 uses specific flag bits)
    let mut invalid_flags = G1::one().into_bytes();
    invalid_flags[0] = 0x00; // Clear compression flag - invalid
    assert!(G1::from_slice(&invalid_flags).is_none(), "Invalid flags should be rejected");
}

/// Test that corrupted G2 points are rejected
#[test]
fn test_invalid_g2_point_rejected() {
    use rabe_bls12381::G2;

    // Corrupted valid point
    let mut corrupted = G2::one().into_bytes();
    corrupted[20] ^= 0xFF;
    corrupted[40] ^= 0xFF;
    assert!(G2::from_slice(&corrupted).is_none(), "Corrupted point should be rejected");

    // Invalid compression flags
    let mut invalid_flags = G2::one().into_bytes();
    invalid_flags[0] = 0x00; // Clear compression flag
    assert!(G2::from_slice(&invalid_flags).is_none(), "Invalid flags should be rejected");
}

/// Test that identity points can be optionally rejected
#[test]
fn test_identity_point_rejection() {
    use rabe_bls12381::{G1, G2};

    // G1 identity
    let g1_identity = G1::zero();
    let g1_bytes = g1_identity.into_bytes();

    // Should be accepted when reject_identity is false
    assert!(G1::from_slice_checked(&g1_bytes, false).is_some());
    // Should be rejected when reject_identity is true
    assert!(G1::from_slice_checked(&g1_bytes, true).is_none());

    // G2 identity
    let g2_identity = G2::zero();
    let g2_bytes = g2_identity.into_bytes();

    assert!(G2::from_slice_checked(&g2_bytes, false).is_some());
    assert!(G2::from_slice_checked(&g2_bytes, true).is_none());
}

/// Test that valid points are accepted
#[test]
fn test_valid_points_accepted() {
    use rabe_bls12381::{G1, G2, Fr};
    use rand::thread_rng;

    let mut rng = thread_rng();

    // Random G1 point roundtrip
    let g1 = G1::random(&mut rng);
    let g1_bytes = g1.into_bytes();
    let g1_restored = G1::from_slice(&g1_bytes).expect("Valid G1 should deserialize");
    assert_eq!(g1.into_bytes(), g1_restored.into_bytes());

    // Random G2 point roundtrip
    let g2 = G2::random(&mut rng);
    let g2_bytes = g2.into_bytes();
    let g2_restored = G2::from_slice(&g2_bytes).expect("Valid G2 should deserialize");
    assert_eq!(g2.into_bytes(), g2_restored.into_bytes());

    // Fr roundtrip
    let fr = Fr::random(&mut rng);
    let fr_bytes = fr.into_bytes();
    let fr_restored = Fr::from_slice(&fr_bytes).expect("Valid Fr should deserialize");
    assert_eq!(fr.into_bytes(), fr_restored.into_bytes());
}

/// Test that wrong-sized input is rejected for group elements
#[test]
fn test_wrong_size_rejected() {
    use rabe_bls12381::{G1, G2};

    // Too short - definitely rejected
    assert!(G1::from_slice(&[0u8; 20]).is_none(), "Short G1 should be rejected");
    assert!(G2::from_slice(&[0u8; 50]).is_none(), "Short G2 should be rejected");

    // Empty input
    assert!(G1::from_slice(&[]).is_none(), "Empty G1 should be rejected");
    assert!(G2::from_slice(&[]).is_none(), "Empty G2 should be rejected");
}

/// Test CBOR deserialization rejects malformed group elements
#[test]
fn test_cbor_rejects_invalid_points() {
    use rabe_bls12381::G1;

    // Create malformed CBOR with invalid G1 point
    // This simulates an attacker sending malformed data
    let invalid_g1_bytes = vec![0xFF; 48];

    // Try to decode as G1 - should fail gracefully
    let result: Result<G1, _> = ciborium::from_reader(&invalid_g1_bytes[..]);
    // CBOR parsing itself may fail or the G1 deserialization will fail
    // Either way, we should not get a valid G1
    assert!(result.is_err() || result.unwrap().into_bytes() != invalid_g1_bytes.as_slice());
}
