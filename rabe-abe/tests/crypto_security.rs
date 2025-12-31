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
