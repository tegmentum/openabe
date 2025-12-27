//! Cross-platform compatibility tests
//!
//! These tests verify that:
//! 1. Keys and ciphertexts can be serialized to CBOR
//! 2. The CBOR format is deterministic (same output for same input)
//! 3. Keys/ciphertexts can roundtrip through CBOR
//!
//! These tests ensure native Rust and WASM builds produce compatible outputs.

use rabe_abe::schemes::waters::{setup as waters_setup, keygen as waters_keygen, encrypt as waters_encrypt, decrypt as waters_decrypt, parse_policy, Mpk, Msk, SecretKey, FullCiphertext};
use rabe_abe::schemes::waters_cca::{encrypt as waters_cca_encrypt, decrypt as waters_cca_decrypt, CcaFullCiphertext};
use rabe_abe::schemes::gpsw::{setup as gpsw_setup, keygen as gpsw_keygen, encrypt as gpsw_encrypt, decrypt as gpsw_decrypt, Mpk as GpswMpk, Msk as GpswMsk, SecretKey as GpswSecretKey, FullCiphertext as GpswFullCiphertext};
use rabe_abe::lsss::PolicyNode;
use rabe_abe::cbor::{encode_mpk, decode_mpk, encode_msk, decode_msk, encode_sk, decode_sk, encode_cca_full_ct, decode_cca_full_ct};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

/// Test deterministic setup with seeded RNG
#[test]
fn test_deterministic_setup() {
    // Two RNGs with same seed should produce identical keys
    let mut rng1 = ChaCha20Rng::seed_from_u64(12345);
    let mut rng2 = ChaCha20Rng::seed_from_u64(12345);

    let (mpk1, msk1) = waters_setup(&mut rng1);
    let (mpk2, msk2) = waters_setup(&mut rng2);

    // Serialize both and compare
    let mpk1_cbor = encode_mpk(&mpk1).unwrap();
    let mpk2_cbor = encode_mpk(&mpk2).unwrap();

    assert_eq!(mpk1_cbor, mpk2_cbor, "Deterministic setup should produce identical MPK");

    let msk1_cbor = encode_msk(&msk1).unwrap();
    let msk2_cbor = encode_msk(&msk2).unwrap();

    assert_eq!(msk1_cbor, msk2_cbor, "Deterministic setup should produce identical MSK");
}

/// Test MPK CBOR roundtrip
#[test]
fn test_mpk_cbor_roundtrip() {
    let mut rng = ChaCha20Rng::seed_from_u64(42);
    let (mpk, _msk) = waters_setup(&mut rng);

    let cbor = encode_mpk(&mpk).unwrap();
    let mpk2 = decode_mpk(&cbor).unwrap();

    // Re-encode and compare
    let cbor2 = encode_mpk(&mpk2).unwrap();
    assert_eq!(cbor, cbor2, "MPK should roundtrip through CBOR");
}

/// Test MSK CBOR roundtrip
#[test]
fn test_msk_cbor_roundtrip() {
    let mut rng = ChaCha20Rng::seed_from_u64(42);
    let (_mpk, msk) = waters_setup(&mut rng);

    let cbor = encode_msk(&msk).unwrap();
    let msk2 = decode_msk(&cbor).unwrap();

    // Re-encode and compare
    let cbor2 = encode_msk(&msk2).unwrap();
    assert_eq!(cbor, cbor2, "MSK should roundtrip through CBOR");
}

/// Test SecretKey CBOR roundtrip
#[test]
fn test_sk_cbor_roundtrip() {
    let mut rng = ChaCha20Rng::seed_from_u64(42);
    let (mpk, msk) = waters_setup(&mut rng);

    let attrs = vec!["admin".to_string(), "developer".to_string()];
    let sk = waters_keygen(&mut rng, &mpk, &msk, &attrs).unwrap();

    let cbor = encode_sk(&sk).unwrap();
    let sk2 = decode_sk(&cbor).unwrap();

    // Verify attributes match
    assert_eq!(sk.attributes, sk2.attributes, "Attributes should match after roundtrip");

    // Re-encode and compare
    let cbor2 = encode_sk(&sk2).unwrap();
    assert_eq!(cbor, cbor2, "SK should roundtrip through CBOR");
}

/// Test CCA ciphertext CBOR roundtrip
#[test]
fn test_cca_ct_cbor_roundtrip() {
    let mut rng = ChaCha20Rng::seed_from_u64(42);
    let (mpk, msk) = waters_setup(&mut rng);

    let policy = PolicyNode::And(vec![
        PolicyNode::Attr("admin".to_string()),
        PolicyNode::Attr("developer".to_string()),
    ]);

    let plaintext = b"Cross-platform test message";
    let ct = waters_cca_encrypt(&mut rng, &mpk, &policy, plaintext).unwrap();

    let cbor = encode_cca_full_ct(&ct).unwrap();
    let ct2 = decode_cca_full_ct(&cbor).unwrap();

    // Verify policy matches
    assert_eq!(ct.cca_ct.cpa_ct.policy, ct2.cca_ct.cpa_ct.policy, "Policy should match after roundtrip");

    // Re-encode and compare
    let cbor2 = encode_cca_full_ct(&ct2).unwrap();
    assert_eq!(cbor, cbor2, "CCA CT should roundtrip through CBOR");
}

/// Test full encryption/decryption with CBOR serialization
#[test]
fn test_full_encrypt_decrypt_with_cbor() {
    let mut rng = ChaCha20Rng::seed_from_u64(42);

    // Setup
    let (mpk, msk) = waters_setup(&mut rng);

    // Keygen
    let attrs = vec!["admin".to_string(), "developer".to_string()];
    let sk = waters_keygen(&mut rng, &mpk, &msk, &attrs).unwrap();

    // Encrypt
    let policy = PolicyNode::And(vec![
        PolicyNode::Attr("admin".to_string()),
        PolicyNode::Attr("developer".to_string()),
    ]);
    let plaintext = b"This message should survive CBOR roundtrip";
    let ct = waters_cca_encrypt(&mut rng, &mpk, &policy, plaintext).unwrap();

    // Serialize everything to CBOR
    let mpk_cbor = encode_mpk(&mpk).unwrap();
    let sk_cbor = encode_sk(&sk).unwrap();
    let ct_cbor = encode_cca_full_ct(&ct).unwrap();

    // Deserialize (simulating receiving data from different platform)
    let mpk2 = decode_mpk(&mpk_cbor).unwrap();
    let sk2 = decode_sk(&sk_cbor).unwrap();
    let ct2 = decode_cca_full_ct(&ct_cbor).unwrap();

    // Decrypt
    let decrypted = waters_cca_decrypt(&mpk2, &sk2, &ct2).unwrap();
    assert_eq!(decrypted, plaintext);
}

/// Test that CBOR size is reasonable
#[test]
fn test_cbor_size() {
    let mut rng = ChaCha20Rng::seed_from_u64(42);
    let (mpk, msk) = waters_setup(&mut rng);

    let mpk_cbor = encode_mpk(&mpk).unwrap();
    let msk_cbor = encode_msk(&msk).unwrap();

    // MPK should be reasonably sized (G1, G2, GT elements + hash key)
    // G1: 48 bytes compressed, G2: 96 bytes, GT: 576 bytes
    // MPK has: g1, g2, g1a, g2alpha, egg_alpha, k (32 bytes)
    // Expected: ~48 + 96 + 48 + 96 + 576 + 32 + overhead = ~900-1200 bytes
    assert!(mpk_cbor.len() < 2000, "MPK CBOR size should be reasonable: {} bytes", mpk_cbor.len());

    // MSK is just alpha (32 bytes) + g2a (96 bytes) + overhead
    assert!(msk_cbor.len() < 500, "MSK CBOR size should be reasonable: {} bytes", msk_cbor.len());

    println!("MPK CBOR size: {} bytes", mpk_cbor.len());
    println!("MSK CBOR size: {} bytes", msk_cbor.len());
}

/// Test GPSW KP-ABE with deterministic RNG
#[test]
fn test_gpsw_deterministic() {
    let mut rng = ChaCha20Rng::seed_from_u64(12345);

    // Setup
    let (mpk, msk) = gpsw_setup(&mut rng);

    // Create key with policy
    let policy = PolicyNode::Or(vec![
        PolicyNode::Attr("manager".to_string()),
        PolicyNode::Attr("executive".to_string()),
    ]);
    let sk = gpsw_keygen(&mut rng, &mpk, &msk, &policy).unwrap();

    // Encrypt under attributes that satisfy the policy
    let attributes = vec!["manager".to_string()];
    let plaintext = b"KP-ABE test message";
    let ct = gpsw_encrypt(&mut rng, &mpk, &attributes, plaintext).unwrap();

    // Decrypt
    let decrypted = gpsw_decrypt(&mpk, &sk, &ct).unwrap();
    assert_eq!(decrypted, plaintext);
}

/// Generate test vectors for cross-platform verification
#[test]
fn test_generate_test_vectors() {
    let mut rng = ChaCha20Rng::seed_from_u64(0xDEADBEEF);

    // Waters '11 CPA test vector
    let (mpk, msk) = waters_setup(&mut rng);
    let attrs = vec!["role:admin".to_string()];
    let sk = waters_keygen(&mut rng, &mpk, &msk, &attrs).unwrap();

    let policy = PolicyNode::Attr("role:admin".to_string());
    let plaintext = b"Test vector plaintext";
    let ct = waters_encrypt(&mut rng, &mpk, &policy, plaintext).unwrap();

    // Serialize
    let mpk_cbor = encode_mpk(&mpk).unwrap();
    let sk_cbor = encode_sk(&sk).unwrap();

    // These could be saved to files for cross-platform testing
    println!("Test vector MPK ({} bytes): {:02x?}", mpk_cbor.len(), &mpk_cbor[..20]);
    println!("Test vector SK ({} bytes): {:02x?}", sk_cbor.len(), &sk_cbor[..20]);

    // Verify decryption works
    let decrypted = waters_decrypt(&mpk, &sk, &ct).unwrap();
    assert_eq!(decrypted, plaintext);
}
