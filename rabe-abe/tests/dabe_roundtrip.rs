//! Round-trip tests for Decentralized Attribute-Based Encryption (DABE)
//!
//! Tests serialization/deserialization and cross-process scenarios

use rand::thread_rng;
use std::collections::HashMap;

use rabe_abe::lsss::PolicyNode;
use rabe_abe::schemes::dabe::{
    global_setup, authority_setup, authority_keygen, aggregate_user_keys,
    encrypt, decrypt,
    GlobalParams, AuthorityPk, AuthoritySk, UserKeyComponent, UserSecretKey, FullCiphertext,
};

// =============================================================================
// JSON Serialization Round-trip Tests
// =============================================================================

#[test]
fn test_global_params_json_roundtrip() {
    let mut rng = thread_rng();
    let gp = global_setup(&mut rng);

    // Serialize to JSON
    let json = serde_json::to_string(&gp).expect("Failed to serialize GlobalParams");

    // Deserialize back
    let gp2: GlobalParams = serde_json::from_str(&json).expect("Failed to deserialize GlobalParams");

    // Verify by using in encryption
    let (apk, ask) = authority_setup(&mut rng, &gp2, "test");
    let mut pks = HashMap::new();
    pks.insert("test".to_string(), apk);

    let uk = authority_keygen(&mut rng, &gp2, &ask, "user@test.com", &["admin".to_string()]).unwrap();
    let usk = aggregate_user_keys(vec![uk]).unwrap();

    let policy = PolicyNode::Attr("test:admin".to_string());
    let ct = encrypt(&mut rng, &gp2, &pks, &policy, b"test message").unwrap();
    let decrypted = decrypt(&gp2, &usk, &ct).unwrap();

    assert_eq!(decrypted, b"test message");
}

#[test]
fn test_authority_keys_json_roundtrip() {
    let mut rng = thread_rng();
    let gp = global_setup(&mut rng);
    let (apk, ask) = authority_setup(&mut rng, &gp, "auth1");

    // Serialize both keys
    let apk_json = serde_json::to_string(&apk).expect("Failed to serialize AuthorityPk");
    let ask_json = serde_json::to_string(&ask).expect("Failed to serialize AuthoritySk");

    // Deserialize
    let apk2: AuthorityPk = serde_json::from_str(&apk_json).expect("Failed to deserialize AuthorityPk");
    let ask2: AuthoritySk = serde_json::from_str(&ask_json).expect("Failed to deserialize AuthoritySk");

    // Verify authority IDs preserved
    assert_eq!(apk2.aid, "auth1");
    assert_eq!(ask2.aid, "auth1");

    // Verify keys work together
    let mut pks = HashMap::new();
    pks.insert("auth1".to_string(), apk2);

    let uk = authority_keygen(&mut rng, &gp, &ask2, "user@test.com", &["manager".to_string()]).unwrap();
    let usk = aggregate_user_keys(vec![uk]).unwrap();

    let policy = PolicyNode::Attr("auth1:manager".to_string());
    let ct = encrypt(&mut rng, &gp, &pks, &policy, b"manager only").unwrap();
    let decrypted = decrypt(&gp, &usk, &ct).unwrap();

    assert_eq!(decrypted, b"manager only");
}

#[test]
fn test_user_key_component_json_roundtrip() {
    let mut rng = thread_rng();
    let gp = global_setup(&mut rng);
    let (_apk, ask) = authority_setup(&mut rng, &gp, "company");

    let attrs = vec!["admin".to_string(), "developer".to_string()];
    let uk = authority_keygen(&mut rng, &gp, &ask, "alice@company.com", &attrs).unwrap();

    // Serialize
    let uk_json = serde_json::to_string(&uk).expect("Failed to serialize UserKeyComponent");

    // Deserialize
    let uk2: UserKeyComponent = serde_json::from_str(&uk_json).expect("Failed to deserialize UserKeyComponent");

    // Verify fields preserved
    assert_eq!(uk2.aid, "company");
    assert_eq!(uk2.kx.len(), 2);
    assert!(uk2.kx.contains_key("company:admin"));
    assert!(uk2.kx.contains_key("company:developer"));
}

#[test]
fn test_user_secret_key_json_roundtrip() {
    let mut rng = thread_rng();
    let gp = global_setup(&mut rng);

    // Setup two authorities
    let (_apk1, ask1) = authority_setup(&mut rng, &gp, "hr");
    let (_apk2, ask2) = authority_setup(&mut rng, &gp, "engineering");

    // Issue keys from both
    let uk1 = authority_keygen(&mut rng, &gp, &ask1, "bob@corp.com", &["employee".to_string()]).unwrap();
    let uk2 = authority_keygen(&mut rng, &gp, &ask2, "bob@corp.com", &["developer".to_string()]).unwrap();

    let usk = aggregate_user_keys(vec![uk1, uk2]).unwrap();

    // Serialize
    let usk_json = serde_json::to_string(&usk).expect("Failed to serialize UserSecretKey");

    // Deserialize
    let usk2: UserSecretKey = serde_json::from_str(&usk_json).expect("Failed to deserialize UserSecretKey");

    // Verify
    assert_eq!(usk2.components.len(), 2);
    assert!(usk2.components.contains_key("hr"));
    assert!(usk2.components.contains_key("engineering"));
}

#[test]
fn test_ciphertext_json_roundtrip() {
    let mut rng = thread_rng();
    let gp = global_setup(&mut rng);
    let (apk, _ask) = authority_setup(&mut rng, &gp, "test");

    let mut pks = HashMap::new();
    pks.insert("test".to_string(), apk);

    let policy = PolicyNode::Attr("test:admin".to_string());
    let plaintext = b"This is a secret message for the round-trip test";
    let ct = encrypt(&mut rng, &gp, &pks, &policy, plaintext).unwrap();

    // Serialize
    let ct_json = serde_json::to_string(&ct).expect("Failed to serialize FullCiphertext");

    // Deserialize
    let ct2: FullCiphertext = serde_json::from_str(&ct_json).expect("Failed to deserialize FullCiphertext");

    // Verify policy preserved
    assert_eq!(ct2.abe_ct.policy, ct.abe_ct.policy);
    assert_eq!(ct2.sym_ct.len(), ct.sym_ct.len());
}

// =============================================================================
// Full End-to-End Round-trip Tests
// =============================================================================

#[test]
fn test_single_authority_full_roundtrip() {
    let mut rng = thread_rng();

    // === SETUP PHASE (Authority Server) ===
    let gp = global_setup(&mut rng);
    let (apk, ask) = authority_setup(&mut rng, &gp, "acme");

    // Serialize everything
    let gp_json = serde_json::to_string(&gp).unwrap();
    let apk_json = serde_json::to_string(&apk).unwrap();
    let ask_json = serde_json::to_string(&ask).unwrap();

    // === KEYGEN PHASE (Simulate different process) ===
    let gp2: GlobalParams = serde_json::from_str(&gp_json).unwrap();
    let ask2: AuthoritySk = serde_json::from_str(&ask_json).unwrap();

    let uk = authority_keygen(&mut rng, &gp2, &ask2, "user@acme.com",
        &["level1".to_string(), "level2".to_string()]).unwrap();
    let uk_json = serde_json::to_string(&uk).unwrap();

    // === USER AGGREGATION (User's device) ===
    let uk3: UserKeyComponent = serde_json::from_str(&uk_json).unwrap();
    let usk = aggregate_user_keys(vec![uk3]).unwrap();
    let usk_json = serde_json::to_string(&usk).unwrap();

    // === ENCRYPTION (Data owner) ===
    let gp3: GlobalParams = serde_json::from_str(&gp_json).unwrap();
    let apk3: AuthorityPk = serde_json::from_str(&apk_json).unwrap();

    let mut pks = HashMap::new();
    pks.insert("acme".to_string(), apk3);

    let policy = PolicyNode::And(vec![
        PolicyNode::Attr("acme:level1".to_string()),
        PolicyNode::Attr("acme:level2".to_string()),
    ]);
    let plaintext = b"Confidential: Q4 earnings report";
    let ct = encrypt(&mut rng, &gp3, &pks, &policy, plaintext).unwrap();
    let ct_json = serde_json::to_string(&ct).unwrap();

    // === DECRYPTION (User's device, different session) ===
    let gp4: GlobalParams = serde_json::from_str(&gp_json).unwrap();
    let usk4: UserSecretKey = serde_json::from_str(&usk_json).unwrap();
    let ct4: FullCiphertext = serde_json::from_str(&ct_json).unwrap();

    let decrypted = decrypt(&gp4, &usk4, &ct4).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_multi_authority_serialization_roundtrip() {
    // This test verifies that keys from multiple authorities can be serialized,
    // deserialized, and used correctly.

    let mut rng = thread_rng();

    // === GLOBAL SETUP ===
    let gp = global_setup(&mut rng);
    let gp_json = serde_json::to_string(&gp).unwrap();

    // === AUTHORITY 1 SETUP (HR Department) ===
    let gp1: GlobalParams = serde_json::from_str(&gp_json).unwrap();
    let (apk_hr, ask_hr) = authority_setup(&mut rng, &gp1, "hr");
    let apk_hr_json = serde_json::to_string(&apk_hr).unwrap();
    let ask_hr_json = serde_json::to_string(&ask_hr).unwrap();

    // === AUTHORITY 2 SETUP (IT Department) ===
    let gp2: GlobalParams = serde_json::from_str(&gp_json).unwrap();
    let (apk_it, ask_it) = authority_setup(&mut rng, &gp2, "it");
    let apk_it_json = serde_json::to_string(&apk_it).unwrap();
    let ask_it_json = serde_json::to_string(&ask_it).unwrap();

    // === HR ISSUES KEY COMPONENT ===
    let gp_hr: GlobalParams = serde_json::from_str(&gp_json).unwrap();
    let ask_hr2: AuthoritySk = serde_json::from_str(&ask_hr_json).unwrap();
    let uk_hr = authority_keygen(&mut rng, &gp_hr, &ask_hr2, "alice@corp.com",
        &["employee".to_string(), "manager".to_string()]).unwrap();
    let uk_hr_json = serde_json::to_string(&uk_hr).unwrap();

    // === IT ISSUES KEY COMPONENT ===
    let gp_it: GlobalParams = serde_json::from_str(&gp_json).unwrap();
    let ask_it2: AuthoritySk = serde_json::from_str(&ask_it_json).unwrap();
    let uk_it = authority_keygen(&mut rng, &gp_it, &ask_it2, "alice@corp.com",
        &["developer".to_string(), "sysadmin".to_string()]).unwrap();
    let uk_it_json = serde_json::to_string(&uk_it).unwrap();

    // === USER AGGREGATES KEYS ===
    let uk_hr3: UserKeyComponent = serde_json::from_str(&uk_hr_json).unwrap();
    let uk_it3: UserKeyComponent = serde_json::from_str(&uk_it_json).unwrap();

    let usk = aggregate_user_keys(vec![uk_hr3, uk_it3]).unwrap();
    let usk_json = serde_json::to_string(&usk).unwrap();

    // Verify both authorities are in the key
    assert_eq!(usk.components.len(), 2);
    assert!(usk.components.contains_key("hr"));
    assert!(usk.components.contains_key("it"));

    // === TEST HR-ONLY POLICY ===
    let gp_enc: GlobalParams = serde_json::from_str(&gp_json).unwrap();
    let apk_hr3: AuthorityPk = serde_json::from_str(&apk_hr_json).unwrap();

    let mut pks_hr = HashMap::new();
    pks_hr.insert("hr".to_string(), apk_hr3);

    // Policy within single authority works fine
    let policy_hr = PolicyNode::And(vec![
        PolicyNode::Attr("hr:employee".to_string()),
        PolicyNode::Attr("hr:manager".to_string()),
    ]);

    let plaintext = b"HR confidential document";
    let ct = encrypt(&mut rng, &gp_enc, &pks_hr, &policy_hr, plaintext).unwrap();
    let ct_json = serde_json::to_string(&ct).unwrap();

    // === USER DECRYPTS ===
    let gp_dec: GlobalParams = serde_json::from_str(&gp_json).unwrap();
    let usk_dec: UserSecretKey = serde_json::from_str(&usk_json).unwrap();
    let ct_dec: FullCiphertext = serde_json::from_str(&ct_json).unwrap();

    let decrypted = decrypt(&gp_dec, &usk_dec, &ct_dec).unwrap();
    assert_eq!(decrypted, plaintext);

    // === TEST IT-ONLY POLICY ===
    let apk_it3: AuthorityPk = serde_json::from_str(&apk_it_json).unwrap();
    let mut pks_it = HashMap::new();
    pks_it.insert("it".to_string(), apk_it3);

    let policy_it = PolicyNode::Or(vec![
        PolicyNode::Attr("it:developer".to_string()),
        PolicyNode::Attr("it:sysadmin".to_string()),
    ]);

    let plaintext_it = b"IT department memo";
    let ct_it = encrypt(&mut rng, &gp_enc, &pks_it, &policy_it, plaintext_it).unwrap();
    let ct_it_json = serde_json::to_string(&ct_it).unwrap();

    let ct_it_dec: FullCiphertext = serde_json::from_str(&ct_it_json).unwrap();
    let decrypted_it = decrypt(&gp_dec, &usk_dec, &ct_it_dec).unwrap();
    assert_eq!(decrypted_it, plaintext_it);
}

#[test]
fn test_cross_authority_or_roundtrip() {
    // Test cross-authority OR policy with serialization

    let mut rng = thread_rng();

    // Setup
    let gp = global_setup(&mut rng);
    let gp_json = serde_json::to_string(&gp).unwrap();

    let (apk_hr, ask_hr) = authority_setup(&mut rng, &gp, "hr");
    let (apk_it, _ask_it) = authority_setup(&mut rng, &gp, "it");

    let apk_hr_json = serde_json::to_string(&apk_hr).unwrap();
    let apk_it_json = serde_json::to_string(&apk_it).unwrap();

    // User only gets HR key
    let uk_hr = authority_keygen(&mut rng, &gp, &ask_hr, "user@corp.com", &["employee".to_string()]).unwrap();
    let uk_hr_json = serde_json::to_string(&uk_hr).unwrap();

    // Aggregate (only HR)
    let uk_hr2: UserKeyComponent = serde_json::from_str(&uk_hr_json).unwrap();
    let usk = aggregate_user_keys(vec![uk_hr2]).unwrap();
    let usk_json = serde_json::to_string(&usk).unwrap();

    // Encrypt with cross-authority OR policy
    let apk_hr2: AuthorityPk = serde_json::from_str(&apk_hr_json).unwrap();
    let apk_it2: AuthorityPk = serde_json::from_str(&apk_it_json).unwrap();

    let mut pks = HashMap::new();
    pks.insert("hr".to_string(), apk_hr2);
    pks.insert("it".to_string(), apk_it2);

    let policy = PolicyNode::Or(vec![
        PolicyNode::Attr("hr:employee".to_string()),
        PolicyNode::Attr("it:admin".to_string()),
    ]);

    let gp2: GlobalParams = serde_json::from_str(&gp_json).unwrap();
    let plaintext = b"Cross-authority OR document";
    let ct = encrypt(&mut rng, &gp2, &pks, &policy, plaintext).unwrap();
    let ct_json = serde_json::to_string(&ct).unwrap();

    // Decrypt (should work with just HR key)
    let gp3: GlobalParams = serde_json::from_str(&gp_json).unwrap();
    let usk2: UserSecretKey = serde_json::from_str(&usk_json).unwrap();
    let ct2: FullCiphertext = serde_json::from_str(&ct_json).unwrap();

    let decrypted = decrypt(&gp3, &usk2, &ct2).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_cross_authority_and_roundtrip() {
    // This test verifies that cross-authority AND policies work correctly.
    // Full LW11 scheme implementation supports this through special handling
    // in encryption where each authority's branch receives the full secret.

    let mut rng = thread_rng();

    // Setup
    let gp = global_setup(&mut rng);
    let gp_json = serde_json::to_string(&gp).unwrap();

    let (apk_hr, ask_hr) = authority_setup(&mut rng, &gp, "hr");
    let (apk_it, ask_it) = authority_setup(&mut rng, &gp, "it");

    let apk_hr_json = serde_json::to_string(&apk_hr).unwrap();
    let apk_it_json = serde_json::to_string(&apk_it).unwrap();

    // User gets keys from BOTH authorities
    let uk_hr = authority_keygen(&mut rng, &gp, &ask_hr, "user@corp.com", &["employee".to_string()]).unwrap();
    let uk_it = authority_keygen(&mut rng, &gp, &ask_it, "user@corp.com", &["developer".to_string()]).unwrap();

    let uk_hr_json = serde_json::to_string(&uk_hr).unwrap();
    let uk_it_json = serde_json::to_string(&uk_it).unwrap();

    // Aggregate both
    let uk_hr2: UserKeyComponent = serde_json::from_str(&uk_hr_json).unwrap();
    let uk_it2: UserKeyComponent = serde_json::from_str(&uk_it_json).unwrap();
    let usk = aggregate_user_keys(vec![uk_hr2, uk_it2]).unwrap();
    let usk_json = serde_json::to_string(&usk).unwrap();

    // Encrypt with cross-authority AND policy
    let apk_hr2: AuthorityPk = serde_json::from_str(&apk_hr_json).unwrap();
    let apk_it2: AuthorityPk = serde_json::from_str(&apk_it_json).unwrap();

    let mut pks = HashMap::new();
    pks.insert("hr".to_string(), apk_hr2);
    pks.insert("it".to_string(), apk_it2);

    let policy = PolicyNode::And(vec![
        PolicyNode::Attr("hr:employee".to_string()),
        PolicyNode::Attr("it:developer".to_string()),
    ]);

    let gp2: GlobalParams = serde_json::from_str(&gp_json).unwrap();
    let plaintext = b"Cross-authority AND document";
    let ct = encrypt(&mut rng, &gp2, &pks, &policy, plaintext).unwrap();
    let ct_json = serde_json::to_string(&ct).unwrap();

    // Decrypt (needs both HR and IT keys)
    let gp3: GlobalParams = serde_json::from_str(&gp_json).unwrap();
    let usk2: UserSecretKey = serde_json::from_str(&usk_json).unwrap();
    let ct2: FullCiphertext = serde_json::from_str(&ct_json).unwrap();

    let decrypted = decrypt(&gp3, &usk2, &ct2).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_threshold_policy_roundtrip() {
    let mut rng = thread_rng();

    let gp = global_setup(&mut rng);
    let (apk, ask) = authority_setup(&mut rng, &gp, "gov");

    // Serialize/deserialize
    let gp_json = serde_json::to_string(&gp).unwrap();
    let apk_json = serde_json::to_string(&apk).unwrap();
    let ask_json = serde_json::to_string(&ask).unwrap();

    let gp2: GlobalParams = serde_json::from_str(&gp_json).unwrap();
    let ask2: AuthoritySk = serde_json::from_str(&ask_json).unwrap();

    // User gets 3 of 5 security clearances
    let uk = authority_keygen(&mut rng, &gp2, &ask2, "agent@gov.org",
        &["clearance_a".to_string(), "clearance_b".to_string(), "clearance_c".to_string()]).unwrap();

    let uk_json = serde_json::to_string(&uk).unwrap();
    let uk2: UserKeyComponent = serde_json::from_str(&uk_json).unwrap();
    let usk = aggregate_user_keys(vec![uk2]).unwrap();
    let usk_json = serde_json::to_string(&usk).unwrap();

    // Encrypt with 2-of-5 threshold
    let apk2: AuthorityPk = serde_json::from_str(&apk_json).unwrap();
    let mut pks = HashMap::new();
    pks.insert("gov".to_string(), apk2);

    let policy = PolicyNode::Threshold(2, vec![
        PolicyNode::Attr("gov:clearance_a".to_string()),
        PolicyNode::Attr("gov:clearance_b".to_string()),
        PolicyNode::Attr("gov:clearance_c".to_string()),
        PolicyNode::Attr("gov:clearance_d".to_string()),
        PolicyNode::Attr("gov:clearance_e".to_string()),
    ]);

    let plaintext = b"TOP SECRET: Operation details";
    let ct = encrypt(&mut rng, &gp2, &pks, &policy, plaintext).unwrap();
    let ct_json = serde_json::to_string(&ct).unwrap();

    // Decrypt
    let gp3: GlobalParams = serde_json::from_str(&gp_json).unwrap();
    let usk2: UserSecretKey = serde_json::from_str(&usk_json).unwrap();
    let ct2: FullCiphertext = serde_json::from_str(&ct_json).unwrap();

    let decrypted = decrypt(&gp3, &usk2, &ct2).unwrap();
    assert_eq!(decrypted, plaintext);
}

// =============================================================================
// Edge Case Tests
// =============================================================================

#[test]
fn test_empty_message_roundtrip() {
    let mut rng = thread_rng();
    let gp = global_setup(&mut rng);
    let (apk, ask) = authority_setup(&mut rng, &gp, "test");

    let mut pks = HashMap::new();
    pks.insert("test".to_string(), apk);

    let uk = authority_keygen(&mut rng, &gp, &ask, "user@test.com", &["attr".to_string()]).unwrap();
    let usk = aggregate_user_keys(vec![uk]).unwrap();

    let policy = PolicyNode::Attr("test:attr".to_string());
    let plaintext = b"";
    let ct = encrypt(&mut rng, &gp, &pks, &policy, plaintext).unwrap();

    // Serialize/deserialize
    let ct_json = serde_json::to_string(&ct).unwrap();
    let ct2: FullCiphertext = serde_json::from_str(&ct_json).unwrap();

    let decrypted = decrypt(&gp, &usk, &ct2).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_large_message_roundtrip() {
    let mut rng = thread_rng();
    let gp = global_setup(&mut rng);
    let (apk, ask) = authority_setup(&mut rng, &gp, "test");

    let mut pks = HashMap::new();
    pks.insert("test".to_string(), apk);

    let uk = authority_keygen(&mut rng, &gp, &ask, "user@test.com", &["attr".to_string()]).unwrap();
    let usk = aggregate_user_keys(vec![uk]).unwrap();

    let policy = PolicyNode::Attr("test:attr".to_string());

    // 1MB message
    let plaintext: Vec<u8> = (0..1_000_000).map(|i| (i % 256) as u8).collect();
    let ct = encrypt(&mut rng, &gp, &pks, &policy, &plaintext).unwrap();

    // Serialize/deserialize
    let ct_json = serde_json::to_string(&ct).unwrap();
    let ct2: FullCiphertext = serde_json::from_str(&ct_json).unwrap();

    let decrypted = decrypt(&gp, &usk, &ct2).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_special_characters_in_authority_id() {
    let mut rng = thread_rng();
    let gp = global_setup(&mut rng);

    // Authority ID with special characters
    let (apk, ask) = authority_setup(&mut rng, &gp, "org.example.department-123");

    // Serialize/deserialize
    let apk_json = serde_json::to_string(&apk).unwrap();
    let ask_json = serde_json::to_string(&ask).unwrap();

    let apk2: AuthorityPk = serde_json::from_str(&apk_json).unwrap();
    let ask2: AuthoritySk = serde_json::from_str(&ask_json).unwrap();

    assert_eq!(apk2.aid, "org.example.department-123");
    assert_eq!(ask2.aid, "org.example.department-123");

    let mut pks = HashMap::new();
    pks.insert("org.example.department-123".to_string(), apk2);

    let uk = authority_keygen(&mut rng, &gp, &ask2, "user@test.com", &["role".to_string()]).unwrap();
    let usk = aggregate_user_keys(vec![uk]).unwrap();

    let policy = PolicyNode::Attr("org.example.department-123:role".to_string());
    let ct = encrypt(&mut rng, &gp, &pks, &policy, b"test").unwrap();
    let decrypted = decrypt(&gp, &usk, &ct).unwrap();

    assert_eq!(decrypted, b"test");
}

#[test]
fn test_user_key_component_fields() {
    let mut rng = thread_rng();
    let gp = global_setup(&mut rng);
    let (_apk, ask) = authority_setup(&mut rng, &gp, "test");

    let uk = authority_keygen(&mut rng, &gp, &ask, "user@test.com", &["attr".to_string()]).unwrap();

    // Serialize/deserialize
    let uk_json = serde_json::to_string(&uk).unwrap();
    let uk2: UserKeyComponent = serde_json::from_str(&uk_json).unwrap();

    // Verify authority ID is preserved
    assert_eq!(uk2.aid, "test");
    assert!(uk2.kx.contains_key("test:attr"));
}

// =============================================================================
// Failure Case Tests
// =============================================================================

#[test]
fn test_wrong_authority_key_fails() {
    let mut rng = thread_rng();
    let gp = global_setup(&mut rng);

    // Authority 1 sets up
    let (apk1, _ask1) = authority_setup(&mut rng, &gp, "auth1");

    // Authority 2 sets up (different)
    let (_apk2, ask2) = authority_setup(&mut rng, &gp, "auth2");

    // User gets key from auth2 but we encrypt with auth1's pk
    let uk = authority_keygen(&mut rng, &gp, &ask2, "user@test.com", &["admin".to_string()]).unwrap();

    // Serialize/deserialize
    let uk_json = serde_json::to_string(&uk).unwrap();
    let uk2: UserKeyComponent = serde_json::from_str(&uk_json).unwrap();
    let usk = aggregate_user_keys(vec![uk2]).unwrap();

    // Encrypt with auth1
    let mut pks = HashMap::new();
    pks.insert("auth1".to_string(), apk1);

    let policy = PolicyNode::Attr("auth1:admin".to_string());
    let ct = encrypt(&mut rng, &gp, &pks, &policy, b"secret").unwrap();

    // Decryption should fail - user has auth2 keys, not auth1
    let result = decrypt(&gp, &usk, &ct);
    assert!(result.is_err());
}

#[test]
fn test_partial_authority_keys_fails_and_policy() {
    let mut rng = thread_rng();
    let gp = global_setup(&mut rng);

    let (apk1, ask1) = authority_setup(&mut rng, &gp, "auth1");
    let (apk2, _ask2) = authority_setup(&mut rng, &gp, "auth2");

    // User only gets key from auth1
    let uk1 = authority_keygen(&mut rng, &gp, &ask1, "user@test.com", &["role".to_string()]).unwrap();
    let usk = aggregate_user_keys(vec![uk1]).unwrap();

    let mut pks = HashMap::new();
    pks.insert("auth1".to_string(), apk1);
    pks.insert("auth2".to_string(), apk2);

    // Policy requires attributes from BOTH authorities
    let policy = PolicyNode::And(vec![
        PolicyNode::Attr("auth1:role".to_string()),
        PolicyNode::Attr("auth2:role".to_string()),
    ]);

    let ct = encrypt(&mut rng, &gp, &pks, &policy, b"need both").unwrap();

    // Serialize/deserialize to ensure it's not a serialization issue
    let ct_json = serde_json::to_string(&ct).unwrap();
    let ct2: FullCiphertext = serde_json::from_str(&ct_json).unwrap();

    // Should fail - missing auth2 keys
    let result = decrypt(&gp, &usk, &ct2);
    assert!(result.is_err());
}
