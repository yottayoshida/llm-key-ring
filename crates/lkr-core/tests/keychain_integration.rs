//! Tier 2: Contract tests — real macOS Keychain operations.
//!
//! These tests create a temporary keychain in /tmp/ and exercise the full
//! init → set → get → list → delete → lock flow.
//!
//! Run with: `cargo test --test keychain_integration`
//! These tests WILL create/delete keychain files in /tmp/.

use lkr_core::custom_keychain;
use lkr_core::error::Error;
use lkr_core::{KeyKind, KeyStore, KeychainStore};
use security_framework::os::macos::keychain::{CreateOptions, SecKeychain};
use std::ffi::c_void;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};

// Unique counter to avoid test keychain name collisions in parallel runs
static TEST_COUNTER: AtomicU32 = AtomicU32::new(0);

const TEST_PASSWORD: &str = "test-pw-12345";

/// Create a unique test keychain in /tmp/ and return (path, SecKeychain).
fn create_test_keychain() -> (PathBuf, SecKeychain) {
    let id = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
    let pid = std::process::id();
    let path = PathBuf::from(format!("/tmp/lkr-test-{}-{}.keychain-db", pid, id));

    // Cleanup leftover from previous run
    if path.exists() {
        cleanup_keychain(&path);
    }

    let kc = CreateOptions::new()
        .password(TEST_PASSWORD)
        .create(&path)
        .expect("Failed to create test keychain");

    // Remove from search list (same as custom_keychain::ensure_not_in_search_list)
    let _ = custom_keychain::ensure_not_in_search_list(&kc);

    (path, kc)
}

/// Clean up a test keychain file.
fn cleanup_keychain(path: &PathBuf) {
    unsafe extern "C" {
        fn SecKeychainDelete(keychain: *const c_void) -> i32;
    }

    // Try to open and delete properly first
    if let Ok(kc) = SecKeychain::open(path.as_path()) {
        use core_foundation::base::TCFType;
        unsafe {
            SecKeychainDelete(kc.as_concrete_TypeRef() as _);
        }
    }
    // Fallback: remove the file
    let _ = std::fs::remove_file(path);
}

// ── Tier 2: Contract tests ──────────────────────────────────────

#[test]
fn test_create_unlock_lock_cycle() {
    let (path, mut kc) = create_test_keychain();

    // Lock
    assert!(custom_keychain::lock(&kc).is_ok());

    // Unlock with correct password
    assert!(custom_keychain::unlock(&mut kc, TEST_PASSWORD).is_ok());

    // Unlock with wrong password
    assert!(custom_keychain::lock(&kc).is_ok());
    let result = custom_keychain::unlock(&mut kc, "wrong-password");
    assert!(
        matches!(result, Err(Error::PasswordWrong)),
        "Expected PasswordWrong, got: {:?}",
        result
    );

    cleanup_keychain(&path);
}

#[test]
fn test_set_get_delete_flow() {
    let (path, mut kc) = create_test_keychain();
    let _ = custom_keychain::unlock(&mut kc, TEST_PASSWORD);

    let store = KeychainStore::new_v3(kc);

    // Set
    store
        .set("test:key1", "sk-secret-value-123", KeyKind::Runtime, false)
        .expect("set should succeed");

    // Get
    let (value, kind) = store.get("test:key1").expect("get should succeed");
    assert_eq!(&*value, "sk-secret-value-123");
    assert_eq!(kind, KeyKind::Runtime);

    // Exists
    assert!(store.exists("test:key1").unwrap());
    assert!(!store.exists("test:nonexistent").unwrap());

    // Delete
    store.delete("test:key1").expect("delete should succeed");
    assert!(!store.exists("test:key1").unwrap());

    cleanup_keychain(&path);
}

#[test]
fn test_set_duplicate_rejected() {
    let (path, mut kc) = create_test_keychain();
    let _ = custom_keychain::unlock(&mut kc, TEST_PASSWORD);

    let store = KeychainStore::new_v3(kc);

    store
        .set("test:dup", "value1", KeyKind::Runtime, false)
        .unwrap();

    let result = store.set("test:dup", "value2", KeyKind::Runtime, false);
    assert!(matches!(result, Err(Error::KeyAlreadyExists { .. })));

    cleanup_keychain(&path);
}

#[test]
fn test_set_force_overwrite() {
    let (path, mut kc) = create_test_keychain();
    let _ = custom_keychain::unlock(&mut kc, TEST_PASSWORD);

    let store = KeychainStore::new_v3(kc);

    store
        .set("test:force", "old-value", KeyKind::Runtime, false)
        .unwrap();
    store
        .set("test:force", "new-value", KeyKind::Runtime, true)
        .unwrap();

    let (value, _) = store.get("test:force").unwrap();
    assert_eq!(&*value, "new-value");

    cleanup_keychain(&path);
}

#[test]
fn test_list_keys() {
    let (path, mut kc) = create_test_keychain();
    let _ = custom_keychain::unlock(&mut kc, TEST_PASSWORD);

    let store = KeychainStore::new_v3(kc);

    // Empty list
    let entries = store.list(false).unwrap();
    assert!(entries.is_empty());

    // Add keys
    store
        .set("alpha:key", "v1", KeyKind::Runtime, false)
        .unwrap();
    store
        .set("beta:key", "v2", KeyKind::Admin, false)
        .unwrap();

    // List without admin
    let entries = store.list(false).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].name, "alpha:key");

    // List with admin
    let entries = store.list(true).unwrap();
    assert_eq!(entries.len(), 2);

    cleanup_keychain(&path);
}

#[test]
fn test_admin_key_storage() {
    let (path, mut kc) = create_test_keychain();
    let _ = custom_keychain::unlock(&mut kc, TEST_PASSWORD);

    let store = KeychainStore::new_v3(kc);

    store
        .set("openai:admin", "sk-admin-secret", KeyKind::Admin, false)
        .unwrap();

    let (value, kind) = store.get("openai:admin").unwrap();
    assert_eq!(&*value, "sk-admin-secret");
    assert_eq!(kind, KeyKind::Admin);

    cleanup_keychain(&path);
}

#[test]
fn test_search_list_isolation() {
    let (path, kc) = create_test_keychain();

    // Verify our keychain is NOT in the search list (I1)
    let in_list = custom_keychain::is_in_search_list(&kc).unwrap();
    assert!(
        !in_list,
        "Test keychain should NOT be in search list (I1 violation)"
    );

    cleanup_keychain(&path);
}

#[test]
fn test_disable_user_interaction_guard_prevents_dialog() {
    // Verify that the guard works and doesn't panic
    let guard = custom_keychain::disable_user_interaction();
    assert!(guard.is_ok());

    // While guard is held, user interaction should be disallowed
    let allowed = SecKeychain::user_interaction_allowed().unwrap_or(true);
    assert!(!allowed, "User interaction should be disabled while guard is held");

    // Drop guard — interaction re-enabled
    drop(guard.unwrap());

    let allowed = SecKeychain::user_interaction_allowed().unwrap_or(false);
    assert!(allowed, "User interaction should be re-enabled after guard drop");
}

// ── Tier 3: Integration tests (manual, #[ignore]) ──────────────

#[test]
#[ignore]
fn test_acl_blocks_other_process() {
    // This test requires manual setup:
    // 1. Build lkr binary
    // 2. Run `lkr init` + `lkr set test:acl-check value`
    // 3. Try to read the key from a different binary (e.g. /usr/bin/security)
    // Expected: -25308 (errSecInteractionNotAllowed) from the other binary
    eprintln!("Manual test: ACL blocks non-lkr processes");
    eprintln!("  1. lkr init && lkr set test:acl sk-test-value");
    eprintln!("  2. security find-generic-password -s com.llm-key-ring -a test:acl -w");
    eprintln!("  Expected: security: SecKeychainSearchCopyNext: The specified item could not be found");
}

#[test]
#[ignore]
fn test_cdhash_mismatch_triggers_harden_guidance() {
    // This test requires manual setup:
    // 1. Build lkr, run init + set
    // 2. Rebuild lkr (changes cdhash)
    // 3. Try `lkr get` — should get -25308 + harden guidance
    // 4. Run `lkr harden` — should fix
    // 5. `lkr get` should succeed
    eprintln!("Manual test: cdhash mismatch → harden");
    eprintln!("  1. cargo install --path crates/lkr-cli && lkr init && lkr set test:cd sk-value");
    eprintln!("  2. cargo install --path crates/lkr-cli  # rebuild changes cdhash");
    eprintln!("  3. lkr get test:cd  # expect error + harden guidance");
    eprintln!("  4. lkr harden");
    eprintln!("  5. lkr get test:cd  # should succeed");
}
