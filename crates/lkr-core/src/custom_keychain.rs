//! Custom Keychain lifecycle management for LKR v0.3.0.
//!
//! Manages `lkr.keychain-db` — a dedicated keychain separate from login.keychain.
//! Provides create, open, unlock, lock, and search list isolation.

use crate::error::{Error, Result};
use core_foundation::base::TCFType;
use security_framework::os::macos::keychain::{CreateOptions, SecKeychain};
use std::ffi::c_void;
use std::path::PathBuf;

// ── Hand-declared Security.framework symbols ────────────────────
unsafe extern "C" {
    fn SecKeychainLock(keychain: *const c_void) -> i32;
    fn SecKeychainDelete(keychain: *const c_void) -> i32;
    fn SecKeychainCopySearchList(search_list_out: *mut *mut c_void) -> i32;
    fn SecKeychainSetSearchList(search_list: *const c_void) -> i32;
}

// ── Core Foundation helpers ─────────────────────────────────────
unsafe extern "C" {
    fn CFArrayGetCount(array: *const c_void) -> isize;
    fn CFArrayGetValueAtIndex(array: *const c_void, idx: isize) -> *const c_void;
    fn CFArrayCreateMutable(
        allocator: *const c_void,
        capacity: isize,
        callbacks: *const c_void,
    ) -> *mut c_void;
    fn CFArrayAppendValue(array: *mut c_void, value: *const c_void);
    fn CFRelease(cf: *const c_void);
    fn CFEqual(cf1: *const c_void, cf2: *const c_void) -> bool;
    static kCFTypeArrayCallBacks: c_void;
}

/// Default keychain filename.
const KEYCHAIN_FILENAME: &str = "lkr.keychain-db";

/// Auto-lock timeout in seconds (5 minutes).
const AUTO_LOCK_TIMEOUT_SECS: u32 = 300;

/// Resolved path to the custom keychain file.
pub fn keychain_path() -> PathBuf {
    dirs_next()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(KEYCHAIN_FILENAME)
}

/// Return `~/Library/Keychains/` on macOS.
fn dirs_next() -> Option<PathBuf> {
    home::home_dir().map(|h| h.join("Library").join("Keychains"))
}

/// Check whether the custom keychain file exists.
pub fn is_initialized() -> bool {
    keychain_path().exists()
}

/// Create a new custom keychain with the given password.
///
/// Also applies lock-on-sleep and auto-lock timeout settings,
/// then ensures the keychain is removed from the default search list (I1/SR9).
pub fn create(password: &str) -> Result<SecKeychain> {
    let path = keychain_path();
    if path.exists() {
        return Err(Error::Keychain(
            "Custom keychain already exists. Run `lkr lock` or use existing keychain.".into(),
        ));
    }

    let keychain = CreateOptions::new()
        .password(password)
        .create(path.as_path())
        .map_err(|e| Error::Keychain(format!("Failed to create custom keychain: {e}")))?;

    // Apply lock-on-sleep + auto-lock timeout
    apply_settings(&keychain)?;

    // Remove from search list (I1: lkr.keychain-db must never be in search list)
    ensure_not_in_search_list(&keychain)?;

    Ok(keychain)
}

/// Open an existing custom keychain.
pub fn open() -> Result<SecKeychain> {
    let path = keychain_path();
    if !path.exists() {
        return Err(Error::NotInitialized);
    }
    SecKeychain::open(path.as_path())
        .map_err(|e| Error::Keychain(format!("Failed to open custom keychain: {e}")))
}

/// Unlock the custom keychain with the given password.
pub fn unlock(keychain: &mut SecKeychain, password: &str) -> Result<()> {
    keychain
        .unlock(Some(password))
        .map_err(|e| {
            let code = e.code();
            match code {
                -25293 => Error::PasswordWrong,
                -25308 => Error::KeychainLocked, // interaction not allowed
                _ => Error::Keychain(format!("Failed to unlock: {e}")),
            }
        })
}

/// Lock the custom keychain.
pub fn lock(keychain: &SecKeychain) -> Result<()> {
    let status = unsafe { SecKeychainLock(keychain.as_concrete_TypeRef() as _) };
    if status != 0 {
        return Err(Error::Keychain(format!(
            "Failed to lock keychain: OSStatus {status}"
        )));
    }
    Ok(())
}

/// Delete the custom keychain (used by cleanup/reset).
pub fn delete(keychain: &SecKeychain) -> Result<()> {
    let status = unsafe { SecKeychainDelete(keychain.as_concrete_TypeRef() as _) };
    if status != 0 {
        return Err(Error::Keychain(format!(
            "Failed to delete keychain: OSStatus {status}"
        )));
    }
    Ok(())
}

/// Apply lock-on-sleep and auto-lock timeout settings.
fn apply_settings(_keychain: &SecKeychain) -> Result<()> {
    use security_framework::os::macos::keychain::KeychainSettings;

    let mut settings = KeychainSettings::new();
    settings.set_lock_on_sleep(true);
    settings.set_lock_interval(Some(AUTO_LOCK_TIMEOUT_SECS));

    // set_settings requires &mut, but we just created the keychain
    // so we clone the reference through a re-open
    let mut kc = SecKeychain::open(keychain_path().as_path())
        .map_err(|e| Error::Keychain(format!("Failed to reopen keychain for settings: {e}")))?;
    kc.set_settings(&settings)
        .map_err(|e| Error::Keychain(format!("Failed to apply keychain settings: {e}")))?;
    Ok(())
}

/// Ensure the custom keychain is NOT in the default search list (I1/SR9).
///
/// `CreateOptions::create()` may or may not auto-add the keychain to the search list
/// (PoC-D showed it does not on current macOS, but we verify defensively).
///
/// Saves the original search list, filters out our keychain, and restores.
pub fn ensure_not_in_search_list(keychain: &SecKeychain) -> Result<()> {
    unsafe {
        // Get current search list
        let mut search_list: *mut c_void = std::ptr::null_mut();
        let copy_status = SecKeychainCopySearchList(&mut search_list);
        if copy_status != 0 {
            return Err(Error::Keychain(format!(
                "SecKeychainCopySearchList failed: OSStatus {copy_status}"
            )));
        }

        let count = CFArrayGetCount(search_list);
        let our_ref = keychain.as_concrete_TypeRef() as *const c_void;

        // Check if our keychain is in the list
        let mut found = false;
        for i in 0..count {
            let item = CFArrayGetValueAtIndex(search_list, i);
            if CFEqual(item, our_ref) {
                found = true;
                break;
            }
        }

        if !found {
            // Not in search list — nothing to do
            CFRelease(search_list as _);
            return Ok(());
        }

        // Build new list without our keychain
        let new_list =
            CFArrayCreateMutable(std::ptr::null(), count, &kCFTypeArrayCallBacks as *const c_void);
        for i in 0..count {
            let item = CFArrayGetValueAtIndex(search_list, i);
            if !CFEqual(item, our_ref) {
                CFArrayAppendValue(new_list, item);
            }
        }

        // Apply filtered list
        let set_status = SecKeychainSetSearchList(new_list as _);
        CFRelease(new_list as _);
        CFRelease(search_list as _);

        if set_status != 0 {
            return Err(Error::Keychain(format!(
                "SecKeychainSetSearchList failed: OSStatus {set_status}"
            )));
        }

        // Verify (before/after — Codex②)
        let mut verify_list: *mut c_void = std::ptr::null_mut();
        let verify_status = SecKeychainCopySearchList(&mut verify_list);
        if verify_status == 0 {
            let verify_count = CFArrayGetCount(verify_list);
            for i in 0..verify_count {
                let item = CFArrayGetValueAtIndex(verify_list, i);
                if CFEqual(item, our_ref) {
                    CFRelease(verify_list as _);
                    return Err(Error::Keychain(
                        "Failed to remove custom keychain from search list (still present after set)"
                            .into(),
                    ));
                }
            }
            CFRelease(verify_list as _);
        }

        Ok(())
    }
}

/// Check if the custom keychain is in the search list (for SR9 validation).
/// Returns true if found (which is a violation of I1).
pub fn is_in_search_list(keychain: &SecKeychain) -> Result<bool> {
    unsafe {
        let mut search_list: *mut c_void = std::ptr::null_mut();
        let status = SecKeychainCopySearchList(&mut search_list);
        if status != 0 {
            return Err(Error::Keychain(format!(
                "SecKeychainCopySearchList failed: OSStatus {status}"
            )));
        }

        let count = CFArrayGetCount(search_list);
        let our_ref = keychain.as_concrete_TypeRef() as *const c_void;

        let mut found = false;
        for i in 0..count {
            let item = CFArrayGetValueAtIndex(search_list, i);
            if CFEqual(item, our_ref) {
                found = true;
                break;
            }
        }

        CFRelease(search_list as _);
        Ok(found)
    }
}

/// RAII guard that disables user interaction for the duration of its lifetime (SR12/I7).
///
/// Re-exported from `security-framework` crate. On drop, user interaction is re-enabled.
/// Use this before any Keychain operation to prevent macOS GUI dialogs.
pub fn disable_user_interaction(
) -> std::result::Result<security_framework::os::macos::keychain::KeychainUserInteractionLock, security_framework::base::Error>
{
    SecKeychain::disable_user_interaction()
}

// ── Tier 1: Unit tests ─────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;

    // -- Path construction --

    #[test]
    fn test_keychain_path_ends_with_filename() {
        let path = keychain_path();
        assert_eq!(
            path.file_name().unwrap().to_str().unwrap(),
            KEYCHAIN_FILENAME
        );
    }

    #[test]
    fn test_keychain_path_is_in_keychains_dir() {
        let path = keychain_path();
        let parent = path.parent().unwrap();
        assert!(
            parent.ends_with("Library/Keychains"),
            "Expected path under Library/Keychains, got: {}",
            parent.display()
        );
    }

    #[test]
    fn test_keychain_path_is_absolute() {
        let path = keychain_path();
        assert!(path.is_absolute());
    }

    #[test]
    fn test_keychain_filename_constant() {
        assert_eq!(KEYCHAIN_FILENAME, "lkr.keychain-db");
    }

    #[test]
    fn test_auto_lock_timeout() {
        assert_eq!(AUTO_LOCK_TIMEOUT_SECS, 300); // 5 minutes
    }

    // -- is_initialized depends on filesystem state --
    // (Tier 2 tests cover actual create/open/unlock cycles)

    // -- disable_user_interaction RAII guard --

    #[test]
    fn test_disable_user_interaction_guard() {
        // Verify the guard can be created and dropped without panic
        let guard = disable_user_interaction();
        assert!(guard.is_ok());
        drop(guard);
        // After drop, interaction should be re-enabled
        let allowed = SecKeychain::user_interaction_allowed();
        assert!(allowed.unwrap_or(true));
    }
}
