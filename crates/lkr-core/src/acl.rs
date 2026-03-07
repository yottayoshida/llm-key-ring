//! Legacy ACL builder for LKR v0.3.0.
//!
//! Provides `build_access()` — creates a `SecAccessRef` that restricts
//! keychain item access to the LKR binary itself (Layer 2 defense).
//!
//! Uses Legacy ACL path: `SecTrustedApplicationCreateFromPath` +
//! `SecAccessCreate`. This does NOT require Apple Developer Program
//! membership or code-signing entitlements.

use crate::error::{Error, Result};
use security_framework::os::macos::keychain::SecKeychain;
use std::ffi::{CString, c_void};
use std::path::Path;

// ── Hand-declared Security.framework symbols ────────────────────
unsafe extern "C" {
    fn SecTrustedApplicationCreateFromPath(path: *const i8, app_out: *mut *mut c_void) -> i32;

    fn SecAccessCreate(
        descriptor: *const c_void,
        trusted_list: *const c_void,
        access_out: *mut *mut c_void,
    ) -> i32;

    fn SecKeychainItemCopyAccess(item_ref: *const c_void, access_out: *mut *mut c_void) -> i32;
}

// ── Core Foundation helpers ─────────────────────────────────────
unsafe extern "C" {
    fn CFArrayCreateMutable(
        allocator: *const c_void,
        capacity: isize,
        callbacks: *const c_void,
    ) -> *mut c_void;
    fn CFArrayAppendValue(array: *mut c_void, value: *const c_void);
    fn CFRelease(cf: *const c_void);
    fn CFStringCreateWithBytes(
        alloc: *const c_void,
        bytes: *const u8,
        num_bytes: isize,
        encoding: u32,
        is_external: bool,
    ) -> *mut c_void;
    static kCFTypeArrayCallBacks: c_void;
}

/// UTF-8 encoding constant for CFStringCreateWithBytes.
const K_CF_STRING_ENCODING_UTF8: u32 = 0x0800_0100;

/// Build a `SecAccessRef` that trusts only the given binary path (SR5/SR7).
///
/// The returned pointer is a retained CF object; the caller is responsible
/// for releasing it (or passing ownership to `SecKeychainItemCreateFromContent`).
///
/// # Arguments
/// * `lkr_binary_path` — absolute path to the LKR binary (e.g. from `std::env::current_exe()`)
///
/// # Safety
/// Returns a raw `*mut c_void` (SecAccessRef). Caller must manage CF lifecycle.
pub fn build_access(lkr_binary_path: &Path) -> Result<*mut c_void> {
    // SR5: Validate that the path exists and is a file
    if !lkr_binary_path.exists() {
        return Err(Error::Acl(format!(
            "Binary path does not exist: {}",
            lkr_binary_path.display()
        )));
    }
    if !lkr_binary_path.is_file() {
        return Err(Error::Acl(format!(
            "Binary path is not a file: {}",
            lkr_binary_path.display()
        )));
    }

    let path_cstr = CString::new(
        lkr_binary_path
            .to_str()
            .ok_or_else(|| Error::Acl("Binary path contains invalid UTF-8".into()))?,
    )
    .map_err(|e| Error::Acl(format!("Binary path contains NUL byte: {e}")))?;

    unsafe {
        // Step 1: Create a trusted application reference for the LKR binary
        let mut trusted_app: *mut c_void = std::ptr::null_mut();
        let ta_status = SecTrustedApplicationCreateFromPath(path_cstr.as_ptr(), &mut trusted_app);
        if ta_status != 0 {
            return Err(Error::Acl(format!(
                "SecTrustedApplicationCreateFromPath failed: OSStatus {ta_status}"
            )));
        }

        // Step 2: Build a CFArray containing only our trusted application
        let trusted_list =
            CFArrayCreateMutable(std::ptr::null(), 1, &kCFTypeArrayCallBacks as *const c_void);
        CFArrayAppendValue(trusted_list, trusted_app as _);

        // Step 3: Create the access descriptor string
        let desc = "LKR API Key Access";
        let cf_desc = CFStringCreateWithBytes(
            std::ptr::null(),
            desc.as_ptr(),
            desc.len() as isize,
            K_CF_STRING_ENCODING_UTF8,
            false,
        );

        // Step 4: Create the SecAccessRef
        let mut access: *mut c_void = std::ptr::null_mut();
        let access_status = SecAccessCreate(cf_desc, trusted_list as _, &mut access);

        // Cleanup intermediate objects
        CFRelease(cf_desc as _);
        CFRelease(trusted_list as _);
        CFRelease(trusted_app as _);

        if access_status != 0 {
            return Err(Error::Acl(format!(
                "SecAccessCreate failed: OSStatus {access_status}"
            )));
        }

        Ok(access)
    }
}

/// Diagnose whether a -25308 error is caused by ACL mismatch.
///
/// Attempts to read the ACL of the given keychain item.
/// If `SecKeychainItemCopyAccess` also returns -25308, it confirms
/// that the ACL is blocking access (Layer 2 defense is active).
///
/// Returns `true` if ACL mismatch is confirmed (harden candidate).
///
/// # Safety
/// `item_ref` must be a valid `SecKeychainItemRef` or null.
pub unsafe fn is_acl_blocked(item_ref: *const c_void) -> bool {
    if item_ref.is_null() {
        return false;
    }

    let _guard = SecKeychain::disable_user_interaction();

    unsafe {
        let mut access: *mut c_void = std::ptr::null_mut();
        let status = SecKeychainItemCopyAccess(item_ref, &mut access);

        if !access.is_null() {
            CFRelease(access as _);
        }

        // -25308 = errSecInteractionNotAllowed
        // If CopyAccess also gets -25308, the ACL is blocking us
        status == -25308
    }
}

/// Resolve the current LKR binary path for ACL creation.
///
/// Uses `std::env::current_exe()` and canonicalizes the result (SR7).
pub fn current_binary_path() -> Result<std::path::PathBuf> {
    std::env::current_exe()
        .and_then(|p| p.canonicalize())
        .map_err(|e| Error::Acl(format!("Failed to resolve current binary path: {e}")))
}

// ── Tier 1: Unit tests ─────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;

    // -- SR5: path validation --

    #[test]
    fn test_build_access_nonexistent_path() {
        let result = build_access(Path::new("/nonexistent/binary/lkr"));
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, Error::Acl(_)));
        assert!(err.to_string().contains("does not exist"));
    }

    #[test]
    fn test_build_access_directory_rejected() {
        // /tmp exists but is a directory, not a file
        let result = build_access(Path::new("/tmp"));
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not a file"));
    }

    #[test]
    fn test_build_access_real_binary() {
        // Use the test binary itself as a valid path
        let path = current_binary_path().unwrap();
        let result = build_access(&path);
        assert!(result.is_ok());
        // Cleanup: release the SecAccessRef
        let access = result.unwrap();
        if !access.is_null() {
            unsafe { CFRelease(access as _) };
        }
    }

    // -- SR5/I2: /usr/bin/security must never be trusted --

    #[test]
    fn test_build_access_security_binary_not_blocked_at_path_level() {
        // build_access() validates path existence/file, not path content.
        // I2 enforcement is at the caller level (KeychainStore::set).
        // /usr/bin/security exists and is a file, so build_access accepts it.
        // This test documents the design boundary.
        let security_path = Path::new("/usr/bin/security");
        if security_path.exists() {
            let result = build_access(security_path);
            // build_access succeeds — I2 is enforced elsewhere
            assert!(result.is_ok());
            let access = result.unwrap();
            if !access.is_null() {
                unsafe { CFRelease(access as _) };
            }
        }
    }

    // -- SR7: path canonicalization --

    #[test]
    fn test_current_binary_path_is_absolute() {
        let path = current_binary_path().unwrap();
        assert!(path.is_absolute());
    }

    #[test]
    fn test_current_binary_path_no_symlinks() {
        let path = current_binary_path().unwrap();
        // canonicalize() resolves symlinks, so the path should equal itself
        assert_eq!(path, path.canonicalize().unwrap());
    }

    // -- is_acl_blocked --

    #[test]
    fn test_is_acl_blocked_null_item() {
        assert!(unsafe { !is_acl_blocked(std::ptr::null()) });
    }
}
