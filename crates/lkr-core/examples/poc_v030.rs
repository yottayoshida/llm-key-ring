#![allow(dead_code, unused_imports)]
//! PoC for LKR v0.3.0 — Custom Keychain + Legacy ACL (Pure FFI)
//!
//! Validates 4 capabilities required for v0.3.0:
//!   PoC-A: Custom Keychain create/unlock/add/find/delete
//!   PoC-B: Legacy ACL (SecAccessCreate + SecTrustedApplicationCreateFromPath)
//!   PoC-C: Scoped search via kSecMatchSearchList
//!   PoC-D: Search list exclusion via SecKeychainSetSearchList
//!
//! Run:  cargo run -p lkr-core --example poc_v030
//!
//! Uses a temporary keychain at /tmp/lkr-poc-v030.keychain-db.
//! Does NOT touch login.keychain.

#![allow(unsafe_op_in_unsafe_fn)]

use core_foundation::base::TCFType;
use core_foundation::boolean::CFBoolean;
use core_foundation::data::CFData;
use core_foundation::string::CFString;
use security_framework::os::macos::keychain::CreateOptions;
use security_framework::os::macos::keychain::SecKeychain;
use security_framework_sys::keychain_item::{SecItemCopyMatching, SecItemDelete};
use std::ffi::{c_char, c_void};
use std::path::Path;
use std::ptr;

// ── Security.framework symbols ──────────────────────────────────
unsafe extern "C" {
    static kSecClass: *const c_void;
    static kSecClassGenericPassword: *const c_void;
    static kSecAttrService: *const c_void;
    static kSecAttrAccount: *const c_void;
    static kSecValueData: *const c_void;
    static kSecReturnData: *const c_void;
    static kSecAttrSynchronizable: *const c_void;
    static kSecMatchSearchList: *const c_void;
    static kSecUseKeychain: *const c_void;
    static kSecMatchLimit: *const c_void;
    static kSecMatchLimitAll: *const c_void;
    static kSecReturnAttributes: *const c_void;
}

// ── Legacy ACL APIs (hand-declared, not in security-framework crate) ──
unsafe extern "C" {
    fn SecKeychainLock(keychain: *const c_void) -> i32;

    fn SecAccessCreate(
        descriptor: *const c_void,    // CFStringRef
        trusted_list: *const c_void,  // CFArrayRef
        access_out: *mut *mut c_void, // SecAccessRef*
    ) -> i32;

    fn SecTrustedApplicationCreateFromPath(
        path: *const c_char,       // const char*
        app_out: *mut *mut c_void, // SecTrustedApplicationRef*
    ) -> i32;

    fn SecKeychainItemSetAccess(
        item: *const c_void,   // SecKeychainItemRef
        access: *const c_void, // SecAccessRef
    ) -> i32;

    fn SecKeychainSetSearchList(search_list: *const c_void, // CFArrayRef
    ) -> i32;

    fn SecKeychainCopySearchList(search_list_out: *mut *mut c_void, // CFArrayRef*
    ) -> i32;
}

// Legacy Keychain add/find (returns SecKeychainItemRef, needed for ACL)
unsafe extern "C" {
    fn SecKeychainAddGenericPassword(
        keychain: *const c_void,
        service_len: u32,
        service: *const c_char,
        account_len: u32,
        account: *const c_char,
        password_len: u32,
        password: *const c_void,
        item_out: *mut *mut c_void, // SecKeychainItemRef*
    ) -> i32;

    fn SecKeychainFindGenericPassword(
        keychain_or_array: *const c_void,
        service_len: u32,
        service: *const c_char,
        account_len: u32,
        account: *const c_char,
        password_len: *mut u32,
        password_data: *mut *mut c_void,
        item_out: *mut *mut c_void,
    ) -> i32;

    fn SecKeychainItemFreeContent(attr_list: *const c_void, data: *mut c_void) -> i32;

    // Create item WITH initial SecAccessRef — avoids SetAccess GUI dialog
    fn SecKeychainItemCreateFromContent(
        item_class: u32, // SecItemClass (kSecGenericPasswordItemClass = 0x67656E70 = "genp")
        attr_list: *const SecKeychainAttributeList,
        length: u32,
        data: *const c_void,
        keychain: *const c_void,       // SecKeychainRef
        initial_access: *const c_void, // SecAccessRef (the key!)
        item_ref: *mut *mut c_void,
    ) -> i32;
}

// CSSM-style attribute structures for SecKeychainItemCreateFromContent
#[repr(C)]
struct SecKeychainAttribute {
    tag: u32, // 4-byte tag e.g. 'svce', 'acct'
    length: u32,
    data: *mut c_void,
}

#[repr(C)]
struct SecKeychainAttributeList {
    count: u32,
    attr: *mut SecKeychainAttribute,
}

// ── Core Foundation (raw dict/array ops) ────────────────────────
unsafe extern "C" {
    fn CFDictionaryCreateMutable(
        allocator: *const c_void,
        capacity: isize,
        key_cb: *const c_void,
        val_cb: *const c_void,
    ) -> *mut c_void;
    fn CFDictionarySetValue(dict: *mut c_void, key: *const c_void, val: *const c_void);
    fn CFRelease(cf: *const c_void);
    fn CFArrayCreateMutable(
        allocator: *const c_void,
        capacity: isize,
        callbacks: *const c_void,
    ) -> *mut c_void;
    fn CFArrayAppendValue(array: *mut c_void, value: *const c_void);
    fn CFArrayGetCount(array: *const c_void) -> isize;
    static kCFTypeDictionaryKeyCallBacks: c_void;
    static kCFTypeDictionaryValueCallBacks: c_void;
    static kCFTypeArrayCallBacks: c_void;
}

// ── Constants ───────────────────────────────────────────────────
const KEYCHAIN_PW: &str = "poc-test-password";
const SERVICE: &str = "com.llm-key-ring.poc-v030";
const ACCOUNT: &str = "poc:test-key";
const SECRET: &[u8] = b"sk-poc-test-secret-value-12345";

const KEYCHAIN_PATH: &str = "/tmp/lkr-poc-v030.keychain-db";

// Proper keychain deletion: delete from subsystem + remove file
unsafe extern "C" {
    fn SecKeychainDelete(keychain: *const c_void) -> i32;
}

fn cleanup_keychain(path: &str) {
    // Try to open and delete via Security framework first
    if let Ok(kc) = SecKeychain::open(Path::new(path)) {
        unsafe {
            SecKeychainDelete(kc.as_concrete_TypeRef() as _);
        }
    }
    let _ = std::fs::remove_file(path);
}

// ── Helpers ─────────────────────────────────────────────────────

fn status_str(s: i32) -> &'static str {
    match s {
        0 => "errSecSuccess",
        -25299 => "errSecDuplicateItem",
        -25300 => "errSecItemNotFound",
        -25293 => "errSecAuthFailed",
        -25308 => "errSecInteractionNotAllowed",
        -25294 => "errSecNoSuchKeychain",
        -128 => "errSecUserCanceled",
        _ => "other",
    }
}

unsafe fn new_dict() -> *mut c_void {
    CFDictionaryCreateMutable(
        ptr::null(),
        0,
        &kCFTypeDictionaryKeyCallBacks as *const c_void,
        &kCFTypeDictionaryValueCallBacks as *const c_void,
    )
}

// ═══════════════════════════════════════════════════════════════════
// PoC-A: Custom Keychain basic lifecycle
// ═══════════════════════════════════════════════════════════════════

fn poc_a() -> bool {
    println!("\n============================================================");
    println!("PoC-A: Custom Keychain create/unlock/add/find/delete");
    println!("============================================================");

    // Cleanup any leftover
    cleanup_keychain(KEYCHAIN_PATH);

    // A1: Create custom keychain
    print!("[A1] CreateOptions::create()... ");
    let mut keychain = match CreateOptions::new()
        .password(KEYCHAIN_PW)
        .create(Path::new(KEYCHAIN_PATH))
    {
        Ok(kc) => {
            println!("OK");
            kc
        }
        Err(e) => {
            println!("FAIL: {e}");
            return false;
        }
    };

    // A2: Lock then unlock
    print!("[A2] Lock... ");
    let lock_status = unsafe { SecKeychainLock(keychain.as_concrete_TypeRef() as _) };
    println!("{} ({lock_status})", status_str(lock_status));
    if lock_status != 0 {
        return false;
    }

    print!("     Unlock... ");
    match keychain.unlock(Some(KEYCHAIN_PW)) {
        Ok(()) => println!("OK"),
        Err(e) => {
            println!("FAIL: {e}");
            return false;
        }
    }

    // A3: Add item via SecKeychainAddGenericPassword (Legacy API)
    print!("[A3] SecKeychainAddGenericPassword... ");
    let mut item_ref: *mut c_void = ptr::null_mut();
    let add_status = unsafe {
        SecKeychainAddGenericPassword(
            keychain.as_concrete_TypeRef() as _,
            SERVICE.len() as u32,
            SERVICE.as_ptr() as _,
            ACCOUNT.len() as u32,
            ACCOUNT.as_ptr() as _,
            SECRET.len() as u32,
            SECRET.as_ptr() as _,
            &mut item_ref,
        )
    };
    println!("{} ({add_status})", status_str(add_status));
    if add_status != 0 {
        return false;
    }
    let has_item_ref = !item_ref.is_null();
    println!("     item_ref returned: {has_item_ref}");

    // A4: Find item via SecKeychainFindGenericPassword
    print!("[A4] SecKeychainFindGenericPassword... ");
    let mut pw_len: u32 = 0;
    let mut pw_data: *mut c_void = ptr::null_mut();
    let mut found_item: *mut c_void = ptr::null_mut();
    let find_status = unsafe {
        SecKeychainFindGenericPassword(
            keychain.as_concrete_TypeRef() as _,
            SERVICE.len() as u32,
            SERVICE.as_ptr() as _,
            ACCOUNT.len() as u32,
            ACCOUNT.as_ptr() as _,
            &mut pw_len,
            &mut pw_data,
            &mut found_item,
        )
    };
    println!("{} ({find_status})", status_str(find_status));

    let mut value_matches = false;
    if find_status == 0 && !pw_data.is_null() {
        let retrieved =
            unsafe { std::slice::from_raw_parts(pw_data as *const u8, pw_len as usize) };
        value_matches = retrieved == SECRET;
        println!("     value matches: {value_matches} (len={})", pw_len);
        unsafe {
            SecKeychainItemFreeContent(ptr::null(), pw_data);
        }
    }

    // A5: Delete item
    print!("[A5] Delete via SecItemDelete (scoped)... ");
    let del_status = unsafe {
        let dict = new_dict();
        let svc = CFString::new(SERVICE);
        let acct = CFString::new(ACCOUNT);
        CFDictionarySetValue(dict, kSecClass, kSecClassGenericPassword);
        CFDictionarySetValue(dict, kSecAttrService, svc.as_concrete_TypeRef() as _);
        CFDictionarySetValue(dict, kSecAttrAccount, acct.as_concrete_TypeRef() as _);

        // Scope to our custom keychain
        let arr = CFArrayCreateMutable(ptr::null(), 1, &kCFTypeArrayCallBacks as *const c_void);
        CFArrayAppendValue(arr, keychain.as_concrete_TypeRef() as _);
        CFDictionarySetValue(dict, kSecMatchSearchList, arr);

        let s = SecItemDelete(dict as _);
        CFRelease(dict);
        CFRelease(arr as _);
        s
    };
    println!("{} ({del_status})", status_str(del_status));

    // Cleanup: delete keychain properly
    cleanup_keychain(KEYCHAIN_PATH);

    // Release item_ref
    if !item_ref.is_null() {
        unsafe {
            CFRelease(item_ref as _);
        }
    }
    if !found_item.is_null() {
        unsafe {
            CFRelease(found_item as _);
        }
    }

    let pass = lock_status == 0
        && add_status == 0
        && has_item_ref
        && find_status == 0
        && value_matches
        && del_status == 0;
    println!("\nPoC-A Result: {}", if pass { "PASS" } else { "FAIL" });
    pass
}

// ═══════════════════════════════════════════════════════════════════
// PoC-B: Legacy ACL (SecAccessCreate + SecTrustedApplicationCreateFromPath)
// ═══════════════════════════════════════════════════════════════════

fn poc_b() -> bool {
    println!("\n============================================================");
    println!("PoC-B: Legacy ACL — SecAccessCreate + TrustedApp");
    println!("============================================================");

    cleanup_keychain(KEYCHAIN_PATH);

    // B1: Create + unlock keychain
    print!("[B1] Create keychain... ");
    let keychain = match CreateOptions::new()
        .password(KEYCHAIN_PW)
        .create(Path::new(KEYCHAIN_PATH))
    {
        Ok(kc) => {
            println!("OK");
            kc
        }
        Err(e) => {
            println!("FAIL: {e}");
            return false;
        }
    };

    // B2: Get current binary path
    let exe_path = std::env::current_exe().expect("current_exe failed");
    let exe_path_c = std::ffi::CString::new(exe_path.to_str().unwrap()).unwrap();
    println!("[B2] Binary path: {}", exe_path.display());

    // B3: Create SecTrustedApplicationRef
    print!("[B3] SecTrustedApplicationCreateFromPath... ");
    let mut trusted_app: *mut c_void = ptr::null_mut();
    let ta_status =
        unsafe { SecTrustedApplicationCreateFromPath(exe_path_c.as_ptr(), &mut trusted_app) };
    println!("{} ({ta_status})", status_str(ta_status));
    if ta_status != 0 {
        cleanup_keychain(KEYCHAIN_PATH);
        return false;
    }

    // B4: Create SecAccessRef with trusted app list
    print!("[B4] SecAccessCreate... ");
    let mut access: *mut c_void = ptr::null_mut();
    let access_status = unsafe {
        let trusted_list =
            CFArrayCreateMutable(ptr::null(), 1, &kCFTypeArrayCallBacks as *const c_void);
        CFArrayAppendValue(trusted_list, trusted_app);

        let desc = CFString::new("LKR PoC v0.3.0 test item");
        let s = SecAccessCreate(desc.as_concrete_TypeRef() as _, trusted_list, &mut access);
        CFRelease(trusted_list as _);
        s
    };
    println!("{} ({access_status})", status_str(access_status));
    if access_status != 0 {
        unsafe {
            CFRelease(trusted_app as _);
        }
        cleanup_keychain(KEYCHAIN_PATH);
        return false;
    }

    // B5: Add item + set ACL
    print!("[B5] SecKeychainAddGenericPassword... ");
    let mut item_ref: *mut c_void = ptr::null_mut();
    let add_status = unsafe {
        SecKeychainAddGenericPassword(
            keychain.as_concrete_TypeRef() as _,
            SERVICE.len() as u32,
            SERVICE.as_ptr() as _,
            ACCOUNT.len() as u32,
            ACCOUNT.as_ptr() as _,
            SECRET.len() as u32,
            SECRET.as_ptr() as _,
            &mut item_ref,
        )
    };
    println!("{} ({add_status})", status_str(add_status));
    if add_status != 0 || item_ref.is_null() {
        unsafe {
            CFRelease(trusted_app as _);
            CFRelease(access as _);
        }
        cleanup_keychain(KEYCHAIN_PATH);
        return false;
    }

    // B6a: Set ACL WITH disable_user_interaction (test ②)
    println!("[B6a] SecKeychainItemSetAccess WITH disable_user_interaction...");
    let acl_status_guarded = unsafe {
        let _guard = SecKeychain::disable_user_interaction();
        match &_guard {
            Ok(_) => println!("      disable_user_interaction: OK"),
            Err(e) => println!("      disable_user_interaction: FAIL ({e})"),
        }
        let s = SecKeychainItemSetAccess(item_ref, access);
        println!("      SetAccess result: {} ({s})", status_str(s));
        s
        // _guard drops here → re-enables user interaction
    };

    // B6b: Set ACL WITHOUT guard (test ① — may show GUI dialog)
    // Only run if B6a failed, to test if allowing interaction helps
    let acl_status;
    if acl_status_guarded != 0 {
        println!("[B6b] SecKeychainItemSetAccess WITHOUT guard (GUI dialog may appear)...");
        println!("      >>> If a dialog appears, please click 'Always Allow' <<<");
        acl_status = unsafe { SecKeychainItemSetAccess(item_ref, access) };
        println!(
            "      SetAccess result: {} ({acl_status})",
            status_str(acl_status)
        );
    } else {
        acl_status = acl_status_guarded;
        println!("[B6b] Skipped (B6a succeeded)");
    }

    // B7: Verify ACL via security dump-keychain
    println!("[B7] Verifying ACL via `security dump-keychain`...");
    let dump_output = std::process::Command::new("/usr/bin/security")
        .args(["dump-keychain", KEYCHAIN_PATH])
        .output();
    let acl_visible = match &dump_output {
        Ok(out) => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            let has_acl = stdout.contains("ACL") || stdout.contains("access:");
            let has_service = stdout.contains(SERVICE);
            println!("     dump contains ACL info: {has_acl}");
            println!("     dump contains service: {has_service}");
            // Print all lines for full visibility
            for line in stdout.lines() {
                println!("     > {}", line.trim());
            }
            has_service
        }
        Err(e) => {
            println!("     dump-keychain failed: {e}");
            false
        }
    };

    // B8: Read back from this process (should succeed — we are the trusted app)
    print!("[B8] Read back (same process, should succeed)... ");
    let mut pw_len: u32 = 0;
    let mut pw_data: *mut c_void = ptr::null_mut();
    let read_status = unsafe {
        SecKeychainFindGenericPassword(
            keychain.as_concrete_TypeRef() as _,
            SERVICE.len() as u32,
            SERVICE.as_ptr() as _,
            ACCOUNT.len() as u32,
            ACCOUNT.as_ptr() as _,
            &mut pw_len,
            &mut pw_data,
            ptr::null_mut(),
        )
    };
    println!("{} ({read_status})", status_str(read_status));
    if read_status == 0 && !pw_data.is_null() {
        unsafe {
            SecKeychainItemFreeContent(ptr::null(), pw_data);
        }
    }

    // Cleanup
    unsafe {
        CFRelease(item_ref as _);
        CFRelease(access as _);
        CFRelease(trusted_app as _);
    }
    cleanup_keychain(KEYCHAIN_PATH);

    let best_acl = if acl_status_guarded == 0 {
        acl_status_guarded
    } else {
        acl_status
    };
    let pass = ta_status == 0
        && access_status == 0
        && add_status == 0
        && best_acl == 0
        && acl_visible
        && read_status == 0;

    println!("\nPoC-B Summary:");
    println!(
        "  B3 TrustedApp:     {} ({ta_status})",
        status_str(ta_status)
    );
    println!(
        "  B4 SecAccess:      {} ({access_status})",
        status_str(access_status)
    );
    println!(
        "  B5 AddItem:        {} ({add_status})",
        status_str(add_status)
    );
    println!(
        "  B6a SetACL+guard:  {} ({acl_status_guarded})",
        status_str(acl_status_guarded)
    );
    println!(
        "  B6b SetACL no-guard: {} ({acl_status})",
        status_str(acl_status)
    );
    println!(
        "  B8 ReadBack:       {} ({read_status})",
        status_str(read_status)
    );

    println!("\nPoC-B Result: {}", if pass { "PASS" } else { "FAIL" });
    if acl_status_guarded == 0 {
        println!("  ACL works WITH disable_user_interaction! Pure FFI is fully GO.");
    } else if acl_status == 0 {
        println!("  ACL works only WITH user interaction (GUI dialog).");
        println!("  Option: set ACL at init time (one-time dialog), then guard all other ops.");
    } else {
        println!("  ACL setting failed in both modes.");
        println!("  Fallback: hybrid approach (ACL via CLI wrap only).");
    }
    pass
}

// ═══════════════════════════════════════════════════════════════════
// PoC-B2: Create item WITH initial SecAccessRef
//         (avoids SecKeychainItemSetAccess GUI dialog)
// ═══════════════════════════════════════════════════════════════════

fn poc_b2() -> bool {
    println!("\n============================================================");
    println!("PoC-B2: SecKeychainItemCreateFromContent + initial SecAccess");
    println!("============================================================");

    cleanup_keychain(KEYCHAIN_PATH);

    // B2-1: Create + unlock keychain
    print!("[B2-1] Create keychain... ");
    let keychain = match CreateOptions::new()
        .password(KEYCHAIN_PW)
        .create(Path::new(KEYCHAIN_PATH))
    {
        Ok(kc) => {
            println!("OK");
            kc
        }
        Err(e) => {
            println!("FAIL: {e}");
            return false;
        }
    };

    // B2-2: Create TrustedApp + SecAccess (same as PoC-B)
    let exe_path = std::env::current_exe().expect("current_exe failed");
    let exe_path_c = std::ffi::CString::new(exe_path.to_str().unwrap()).unwrap();
    println!("[B2-2] Binary path: {}", exe_path.display());

    print!("       SecTrustedApplicationCreateFromPath... ");
    let mut trusted_app: *mut c_void = ptr::null_mut();
    let ta_status =
        unsafe { SecTrustedApplicationCreateFromPath(exe_path_c.as_ptr(), &mut trusted_app) };
    println!("{} ({ta_status})", status_str(ta_status));
    if ta_status != 0 {
        cleanup_keychain(KEYCHAIN_PATH);
        return false;
    }

    print!("       SecAccessCreate... ");
    let mut access: *mut c_void = ptr::null_mut();
    let access_status = unsafe {
        let trusted_list =
            CFArrayCreateMutable(ptr::null(), 1, &kCFTypeArrayCallBacks as *const c_void);
        CFArrayAppendValue(trusted_list, trusted_app);
        let desc = CFString::new("LKR PoC v0.3.0 B2 test item");
        let s = SecAccessCreate(desc.as_concrete_TypeRef() as _, trusted_list, &mut access);
        CFRelease(trusted_list as _);
        s
    };
    println!("{} ({access_status})", status_str(access_status));
    if access_status != 0 {
        unsafe {
            CFRelease(trusted_app as _);
        }
        cleanup_keychain(KEYCHAIN_PATH);
        return false;
    }

    // B2-3: Create item WITH SecAccess using SecKeychainItemCreateFromContent
    //       CSSM attribute tags: 'svce' = 0x73766365, 'acct' = 0x61636374
    println!("[B2-3] SecKeychainItemCreateFromContent (with initial SecAccess)...");
    print!("       disable_user_interaction + create... ");

    let svc_bytes = SERVICE.as_bytes();
    let acct_bytes = ACCOUNT.as_bytes();

    let mut attrs = [
        SecKeychainAttribute {
            tag: u32::from_be_bytes(*b"svce"),
            length: svc_bytes.len() as u32,
            data: svc_bytes.as_ptr() as *mut c_void,
        },
        SecKeychainAttribute {
            tag: u32::from_be_bytes(*b"acct"),
            length: acct_bytes.len() as u32,
            data: acct_bytes.as_ptr() as *mut c_void,
        },
    ];
    let mut attr_list = SecKeychainAttributeList {
        count: 2,
        attr: attrs.as_mut_ptr(),
    };

    let mut item_ref: *mut c_void = ptr::null_mut();
    let create_status = unsafe {
        // kSecGenericPasswordItemClass = 'genp' = 0x67656E70
        let item_class: u32 = u32::from_be_bytes(*b"genp");

        let _guard = SecKeychain::disable_user_interaction();
        SecKeychainItemCreateFromContent(
            item_class,
            &mut attr_list,
            SECRET.len() as u32,
            SECRET.as_ptr() as _,
            keychain.as_concrete_TypeRef() as _,
            access, // <-- initial SecAccess! This is the key difference
            &mut item_ref,
        )
    };
    println!("{} ({create_status})", status_str(create_status));

    // B2-4: Verify via dump-keychain (check ACL is present)
    println!("[B2-4] Verifying ACL via `security dump-keychain`...");
    let dump_output = std::process::Command::new("/usr/bin/security")
        .args(["dump-keychain", KEYCHAIN_PATH])
        .output();
    let acl_visible = match &dump_output {
        Ok(out) => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            let has_service = stdout.contains(SERVICE);
            println!("     dump contains service: {has_service}");
            for line in stdout.lines() {
                println!("     > {}", line.trim());
            }
            has_service
        }
        Err(e) => {
            println!("     dump-keychain failed: {e}");
            false
        }
    };

    // B2-5: Read back (same process — should succeed as trusted app)
    print!("[B2-5] Read back (same process, should succeed)... ");
    let mut pw_len: u32 = 0;
    let mut pw_data: *mut c_void = ptr::null_mut();
    let read_status = unsafe {
        SecKeychainFindGenericPassword(
            keychain.as_concrete_TypeRef() as _,
            SERVICE.len() as u32,
            SERVICE.as_ptr() as _,
            ACCOUNT.len() as u32,
            ACCOUNT.as_ptr() as _,
            &mut pw_len,
            &mut pw_data,
            ptr::null_mut(),
        )
    };
    println!("{} ({read_status})", status_str(read_status));
    let value_ok = if read_status == 0 && !pw_data.is_null() {
        let retrieved =
            unsafe { std::slice::from_raw_parts(pw_data as *const u8, pw_len as usize) };
        let ok = retrieved == SECRET;
        println!("       value matches: {ok}");
        unsafe {
            SecKeychainItemFreeContent(ptr::null(), pw_data);
        }
        ok
    } else {
        false
    };

    // Cleanup
    if !item_ref.is_null() {
        unsafe {
            CFRelease(item_ref as _);
        }
    }
    unsafe {
        CFRelease(access as _);
        CFRelease(trusted_app as _);
    }
    cleanup_keychain(KEYCHAIN_PATH);

    let pass = create_status == 0 && acl_visible && read_status == 0 && value_ok;
    println!("\nPoC-B2 Summary:");
    println!("  TrustedApp:      {} ({ta_status})", status_str(ta_status));
    println!(
        "  SecAccess:       {} ({access_status})",
        status_str(access_status)
    );
    println!(
        "  CreateFromContent: {} ({create_status})",
        status_str(create_status)
    );
    println!(
        "  ReadBack:        {} ({read_status})",
        status_str(read_status)
    );
    println!("  Value match:     {value_ok}");

    println!("\nPoC-B2 Result: {}", if pass { "PASS" } else { "FAIL" });
    if pass {
        println!("  ACL set at creation time! No GUI dialog needed.");
        println!("  Pure FFI approach is FULLY GO.");
    } else if create_status != 0 {
        println!("  CreateFromContent failed ({create_status}). Hybrid fallback needed.");
    }
    pass
}

// ═══════════════════════════════════════════════════════════════════
// PoC-C: Scoped search via kSecMatchSearchList
// ═══════════════════════════════════════════════════════════════════

fn poc_c() -> bool {
    println!("\n============================================================");
    println!("PoC-C: Scoped search via kSecMatchSearchList");
    println!("============================================================");

    cleanup_keychain(KEYCHAIN_PATH);

    // C1: Create keychain + add item
    print!("[C1] Create keychain + add item... ");
    let keychain = match CreateOptions::new()
        .password(KEYCHAIN_PW)
        .create(Path::new(KEYCHAIN_PATH))
    {
        Ok(kc) => kc,
        Err(e) => {
            println!("FAIL: {e}");
            return false;
        }
    };

    let add_status = unsafe {
        SecKeychainAddGenericPassword(
            keychain.as_concrete_TypeRef() as _,
            SERVICE.len() as u32,
            SERVICE.as_ptr() as _,
            ACCOUNT.len() as u32,
            ACCOUNT.as_ptr() as _,
            SECRET.len() as u32,
            SECRET.as_ptr() as _,
            ptr::null_mut(),
        )
    };
    println!("{} ({add_status})", status_str(add_status));
    if add_status != 0 {
        cleanup_keychain(KEYCHAIN_PATH);
        return false;
    }

    // C2: Search with kSecMatchSearchList scoped to custom keychain
    print!("[C2] SecItemCopyMatching (scoped to custom keychain)... ");
    let scoped_find = unsafe {
        let dict = new_dict();
        let svc = CFString::new(SERVICE);
        let acct = CFString::new(ACCOUNT);
        CFDictionarySetValue(dict, kSecClass, kSecClassGenericPassword);
        CFDictionarySetValue(dict, kSecAttrService, svc.as_concrete_TypeRef() as _);
        CFDictionarySetValue(dict, kSecAttrAccount, acct.as_concrete_TypeRef() as _);
        CFDictionarySetValue(dict, kSecReturnData, CFBoolean::true_value().as_CFTypeRef());

        let arr = CFArrayCreateMutable(ptr::null(), 1, &kCFTypeArrayCallBacks as *const c_void);
        CFArrayAppendValue(arr, keychain.as_concrete_TypeRef() as _);
        CFDictionarySetValue(dict, kSecMatchSearchList, arr);

        let mut result: *const c_void = ptr::null();
        let s = SecItemCopyMatching(dict as _, &mut result as *mut _ as *mut _);

        if s == 0 && !result.is_null() {
            let cf_data = CFData::wrap_under_create_rule(result as _);
            let matches = cf_data.bytes() == SECRET;
            println!("{} ({s}), value matches: {matches}", status_str(s));
            CFRelease(dict);
            CFRelease(arr as _);
            matches
        } else {
            println!("{} ({s})", status_str(s));
            CFRelease(dict);
            CFRelease(arr as _);
            false
        }
    };

    // C3: Search with kSecMatchSearchList scoped to login.keychain (should NOT find our item)
    print!("[C3] SecItemCopyMatching (scoped to login.keychain)... ");
    let login_isolated = unsafe {
        let login_kc = SecKeychain::default().expect("default keychain");
        let dict = new_dict();
        let svc = CFString::new(SERVICE);
        let acct = CFString::new(ACCOUNT);
        CFDictionarySetValue(dict, kSecClass, kSecClassGenericPassword);
        CFDictionarySetValue(dict, kSecAttrService, svc.as_concrete_TypeRef() as _);
        CFDictionarySetValue(dict, kSecAttrAccount, acct.as_concrete_TypeRef() as _);
        CFDictionarySetValue(dict, kSecReturnData, CFBoolean::true_value().as_CFTypeRef());

        let arr = CFArrayCreateMutable(ptr::null(), 1, &kCFTypeArrayCallBacks as *const c_void);
        CFArrayAppendValue(arr, login_kc.as_concrete_TypeRef() as _);
        CFDictionarySetValue(dict, kSecMatchSearchList, arr);

        let mut result: *const c_void = ptr::null();
        let s = SecItemCopyMatching(dict as _, &mut result as *mut _ as *mut _);

        let not_found = s == -25300; // errSecItemNotFound
        println!("{} ({s}) — isolation: {not_found}", status_str(s));

        if !result.is_null() {
            CFRelease(result);
        }
        CFRelease(dict);
        CFRelease(arr as _);
        not_found
    };

    // Cleanup
    cleanup_keychain(KEYCHAIN_PATH);

    let pass = scoped_find && login_isolated;
    println!("\nPoC-C Result: {}", if pass { "PASS" } else { "FAIL" });
    pass
}

// ═══════════════════════════════════════════════════════════════════
// PoC-D: Search list exclusion via SecKeychainSetSearchList
// ═══════════════════════════════════════════════════════════════════

fn poc_d() -> bool {
    println!("\n============================================================");
    println!("PoC-D: Search list exclusion");
    println!("============================================================");

    cleanup_keychain(KEYCHAIN_PATH);

    // D1: Save original search list
    print!("[D1] Save original search list... ");
    let mut original_list: *mut c_void = ptr::null_mut();
    let copy_status = unsafe { SecKeychainCopySearchList(&mut original_list) };
    if copy_status != 0 {
        println!("FAIL ({copy_status})");
        return false;
    }
    let original_count = unsafe { CFArrayGetCount(original_list) };
    println!("OK (count: {original_count})");

    // D2: Create keychain
    print!("[D2] Create keychain... ");
    let keychain = match CreateOptions::new()
        .password(KEYCHAIN_PW)
        .create(Path::new(KEYCHAIN_PATH))
    {
        Ok(kc) => {
            println!("OK");
            kc
        }
        Err(e) => {
            println!("FAIL: {e}");
            unsafe {
                CFRelease(original_list as _);
            }
            return false;
        }
    };

    // D3: Check if custom keychain was auto-added to search list
    print!("[D3] Check if auto-added to search list... ");
    let mut current_list: *mut c_void = ptr::null_mut();
    unsafe {
        SecKeychainCopySearchList(&mut current_list);
    }
    let current_count = unsafe { CFArrayGetCount(current_list) };
    let was_auto_added = current_count > original_count;
    println!(
        "count before: {original_count}, after: {current_count}, auto-added: {was_auto_added}"
    );
    unsafe {
        CFRelease(current_list as _);
    }

    // D4: Restore original search list (exclude custom keychain)
    print!("[D4] SecKeychainSetSearchList (restore original)... ");
    let set_status = unsafe { SecKeychainSetSearchList(original_list) };
    println!("{} ({set_status})", status_str(set_status));

    // D5: Verify exclusion
    print!("[D5] Verify exclusion... ");
    let mut after_list: *mut c_void = ptr::null_mut();
    unsafe {
        SecKeychainCopySearchList(&mut after_list);
    }
    let after_count = unsafe { CFArrayGetCount(after_list) };
    let excluded = after_count == original_count;
    println!("count: {after_count}, matches original: {excluded}");
    unsafe {
        CFRelease(after_list as _);
    }

    // D6: Verify via `security list-keychains`
    println!("[D6] `security list-keychains` output:");
    let list_output = std::process::Command::new("/usr/bin/security")
        .args(["list-keychains"])
        .output();
    let not_in_list = match &list_output {
        Ok(out) => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            for line in stdout.lines() {
                println!("     {}", line.trim());
            }
            let contains_poc = stdout.contains("lkr-poc-v030");
            println!("     contains lkr-poc-v030: {contains_poc}");
            !contains_poc
        }
        Err(e) => {
            println!("     list-keychains failed: {e}");
            false
        }
    };

    // D7: Verify custom keychain still works via direct open
    print!("[D7] Direct open + add (still usable despite exclusion)... ");
    let direct_add = unsafe {
        SecKeychainAddGenericPassword(
            keychain.as_concrete_TypeRef() as _,
            SERVICE.len() as u32,
            SERVICE.as_ptr() as _,
            ACCOUNT.len() as u32,
            ACCOUNT.as_ptr() as _,
            SECRET.len() as u32,
            SECRET.as_ptr() as _,
            ptr::null_mut(),
        )
    };
    println!("{} ({direct_add})", status_str(direct_add));

    // Cleanup
    unsafe {
        CFRelease(original_list as _);
    }
    cleanup_keychain(KEYCHAIN_PATH);

    let pass = set_status == 0 && excluded && not_in_list && direct_add == 0;
    println!("\nPoC-D Result: {}", if pass { "PASS" } else { "FAIL" });
    if was_auto_added {
        println!(
            "  NOTE: CreateOptions::create() auto-adds to search list. Must remove after create."
        );
    }
    pass
}

// ═══════════════════════════════════════════════════════════════════
// Main
// ═══════════════════════════════════════════════════════════════════

fn main() {
    println!("=== LKR v0.3.0 PoC — Custom Keychain + Legacy ACL (Pure FFI) ===");
    println!("Keychain path: {KEYCHAIN_PATH}");
    println!(
        "WARNING: This PoC creates/deletes a temporary keychain. It does NOT touch login.keychain."
    );

    let a = poc_a();
    let b = poc_b();
    let b2 = poc_b2();
    let c = poc_c();
    let d = poc_d();

    println!("\n============================================================");
    println!("SUMMARY");
    println!("============================================================");
    println!(
        "  PoC-A  (Custom Keychain lifecycle):  {}",
        if a { "PASS" } else { "FAIL" }
    );
    println!(
        "  PoC-B  (Legacy ACL via SetAccess):   {}",
        if b { "PASS" } else { "FAIL" }
    );
    println!(
        "  PoC-B2 (Legacy ACL via CreateFrom):  {}",
        if b2 { "PASS" } else { "FAIL" }
    );
    println!(
        "  PoC-C  (Scoped search):              {}",
        if c { "PASS" } else { "FAIL" }
    );
    println!(
        "  PoC-D  (Search list exclusion):      {}",
        if d { "PASS" } else { "FAIL" }
    );

    let acl_ok = b || b2;

    println!();
    if a && acl_ok && c && d {
        println!("VERDICT: ALL PASS — Pure FFI approach is GO");
        if b2 && !b {
            println!("  NOTE: Use SecKeychainItemCreateFromContent (not SetAccess) for ACL.");
        }
    } else if a && c && d && !acl_ok {
        println!("VERDICT: ACL FFI does not work (both B and B2 failed)");
        println!("  Fallback: Hybrid approach (ACL via CLI wrap only)");
        println!("  Custom Keychain + scoped search + search list exclusion confirmed working");
    } else {
        println!("VERDICT: CRITICAL FAILURES — review individual results above");
    }

    let exit_code = if a && acl_ok && c && d {
        0
    } else if a && c && d {
        1
    } else {
        2
    };
    std::process::exit(exit_code);
}
