//! PoC: Verify `kSecAccessControlApplicationPassword` works with unsigned binary.
//!
//! This determines whether admin key ACL (Step 2 of v0.2.0) can proceed.
//! An unsigned binary (`cargo install`) cannot use Touch ID ACL, but
//! APPLICATION_PASSWORD (app-provided master password) might work.
//!
//! Run:  cargo run -p lkr-core --example poc_app_password
//!
//! Success criteria:
//!   1. Store with APPLICATION_PASSWORD ACL succeeds
//!   2. Retrieve with correct password succeeds
//!   3. Retrieve without auth context is BLOCKED
//!   4. Retrieve with wrong password is BLOCKED

// PoC-only: unsafe fn bodies treated as implicit unsafe scope
#![allow(unsafe_op_in_unsafe_fn)]

use core_foundation::base::TCFType;
use core_foundation::boolean::CFBoolean;
use core_foundation::data::CFData;
use core_foundation::string::CFString;
use std::ffi::{c_char, c_void};
use std::ptr;

// ── Security Framework (sys) ────────────────────────────────────
use security_framework_sys::access_control::SecAccessControlCreateWithFlags;
use security_framework_sys::keychain_item::{SecItemAdd, SecItemCopyMatching, SecItemDelete};

// Keychain attribute keys & values (CFStringRef globals from Security.framework)
unsafe extern "C" {
    static kSecClass: *const c_void;
    static kSecClassGenericPassword: *const c_void;
    static kSecAttrService: *const c_void;
    static kSecAttrAccount: *const c_void;
    static kSecValueData: *const c_void;
    static kSecReturnData: *const c_void;
    static kSecAttrSynchronizable: *const c_void;
    static kSecAttrAccessControl: *const c_void;
    static kSecUseAuthenticationContext: *const c_void;
    static kSecAttrAccessibleWhenUnlocked: *const c_void;
}

// ── Core Foundation (raw dict ops) ──────────────────────────────
unsafe extern "C" {
    fn CFDictionaryCreateMutable(
        allocator: *const c_void,
        capacity: isize,
        key_cb: *const c_void,
        val_cb: *const c_void,
    ) -> *mut c_void;
    fn CFDictionarySetValue(dict: *mut c_void, key: *const c_void, val: *const c_void);
    fn CFRelease(cf: *const c_void);
    static kCFTypeDictionaryKeyCallBacks: c_void;
    static kCFTypeDictionaryValueCallBacks: c_void;
}

// ── ObjC Runtime (for LAContext) ────────────────────────────────
#[link(name = "objc", kind = "dylib")]
unsafe extern "C" {
    fn objc_getClass(name: *const c_char) -> *mut c_void;
    fn sel_registerName(name: *const c_char) -> *mut c_void;
    fn objc_msgSend(receiver: *mut c_void, sel: *mut c_void) -> *mut c_void;
}

#[link(name = "LocalAuthentication", kind = "framework")]
unsafe extern "C" {}

// setCredential:type: — (NSData*, int64) → BOOL
unsafe extern "C" {
    #[link_name = "objc_msgSend"]
    fn msg_set_credential(
        ctx: *mut c_void,
        sel: *mut c_void,
        data: *const c_void,
        kind: i64,
    ) -> bool;
}

// ── Constants ───────────────────────────────────────────────────
const LA_CRED_APP_PASSWORD: i64 = -1; // LACredentialType.applicationPassword
const ACL_APP_PASSWORD: usize = 1 << 31; // kSecAccessControlApplicationPassword (CFOptionFlags)

const SERVICE: &str = "com.llm-key-ring.poc-test";
const ACCOUNT: &str = "poc:app-password-test";
const MASTER_PW: &[u8] = b"poc-master-password-2024";
const WRONG_PW: &[u8] = b"wrong-password-xxxxxxxx";
const SECRET: &str = r#"{"value":"sk-poc-test","kind":"admin"}"#;

// ── Helpers ─────────────────────────────────────────────────────

unsafe fn new_dict() -> *mut c_void {
    CFDictionaryCreateMutable(
        ptr::null(),
        0,
        &kCFTypeDictionaryKeyCallBacks as *const c_void,
        &kCFTypeDictionaryValueCallBacks as *const c_void,
    )
}

unsafe fn set_base_query(q: *mut c_void) {
    let svc = CFString::new(SERVICE);
    let acct = CFString::new(ACCOUNT);
    CFDictionarySetValue(q, kSecClass, kSecClassGenericPassword);
    CFDictionarySetValue(
        q,
        kSecAttrService,
        svc.as_concrete_TypeRef() as *const c_void,
    );
    CFDictionarySetValue(
        q,
        kSecAttrAccount,
        acct.as_concrete_TypeRef() as *const c_void,
    );
}

unsafe fn make_la_context(password: &[u8]) -> *mut c_void {
    let cls = objc_getClass(c"LAContext".as_ptr());
    assert!(!cls.is_null(), "LAContext class not found");
    let ctx = objc_msgSend(cls, sel_registerName(c"alloc".as_ptr()));
    let ctx = objc_msgSend(ctx, sel_registerName(c"init".as_ptr()));
    assert!(!ctx.is_null(), "Failed to create LAContext");

    let pw_data = CFData::from_buffer(password);
    // Return type of setCredential:type: is BOOL (signed char on x86_64, bool on arm64).
    // Use u8 interpretation to avoid FFI bool ambiguity.
    let raw_ok = msg_set_credential(
        ctx,
        sel_registerName(c"setCredential:type:".as_ptr()),
        pw_data.as_concrete_TypeRef() as *const c_void,
        LA_CRED_APP_PASSWORD,
    );
    if !raw_ok {
        eprintln!("  WARNING: setCredential:type: returned false (FFI bool may differ)");
        eprintln!("  Continuing anyway to test SecItemAdd...");
    }
    ctx
}

unsafe fn obj_release(p: *mut c_void) {
    if !p.is_null() {
        objc_msgSend(p, sel_registerName(c"release".as_ptr()));
    }
}

fn status_str(s: i32) -> &'static str {
    match s {
        0 => "errSecSuccess",
        -25299 => "errSecDuplicateItem",
        -25300 => "errSecItemNotFound",
        -25293 => "errSecAuthFailed",
        -25308 => "errSecInteractionNotAllowed",
        -128 => "errSecUserCanceled",
        -34018 => "errSecMissingEntitlement",
        _ => "other",
    }
}

// ── Keychain Operations ─────────────────────────────────────────

unsafe fn delete_item() -> i32 {
    let q = new_dict();
    set_base_query(q);
    let s = SecItemDelete(q as *const _);
    CFRelease(q);
    s
}

unsafe fn make_access_control() -> *mut c_void {
    let mut err: *mut c_void = ptr::null_mut();
    let ac = SecAccessControlCreateWithFlags(
        ptr::null(),
        kSecAttrAccessibleWhenUnlocked,
        ACL_APP_PASSWORD,
        &mut err as *mut _ as *mut _,
    );
    if ac.is_null() {
        panic!("SecAccessControlCreateWithFlags failed (err ptr: {err:?})");
    }
    ac as *mut c_void
}

unsafe fn store_item(ctx: *mut c_void, acl: *mut c_void) -> i32 {
    let q = new_dict();
    set_base_query(q);
    let data = CFData::from_buffer(SECRET.as_bytes());
    CFDictionarySetValue(
        q,
        kSecValueData,
        data.as_concrete_TypeRef() as *const c_void,
    );
    CFDictionarySetValue(
        q,
        kSecAttrSynchronizable,
        CFBoolean::false_value().as_CFTypeRef(),
    );
    CFDictionarySetValue(q, kSecAttrAccessControl, acl);
    CFDictionarySetValue(q, kSecUseAuthenticationContext, ctx);

    let s = SecItemAdd(q as *const _, ptr::null_mut());
    CFRelease(q);
    s
}

unsafe fn retrieve_item(ctx: Option<*mut c_void>) -> i32 {
    let q = new_dict();
    set_base_query(q);
    CFDictionarySetValue(
        q,
        kSecReturnData,
        CFBoolean::true_value().as_CFTypeRef(),
    );
    if let Some(c) = ctx {
        CFDictionarySetValue(q, kSecUseAuthenticationContext, c);
    }

    let mut result: *const c_void = ptr::null();
    let s = SecItemCopyMatching(q as *const _, &mut result as *mut _ as *mut _);

    if s == 0 && !result.is_null() {
        let cf = CFData::wrap_under_create_rule(result as *const _);
        if let Ok(text) = std::str::from_utf8(cf.bytes()) {
            let preview = if text.len() > 30 { &text[..30] } else { text };
            println!("    retrieved: {preview}...");
        }
    } else if !result.is_null() {
        CFRelease(result);
    }

    CFRelease(q);
    s
}

// ── Diagnostic: store without ACL (plain Keychain) ──────────────

unsafe fn store_plain() -> i32 {
    let q = new_dict();
    set_base_query(q);
    let data = CFData::from_buffer(SECRET.as_bytes());
    CFDictionarySetValue(q, kSecValueData, data.as_concrete_TypeRef() as *const c_void);
    CFDictionarySetValue(q, kSecAttrSynchronizable, CFBoolean::false_value().as_CFTypeRef());
    let s = SecItemAdd(q as *const _, ptr::null_mut());
    CFRelease(q);
    s
}

// ── Diagnostic: store with ACL but NO LAContext ─────────────────

unsafe fn store_acl_no_ctx(acl: *mut c_void) -> i32 {
    let q = new_dict();
    set_base_query(q);
    let data = CFData::from_buffer(SECRET.as_bytes());
    CFDictionarySetValue(q, kSecValueData, data.as_concrete_TypeRef() as *const c_void);
    CFDictionarySetValue(q, kSecAttrSynchronizable, CFBoolean::false_value().as_CFTypeRef());
    CFDictionarySetValue(q, kSecAttrAccessControl, acl);
    // NOTE: deliberately omitting kSecUseAuthenticationContext
    let s = SecItemAdd(q as *const _, ptr::null_mut());
    CFRelease(q);
    s
}

// ── Main ────────────────────────────────────────────────────────

fn main() {
    println!("=== APPLICATION_PASSWORD PoC ===");
    println!("Testing with unsigned binary (cargo run)\n");

    unsafe {
        // 0. Cleanup
        print!("[0] Cleanup leftover... ");
        let ds = delete_item();
        println!("{} ({ds})", status_str(ds));

        // ── Diagnostic A: Plain store (no ACL) ──
        print!("[A] Plain SecItemAdd (no ACL)... ");
        let sa = store_plain();
        println!("{} ({sa})", status_str(sa));
        if sa == 0 {
            delete_item();
        }

        // ── Diagnostic B: ACL + no LAContext ──
        print!("[B] SecAccessControlCreateWithFlags... ");
        let acl = make_access_control();
        println!("OK");
        print!("    SecItemAdd with ACL, NO LAContext... ");
        let sb = store_acl_no_ctx(acl);
        println!("{} ({sb})", status_str(sb));
        if sb == 0 {
            delete_item();
        }

        // ── Diagnostic C: ACL + LAContext (full test) ──
        print!("[C] LAContext + setCredential... ");
        let ctx = make_la_context(MASTER_PW);
        println!("OK");
        print!("    SecItemAdd with ACL + LAContext... ");
        let sc = store_item(ctx, acl);
        let store_ok = sc == 0;
        println!("{} ({sc})", status_str(sc));
        obj_release(ctx);

        // ── Retrieve tests (only if store succeeded) ──
        let mut ok_correct = false;
        let mut blocked_none = true;
        let mut blocked_wrong = true;

        if store_ok {
            println!("[D] Retrieve tests:");

            print!("  (a) Correct password: ");
            let c1 = make_la_context(MASTER_PW);
            let s1 = retrieve_item(Some(c1));
            ok_correct = s1 == 0;
            println!("{} ({s1})", status_str(s1));
            obj_release(c1);

            print!("  (b) No auth context:  ");
            let s2 = retrieve_item(None);
            blocked_none = s2 != 0;
            println!("{} ({s2})", status_str(s2));

            print!("  (c) Wrong password:   ");
            let c3 = make_la_context(WRONG_PW);
            let s3 = retrieve_item(Some(c3));
            blocked_wrong = s3 != 0;
            println!("{} ({s3})", status_str(s3));
            obj_release(c3);
        } else {
            println!("[D] Retrieve tests: SKIPPED (store failed)");
        }

        // Cleanup
        print!("[E] Final cleanup... ");
        let mut del = delete_item();
        if del != 0 && store_ok {
            let cd = make_la_context(MASTER_PW);
            let qd = new_dict();
            set_base_query(qd);
            CFDictionarySetValue(qd, kSecUseAuthenticationContext, cd);
            del = SecItemDelete(qd as *const _);
            CFRelease(qd);
            obj_release(cd);
        }
        println!("{} ({del})", status_str(del));
        CFRelease(acl as *const c_void);

        // ── Summary ──
        let full = store_ok && ok_correct && blocked_none && blocked_wrong;
        let partial = store_ok && ok_correct;

        println!("\n=== Diagnostic Summary ===");
        println!("[A] Plain store:     {} ({sa})", status_str(sa));
        println!("[B] ACL, no context: {} ({sb})", status_str(sb));
        println!("[C] ACL + context:   {} ({sc})", status_str(sc));
        if store_ok {
            println!("[D] Correct pw:      {}", if ok_correct { "OK" } else { "FAIL" });
            println!("    No context:      {}", if blocked_none { "BLOCKED" } else { "OPEN" });
            println!("    Wrong pw:        {}", if blocked_wrong { "BLOCKED" } else { "OPEN" });
        }

        println!();
        if full {
            println!("VERDICT: FULL PASS — admin ACL proceeds (Step 2 GO)");
        } else if sa == 0 && sc != 0 {
            println!("VERDICT: FAIL — plain Keychain works but APPLICATION_PASSWORD fails");
            println!("  Error {sc} ({}) suggests unsigned binary cannot use this ACL.", status_str(sc));
            println!("  → Step 2 (admin ACL) NO-GO for unsigned binary.");
            println!("  → Defer to v0.3.0 (signed distribution + Touch ID).");
        } else if partial {
            println!("VERDICT: PARTIAL — store/retrieve OK but protection incomplete");
        } else {
            println!("VERDICT: FAIL — Step 2 (admin ACL) dropped from scope");
        }

        std::process::exit(if full { 0 } else { 1 });
    }
}
