use crate::SERVICE_NAME;
use crate::error::{Error, Result};
use core_foundation::base::TCFType;
use core_foundation::string::CFString;
use security_framework::item::{CloudSync, ItemClass, ItemSearchOptions, Limit, SearchResult};
use security_framework_sys::item::kSecAttrAccount;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::ffi::c_void;
use std::ptr;
use std::sync::Mutex;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Key kind — separates high-privilege admin keys from runtime API keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KeyKind {
    Runtime,
    Admin,
}

impl std::fmt::Display for KeyKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyKind::Runtime => write!(f, "runtime"),
            KeyKind::Admin => write!(f, "admin"),
        }
    }
}

impl std::str::FromStr for KeyKind {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "runtime" => Ok(KeyKind::Runtime),
            "admin" => Ok(KeyKind::Admin),
            _ => Err(format!(
                "Invalid kind '{}'. Must be 'runtime' or 'admin'.",
                s
            )),
        }
    }
}

/// Metadata stored alongside each key in Keychain.
/// Serialized as JSON in the Keychain password field:
///   { "value": "<actual-api-key>", "kind": "runtime" }
#[derive(Debug, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
struct StoredEntry {
    value: String,
    #[zeroize(skip)]
    kind: KeyKind,
}

/// Public key entry returned by list().
#[derive(Debug, Clone, Serialize)]
pub struct KeyEntry {
    /// Full account name, e.g. "openai:prod"
    pub name: String,
    /// Provider portion, e.g. "openai"
    pub provider: String,
    /// Label portion, e.g. "prod"
    pub label: String,
    /// Key kind
    pub kind: KeyKind,
    /// Masked value, e.g. "sk-...abcd"
    pub masked_value: String,
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/// Validate key name format: `{provider}:{label}`
/// Allowed characters: [a-z0-9][a-z0-9-]*
fn validate_name(name: &str) -> Result<(String, String)> {
    let re_part = |s: &str| -> bool {
        !s.is_empty()
            && s.chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
            && s.chars().next().is_some_and(|c| c.is_ascii_alphanumeric())
    };

    let parts: Vec<&str> = name.splitn(2, ':').collect();
    if parts.len() != 2 {
        return Err(Error::InvalidKeyName {
            name: name.to_string(),
            reason: "Must be in 'provider:label' format (e.g. openai:prod)".to_string(),
        });
    }

    let (provider, label) = (parts[0], parts[1]);

    if !re_part(provider) {
        return Err(Error::InvalidKeyName {
            name: name.to_string(),
            reason: format!("Provider '{}' must match [a-z0-9][a-z0-9-]*", provider),
        });
    }
    if !re_part(label) {
        return Err(Error::InvalidKeyName {
            name: name.to_string(),
            reason: format!("Label '{}' must match [a-z0-9][a-z0-9-]*", label),
        });
    }

    Ok((provider.to_string(), label.to_string()))
}

/// Mask an API key for display: "sk-proj-abc...xyz" → "sk-p...wxyz"
/// Uses char iterators to avoid allocating the full char vec.
pub fn mask_value(value: &str) -> String {
    let len = value.chars().count();
    if len <= 8 {
        return "*".repeat(len);
    }
    let prefix: String = value.chars().take(4).collect();
    let suffix: String = value
        .chars()
        .rev()
        .take(4)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    format!("{}...{}", prefix, suffix)
}

// ---------------------------------------------------------------------------
// KeyStore trait
// ---------------------------------------------------------------------------

/// Abstraction over key storage backend.
/// Enables MockStore for testing and KeychainStore for production.
pub trait KeyStore {
    fn set(&self, name: &str, value: &str, kind: KeyKind, force: bool) -> Result<()>;
    fn get(&self, name: &str) -> Result<(Zeroizing<String>, KeyKind)>;
    fn delete(&self, name: &str) -> Result<()>;
    fn list(&self, include_admin: bool) -> Result<Vec<KeyEntry>>;
    fn exists(&self, name: &str) -> Result<bool>;
}

// ---------------------------------------------------------------------------
// Keychain raw operations — direct security-framework-sys FFI
// ---------------------------------------------------------------------------
//
// v0.2.0: Replaces `keyring` crate with direct Security.framework calls.
// All new items stored with:
//   - kSecAttrSynchronizable: false  (no iCloud Keychain sync)
//   - kSecAttrAccessibleWhenUnlocked (locked device blocks access)
// All searches use kSecAttrSynchronizableAny for v0.1.0 backward compat.

mod keychain_raw {
    use super::*;
    use core_foundation::boolean::CFBoolean;
    use core_foundation::data::CFData;
    use security_framework_sys::item::{
        kSecAttrService, kSecAttrSynchronizable, kSecAttrSynchronizableAny, kSecClass,
        kSecClassGenericPassword, kSecReturnData, kSecValueData,
    };
    use security_framework_sys::keychain_item::{SecItemAdd, SecItemCopyMatching, SecItemDelete};

    // CFDictionary raw operations — not exposed at the level we need by core_foundation
    #[link(name = "CoreFoundation", kind = "framework")]
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

    // Accessibility constants from Security.framework.
    // kSecAttrAccessible (key) may not be in security-framework-sys, so declare directly.
    #[link(name = "Security", kind = "framework")]
    unsafe extern "C" {
        static kSecAttrAccessible: *const c_void;
        static kSecAttrAccessibleWhenUnlocked: *const c_void;
        static kSecMatchSearchList: *const c_void;
    }

    // v0.3.0: Legacy Keychain API for CreateFromContent + FindGenericPassword
    unsafe extern "C" {
        fn SecKeychainItemCreateFromContent(
            item_class: u32,
            attr_list: *mut SecKeychainAttributeList,
            length: u32,
            data: *const c_void,
            keychain_ref: *const c_void,
            initial_access: *const c_void,
            item_ref_out: *mut *mut c_void,
        ) -> i32;

        fn SecKeychainFindGenericPassword(
            keychain_or_array: *const c_void,
            service_name_length: u32,
            service_name: *const u8,
            account_name_length: u32,
            account_name: *const u8,
            password_length: *mut u32,
            password_data: *mut *mut c_void,
            item_ref: *mut *mut c_void,
        ) -> i32;

        fn SecKeychainItemFreeContent(attr_list: *const c_void, data: *const c_void) -> i32;

        fn SecKeychainItemDelete(item_ref: *const c_void) -> i32;
    }

    // v0.3.0: CSSM attribute structures for SecKeychainItemCreateFromContent
    #[repr(C)]
    struct SecKeychainAttribute {
        tag: u32,
        length: u32,
        data: *mut c_void,
    }

    #[repr(C)]
    struct SecKeychainAttributeList {
        count: u32,
        attr: *mut SecKeychainAttribute,
    }

    fn new_dict() -> *mut c_void {
        unsafe {
            CFDictionaryCreateMutable(
                ptr::null(),
                0,
                &kCFTypeDictionaryKeyCallBacks as *const c_void,
                &kCFTypeDictionaryValueCallBacks as *const c_void,
            )
        }
    }

    /// Set common query fields: class=GenericPassword + service + account.
    /// CFDictionarySetValue retains keys/values, so locals can go out of scope.
    fn set_base(dict: *mut c_void, service: &str, account: &str) {
        let svc = CFString::new(service);
        let acct = CFString::new(account);
        unsafe {
            CFDictionarySetValue(dict, kSecClass as _, kSecClassGenericPassword as _);
            CFDictionarySetValue(dict, kSecAttrService as _, svc.as_concrete_TypeRef() as _);
            CFDictionarySetValue(dict, kSecAttrAccount as _, acct.as_concrete_TypeRef() as _);
        }
    }

    fn os_status_to_error(status: i32, account: &str) -> Error {
        use crate::error::os_status::*;
        match status {
            ERR_SEC_ITEM_NOT_FOUND => Error::KeyNotFound {
                name: account.to_string(),
            },
            ERR_SEC_DUPLICATE_ITEM => Error::KeyAlreadyExists {
                name: account.to_string(),
            },
            ERR_SEC_AUTH_FAILED => Error::PasswordWrong,
            ERR_SEC_INTERACTION_NOT_ALLOWED => Error::InteractionNotAllowed,
            ERR_SEC_NO_SUCH_KEYCHAIN => Error::NotInitialized,
            ERR_SEC_INVALID_KEYCHAIN => Error::Keychain(
                "Keychain file is corrupted or invalid. Try `lkr init` after removing the old file."
                    .into(),
            ),
            ERR_SEC_DECODE_ERROR => Error::Keychain(
                "Failed to decode keychain data. The keychain file may be corrupted.".into(),
            ),
            ERR_SEC_USER_CANCELED => Error::Keychain(
                "Operation was canceled. This may indicate a GUI dialog was suppressed.".into(),
            ),
            _ => Error::Keychain(format!("Keychain error: OSStatus {status}")),
        }
    }

    /// Store a password in Keychain with v0.2.0 hardened attributes.
    pub(super) fn set(service: &str, account: &str, password: &[u8]) -> Result<()> {
        let dict = new_dict();
        set_base(dict, service, account);
        let data = CFData::from_buffer(password);
        unsafe {
            CFDictionarySetValue(dict, kSecValueData as _, data.as_concrete_TypeRef() as _);
            // v0.2.0: Disable iCloud Keychain sync
            CFDictionarySetValue(
                dict,
                kSecAttrSynchronizable as _,
                CFBoolean::false_value().as_CFTypeRef(),
            );
            // v0.2.0: Only accessible when device is unlocked
            CFDictionarySetValue(dict, kSecAttrAccessible, kSecAttrAccessibleWhenUnlocked);

            let status = SecItemAdd(dict as _, ptr::null_mut());
            CFRelease(dict as _);

            if status != 0 {
                return Err(os_status_to_error(status, account));
            }
        }
        Ok(())
    }

    /// Retrieve password bytes from Keychain.
    /// Uses kSecAttrSynchronizableAny for v0.1.0 backward compatibility.
    pub(super) fn get(service: &str, account: &str) -> Result<Vec<u8>> {
        let dict = new_dict();
        set_base(dict, service, account);
        unsafe {
            CFDictionarySetValue(
                dict,
                kSecReturnData as _,
                CFBoolean::true_value().as_CFTypeRef(),
            );
            // v0.1.0 keys may lack synchronizable attr; search all
            CFDictionarySetValue(
                dict,
                kSecAttrSynchronizable as _,
                kSecAttrSynchronizableAny as _,
            );

            let mut result: *const c_void = ptr::null();
            let status = SecItemCopyMatching(dict as _, &mut result as *mut _ as *mut _);
            CFRelease(dict as _);

            if status != 0 {
                return Err(os_status_to_error(status, account));
            }

            if result.is_null() {
                return Err(Error::Keychain(
                    "SecItemCopyMatching returned null".to_string(),
                ));
            }

            let cf_data = CFData::wrap_under_create_rule(result as _);
            Ok(cf_data.bytes().to_vec())
        }
    }

    /// Update attributes on an existing Keychain item.
    /// Used by `lkr migrate` to add v0.2.0 hardened attributes to v0.1.0 keys.
    pub(super) fn update_attributes(service: &str, account: &str) -> Result<()> {
        use security_framework_sys::keychain_item::SecItemUpdate;

        let query = new_dict();
        set_base(query, service, account);
        let attrs = new_dict();

        unsafe {
            // Query: find item (SynchronizableAny for v0.1.0 compat)
            CFDictionarySetValue(
                query,
                kSecAttrSynchronizable as _,
                kSecAttrSynchronizableAny as _,
            );

            // Attributes to update
            CFDictionarySetValue(
                attrs,
                kSecAttrSynchronizable as _,
                CFBoolean::false_value().as_CFTypeRef(),
            );
            CFDictionarySetValue(attrs, kSecAttrAccessible, kSecAttrAccessibleWhenUnlocked);

            let status = SecItemUpdate(query as _, attrs as _);
            CFRelease(query as _);
            CFRelease(attrs as _);

            if status != 0 {
                return Err(os_status_to_error(status, account));
            }
        }
        Ok(())
    }

    /// Delete a key from Keychain.
    /// Uses kSecAttrSynchronizableAny for v0.1.0 backward compatibility.
    pub(super) fn delete(service: &str, account: &str) -> Result<()> {
        let dict = new_dict();
        set_base(dict, service, account);
        unsafe {
            // v0.1.0 keys may lack synchronizable attr; match all
            CFDictionarySetValue(
                dict,
                kSecAttrSynchronizable as _,
                kSecAttrSynchronizableAny as _,
            );

            let status = SecItemDelete(dict as _);
            CFRelease(dict as _);

            if status != 0 {
                return Err(os_status_to_error(status, account));
            }
        }
        Ok(())
    }

    // =====================================================================
    // v0.3.0: Custom Keychain operations (with ACL)
    // =====================================================================

    /// Store a password in Custom Keychain with initial ACL (SR2/SR4).
    ///
    /// Uses `SecKeychainItemCreateFromContent` to set the SecAccess at
    /// creation time, avoiding the GUI dialog issue with `SecKeychainItemSetAccess`.
    ///
    /// # Arguments
    /// * `keychain` — unlocked Custom Keychain reference
    /// * `access` — SecAccessRef built by `acl::build_access()`; may be null to skip ACL
    /// * `service` — service name (e.g. "com.llm-key-ring")
    /// * `account` — account name (e.g. "openai:prod")
    /// * `password` — secret value bytes
    pub(super) fn set_v3(
        keychain: &security_framework::os::macos::keychain::SecKeychain,
        access: *const c_void,
        service: &str,
        account: &str,
        password: &[u8],
    ) -> Result<()> {
        use core_foundation::base::TCFType;
        use security_framework::os::macos::keychain::SecKeychain;

        let _guard = SecKeychain::disable_user_interaction()
            .map_err(|e| Error::Keychain(format!("Failed to disable user interaction: {e}")))?;

        let svc_bytes = service.as_bytes();
        let acct_bytes = account.as_bytes();

        let mut attrs = [
            SecKeychainAttribute {
                tag: u32::from_be_bytes(*b"svce"), // kSecServiceItemAttr
                length: svc_bytes.len() as u32,
                data: svc_bytes.as_ptr() as *mut c_void,
            },
            SecKeychainAttribute {
                tag: u32::from_be_bytes(*b"acct"), // kSecAccountItemAttr
                length: acct_bytes.len() as u32,
                data: acct_bytes.as_ptr() as *mut c_void,
            },
        ];

        let mut attr_list = SecKeychainAttributeList {
            count: 2,
            attr: attrs.as_mut_ptr(),
        };

        let item_class: u32 = u32::from_be_bytes(*b"genp"); // kSecGenericPasswordItemClass

        let mut item_ref: *mut c_void = std::ptr::null_mut();
        let status = unsafe {
            SecKeychainItemCreateFromContent(
                item_class,
                &mut attr_list,
                password.len() as u32,
                password.as_ptr() as _,
                keychain.as_concrete_TypeRef() as _,
                access,
                &mut item_ref,
            )
        };

        // Release the item ref if returned (we don't need it)
        if !item_ref.is_null() {
            unsafe { CFRelease(item_ref as _) };
        }

        if status != 0 {
            return Err(os_status_to_error(status, account));
        }

        Ok(())
    }

    /// Retrieve password bytes from Custom Keychain (v0.3.0).
    ///
    /// Uses `SecKeychainFindGenericPassword` scoped to the given keychain.
    /// Returns the raw bytes and optionally the item ref (for ACL diagnosis).
    pub(super) fn get_v3(
        keychain: &security_framework::os::macos::keychain::SecKeychain,
        service: &str,
        account: &str,
    ) -> Result<Vec<u8>> {
        use core_foundation::base::TCFType;
        use security_framework::os::macos::keychain::SecKeychain;

        let _guard = SecKeychain::disable_user_interaction()
            .map_err(|e| Error::Keychain(format!("Failed to disable user interaction: {e}")))?;

        let svc_bytes = service.as_bytes();
        let acct_bytes = account.as_bytes();

        let mut pw_length: u32 = 0;
        let mut pw_data: *mut c_void = std::ptr::null_mut();
        let mut item_ref: *mut c_void = std::ptr::null_mut();

        let status = unsafe {
            SecKeychainFindGenericPassword(
                keychain.as_concrete_TypeRef() as _,
                svc_bytes.len() as u32,
                svc_bytes.as_ptr(),
                acct_bytes.len() as u32,
                acct_bytes.as_ptr(),
                &mut pw_length,
                &mut pw_data,
                &mut item_ref,
            )
        };

        if status != 0 {
            // Harden -25308: distinguish ACL mismatch from keychain-locked
            if status == crate::error::os_status::ERR_SEC_INTERACTION_NOT_ALLOWED
                && !item_ref.is_null()
            {
                let is_acl = unsafe { crate::acl::is_acl_blocked(item_ref as _) };
                unsafe { CFRelease(item_ref as _) };
                if is_acl {
                    return Err(Error::AclMismatch);
                }
            } else if !item_ref.is_null() {
                unsafe { CFRelease(item_ref as _) };
            }
            return Err(os_status_to_error(status, account));
        }

        // Release the item ref (not needed for basic get)
        if !item_ref.is_null() {
            unsafe { CFRelease(item_ref as _) };
        }

        if pw_data.is_null() {
            return Err(Error::Keychain(
                "SecKeychainFindGenericPassword returned null data".into(),
            ));
        }

        // Copy data out before freeing
        let bytes = unsafe { std::slice::from_raw_parts(pw_data as *const u8, pw_length as usize) }
            .to_vec();

        // Free the password data allocated by Security.framework
        unsafe {
            SecKeychainItemFreeContent(std::ptr::null(), pw_data);
        }

        Ok(bytes)
    }

    /// Delete a key from Custom Keychain (v0.3.0).
    ///
    /// Finds the item via `SecKeychainFindGenericPassword`, then deletes it
    /// via `SecKeychainItemDelete`.
    pub(super) fn delete_v3(
        keychain: &security_framework::os::macos::keychain::SecKeychain,
        service: &str,
        account: &str,
    ) -> Result<()> {
        use core_foundation::base::TCFType;
        use security_framework::os::macos::keychain::SecKeychain;

        let _guard = SecKeychain::disable_user_interaction()
            .map_err(|e| Error::Keychain(format!("Failed to disable user interaction: {e}")))?;

        let svc_bytes = service.as_bytes();
        let acct_bytes = account.as_bytes();

        let mut item_ref: *mut c_void = std::ptr::null_mut();

        let find_status = unsafe {
            SecKeychainFindGenericPassword(
                keychain.as_concrete_TypeRef() as _,
                svc_bytes.len() as u32,
                svc_bytes.as_ptr(),
                acct_bytes.len() as u32,
                acct_bytes.as_ptr(),
                std::ptr::null_mut(), // don't need password data
                std::ptr::null_mut(),
                &mut item_ref,
            )
        };

        if find_status != 0 {
            return Err(os_status_to_error(find_status, account));
        }

        if item_ref.is_null() {
            return Err(Error::KeyNotFound {
                name: account.to_string(),
            });
        }

        let delete_status = unsafe { SecKeychainItemDelete(item_ref) };
        unsafe { CFRelease(item_ref as _) };

        if delete_status != 0 {
            return Err(os_status_to_error(delete_status, account));
        }

        Ok(())
    }

    /// List all items in Custom Keychain (v0.3.0).
    ///
    /// Uses `SecItemCopyMatching` with `kSecMatchSearchList` to scope
    /// the search to the Custom Keychain only.
    pub(super) fn list_v3(
        keychain: &security_framework::os::macos::keychain::SecKeychain,
        service: &str,
    ) -> Result<Vec<String>> {
        use core_foundation::base::TCFType;
        use core_foundation::boolean::CFBoolean;
        use security_framework::os::macos::keychain::SecKeychain;

        let _guard = SecKeychain::disable_user_interaction()
            .map_err(|e| Error::Keychain(format!("Failed to disable user interaction: {e}")))?;

        // Build CFArray with single keychain for kSecMatchSearchList
        unsafe extern "C" {
            fn CFArrayCreateMutable(
                allocator: *const c_void,
                capacity: isize,
                callbacks: *const c_void,
            ) -> *mut c_void;
            fn CFArrayAppendValue(array: *mut c_void, value: *const c_void);
            static kCFTypeArrayCallBacks: c_void;
        }

        // Also need kSecReturnAttributes and kSecMatchLimit
        #[link(name = "Security", kind = "framework")]
        unsafe extern "C" {
            static kSecReturnAttributes: *const c_void;
            static kSecMatchLimit: *const c_void;
            static kSecMatchLimitAll: *const c_void;
        }

        let dict = new_dict();
        let svc = CFString::new(service);

        unsafe {
            CFDictionarySetValue(dict, kSecClass as _, kSecClassGenericPassword as _);
            CFDictionarySetValue(dict, kSecAttrService as _, svc.as_concrete_TypeRef() as _);
            CFDictionarySetValue(
                dict,
                kSecReturnAttributes as _,
                CFBoolean::true_value().as_CFTypeRef(),
            );
            CFDictionarySetValue(dict, kSecMatchLimit as _, kSecMatchLimitAll as _);

            // Scope to Custom Keychain only
            let kc_array =
                CFArrayCreateMutable(std::ptr::null(), 1, &kCFTypeArrayCallBacks as *const c_void);
            CFArrayAppendValue(kc_array, keychain.as_concrete_TypeRef() as _);
            CFDictionarySetValue(dict, kSecMatchSearchList as _, kc_array as _);

            let mut result: *const c_void = ptr::null();
            let status = SecItemCopyMatching(dict as _, &mut result as *mut _ as *mut _);
            CFRelease(dict as _);
            CFRelease(kc_array as _);

            if status == -25300 {
                // errSecItemNotFound — no items
                return Ok(vec![]);
            }
            if status != 0 {
                return Err(os_status_to_error(status, ""));
            }
            if result.is_null() {
                return Ok(vec![]);
            }

            // Result is a CFArray of CFDictionaries
            unsafe extern "C" {
                fn CFArrayGetCount(array: *const c_void) -> isize;
                fn CFArrayGetValueAtIndex(array: *const c_void, idx: isize) -> *const c_void;
                fn CFDictionaryGetValue(dict: *const c_void, key: *const c_void) -> *const c_void;
                fn CFStringGetCStringPtr(string: *const c_void, encoding: u32) -> *const i8;
            }

            let count = CFArrayGetCount(result);
            let mut accounts = Vec::new();

            for i in 0..count {
                let item_dict = CFArrayGetValueAtIndex(result, i);
                let acct_ref = CFDictionaryGetValue(item_dict, kSecAttrAccount as _);
                if !acct_ref.is_null() {
                    // Try fast path: CFStringGetCStringPtr
                    let cstr = CFStringGetCStringPtr(acct_ref, 0x0800_0100); // UTF-8
                    if !cstr.is_null() {
                        if let Ok(s) = std::ffi::CStr::from_ptr(cstr).to_str() {
                            accounts.push(s.to_string());
                        }
                    } else {
                        // Fallback: wrap as CFString
                        let cf_str = CFString::wrap_under_get_rule(acct_ref as _);
                        accounts.push(cf_str.to_string());
                    }
                }
            }

            CFRelease(result);
            Ok(accounts)
        }
    }
}

// ---------------------------------------------------------------------------
// KeychainStore — production implementation using macOS Keychain
// ---------------------------------------------------------------------------

pub struct KeychainStore {
    service: String,
    /// v0.3.0: Custom Keychain (Some = v0.3.0 mode, None = legacy mode for migrate)
    custom_keychain: Option<security_framework::os::macos::keychain::SecKeychain>,
}

impl KeychainStore {
    /// Create a legacy-mode store (v0.2.x compat, for migrate reads).
    pub fn new() -> Self {
        Self {
            service: SERVICE_NAME.to_string(),
            custom_keychain: None,
        }
    }

    /// Create a v0.3.0 store backed by the Custom Keychain.
    ///
    /// The keychain must already be opened (and ideally unlocked).
    /// Use `custom_keychain::open()` + `custom_keychain::unlock()` first.
    pub fn new_v3(keychain: security_framework::os::macos::keychain::SecKeychain) -> Self {
        Self {
            service: SERVICE_NAME.to_string(),
            custom_keychain: Some(keychain),
        }
    }

    /// Check if this store is in v0.3.0 mode (Custom Keychain).
    pub fn is_v3(&self) -> bool {
        self.custom_keychain.is_some()
    }

    /// Extract the account name (kSecAttrAccount) from a CFDictionary.
    /// Returns None if the attribute is missing or not a valid string.
    fn extract_account(dict: &core_foundation::dictionary::CFDictionary) -> Option<String> {
        let account_key = unsafe { CFString::wrap_under_get_rule(kSecAttrAccount) };
        let account_ref = dict.find(account_key.as_CFTypeRef())?;
        let account = unsafe { CFString::wrap_under_get_rule(*account_ref as _) }.to_string();
        Some(account)
    }

    /// Check if a key exists in legacy login.keychain (for migrate detection).
    fn legacy_exists(&self, name: &str) -> bool {
        keychain_raw::get(&self.service, name).is_ok()
    }
}

/// Result of migrating a single key.
#[derive(Debug)]
pub struct MigrateKeyResult {
    /// Key name (e.g. "openai:prod")
    pub name: String,
    /// Key kind
    pub kind: KeyKind,
    /// Whether the migration succeeded
    pub success: bool,
    /// Error message if failed
    pub error: Option<String>,
}

impl MigrateKeyResult {
    fn ok(entry: &KeyEntry) -> Self {
        Self {
            name: entry.name.clone(),
            kind: entry.kind,
            success: true,
            error: None,
        }
    }
    fn err(entry: &KeyEntry, e: &Error) -> Self {
        Self {
            name: entry.name.clone(),
            kind: entry.kind,
            success: false,
            error: Some(e.to_string()),
        }
    }
}

/// Summary of a migrate operation.
#[derive(Debug)]
pub struct MigrateResult {
    /// Per-key results
    pub keys: Vec<MigrateKeyResult>,
}

impl MigrateResult {
    pub fn migrated_count(&self) -> usize {
        self.keys.iter().filter(|k| k.success).count()
    }

    pub fn failed_count(&self) -> usize {
        self.keys.iter().filter(|k| !k.success).count()
    }
}

impl KeychainStore {
    /// Migrate v0.1.0 keys to v0.2.0 attributes.
    ///
    /// Adds `kSecAttrSynchronizable: false` and `kSecAttrAccessibleWhenUnlocked`
    /// to all keys stored under the service name. Idempotent — safe to run
    /// multiple times.
    ///
    /// When `dry_run` is true, returns what *would* be migrated without changes.
    pub fn migrate(&self, dry_run: bool) -> Result<MigrateResult> {
        // List ALL keys (including admin)
        let entries = self.list(true)?;

        let mut results = Vec::new();

        for entry in &entries {
            if dry_run {
                results.push(MigrateKeyResult::ok(entry));
                continue;
            }

            match keychain_raw::update_attributes(&self.service, &entry.name) {
                Ok(()) => results.push(MigrateKeyResult::ok(entry)),
                Err(e) => results.push(MigrateKeyResult::err(entry, &e)),
            }
        }

        Ok(MigrateResult { keys: results })
    }
}

impl Default for KeychainStore {
    fn default() -> Self {
        Self::new()
    }
}

impl KeyStore for KeychainStore {
    fn set(&self, name: &str, value: &str, kind: KeyKind, force: bool) -> Result<()> {
        validate_name(name)?;
        if value.is_empty() {
            return Err(Error::EmptyValue);
        }

        let exists = self.exists(name)?;
        if !force && exists {
            return Err(Error::KeyAlreadyExists {
                name: name.to_string(),
            });
        }

        let stored = StoredEntry {
            value: value.to_string(),
            kind,
        };
        let json = Zeroizing::new(
            serde_json::to_string(&stored)
                .map_err(|e| Error::Keychain(format!("Failed to serialize: {}", e)))?,
        );
        if let Some(kc) = &self.custom_keychain {
            // v0.3.0: Custom Keychain + ACL
            // Build ACL first (fail-closed): if this fails, the old key remains intact
            let access =
                crate::acl::current_binary_path().and_then(|p| crate::acl::build_access(&p))?;

            if exists {
                keychain_raw::delete_v3(kc, &self.service, name)?;
            }

            let result = keychain_raw::set_v3(kc, access, &self.service, name, json.as_bytes());

            // Release the access ref if we created one
            if !access.is_null() {
                unsafe {
                    unsafe extern "C" {
                        fn CFRelease(cf: *const c_void);
                    }
                    CFRelease(access as _);
                }
            }

            result?;
        } else {
            // Legacy mode (v0.2.x)
            if exists {
                keychain_raw::delete(&self.service, name)?;
            }
            keychain_raw::set(&self.service, name, json.as_bytes())?;
        }

        Ok(())
    }

    fn get(&self, name: &str) -> Result<(Zeroizing<String>, KeyKind)> {
        validate_name(name)?;

        let bytes = if let Some(kc) = &self.custom_keychain {
            // v0.3.0: Try Custom Keychain first
            match keychain_raw::get_v3(kc, &self.service, name) {
                Ok(b) => b,
                Err(Error::KeyNotFound { .. }) if self.legacy_exists(name) => {
                    // Key exists in login.keychain but not in Custom Keychain
                    return Err(Error::Keychain(format!(
                        "Key '{}' found in login.keychain but not in lkr.keychain-db. \
                         Run `lkr migrate` to move your keys.",
                        name
                    )));
                }
                Err(e) => return Err(e),
            }
        } else {
            // Legacy mode
            keychain_raw::get(&self.service, name)?
        };

        let json = Zeroizing::new(
            String::from_utf8(bytes)
                .map_err(|e| Error::Keychain(format!("Invalid UTF-8 in Keychain: {}", e)))?,
        );

        let mut stored: StoredEntry = serde_json::from_str(&json)
            .map_err(|e| Error::Keychain(format!("Failed to deserialize: {}", e)))?;

        let value = std::mem::take(&mut stored.value);
        Ok((Zeroizing::new(value), stored.kind))
    }

    fn delete(&self, name: &str) -> Result<()> {
        validate_name(name)?;
        if let Some(kc) = &self.custom_keychain {
            keychain_raw::delete_v3(kc, &self.service, name)
        } else {
            keychain_raw::delete(&self.service, name)
        }
    }

    fn list(&self, include_admin: bool) -> Result<Vec<KeyEntry>> {
        if let Some(kc) = &self.custom_keychain {
            // v0.3.0: List from Custom Keychain via kSecMatchSearchList
            let accounts = keychain_raw::list_v3(kc, &self.service)?;
            let mut entries = Vec::new();
            for account in accounts {
                if let Ok((value, kind)) = self.get(&account) {
                    if !include_admin && kind == KeyKind::Admin {
                        continue;
                    }
                    if let Ok((provider, label)) = validate_name(&account) {
                        entries.push(KeyEntry {
                            name: account,
                            provider,
                            label,
                            kind,
                            masked_value: mask_value(&value),
                        });
                    }
                }
            }
            entries.sort_by(|a, b| a.name.cmp(&b.name));
            Ok(entries)
        } else {
            // Legacy mode: search via ItemSearchOptions (v0.2.x)
            let results = ItemSearchOptions::new()
                .class(ItemClass::generic_password())
                .service(&self.service)
                .cloud_sync(CloudSync::MatchSyncAny)
                .load_attributes(true)
                .limit(Limit::All)
                .search();

            let results = match results {
                Ok(r) => r,
                Err(e) if e.code() == -25300 => return Ok(vec![]),
                Err(e) => return Err(Error::Keychain(format!("Keychain search failed: {}", e))),
            };

            let mut entries = Vec::new();
            for result in results {
                if let SearchResult::Dict(dict) = result
                    && let Some(account) = Self::extract_account(&dict)
                    && let Ok((value, kind)) = self.get(&account)
                {
                    if !include_admin && kind == KeyKind::Admin {
                        continue;
                    }
                    if let Ok((provider, label)) = validate_name(&account) {
                        entries.push(KeyEntry {
                            name: account,
                            provider,
                            label,
                            kind,
                            masked_value: mask_value(&value),
                        });
                    }
                }
            }
            entries.sort_by(|a, b| a.name.cmp(&b.name));
            Ok(entries)
        }
    }

    fn exists(&self, name: &str) -> Result<bool> {
        match self.get(name) {
            Ok(_) => Ok(true),
            Err(Error::KeyNotFound { .. }) => Ok(false),
            Err(e) => Err(e),
        }
    }
}

// ---------------------------------------------------------------------------
// MockStore — in-memory implementation for testing
// ---------------------------------------------------------------------------

pub struct MockStore {
    keys: Mutex<HashMap<String, StoredEntry>>,
}

impl MockStore {
    pub fn new() -> Self {
        Self {
            keys: Mutex::new(HashMap::new()),
        }
    }
}

impl Default for MockStore {
    fn default() -> Self {
        Self::new()
    }
}

impl KeyStore for MockStore {
    fn set(&self, name: &str, value: &str, kind: KeyKind, force: bool) -> Result<()> {
        validate_name(name)?;
        if value.is_empty() {
            return Err(Error::EmptyValue);
        }

        let mut keys = self.keys.lock().unwrap();
        if !force && keys.contains_key(name) {
            return Err(Error::KeyAlreadyExists {
                name: name.to_string(),
            });
        }

        keys.insert(
            name.to_string(),
            StoredEntry {
                value: value.to_string(),
                kind,
            },
        );
        Ok(())
    }

    fn get(&self, name: &str) -> Result<(Zeroizing<String>, KeyKind)> {
        validate_name(name)?;
        let keys = self.keys.lock().unwrap();
        match keys.get(name) {
            Some(entry) => Ok((Zeroizing::new(entry.value.clone()), entry.kind)),
            None => Err(Error::KeyNotFound {
                name: name.to_string(),
            }),
        }
    }

    fn delete(&self, name: &str) -> Result<()> {
        validate_name(name)?;
        let mut keys = self.keys.lock().unwrap();
        if keys.remove(name).is_none() {
            return Err(Error::KeyNotFound {
                name: name.to_string(),
            });
        }
        Ok(())
    }

    fn list(&self, include_admin: bool) -> Result<Vec<KeyEntry>> {
        let keys = self.keys.lock().unwrap();
        let mut entries: Vec<KeyEntry> = keys
            .iter()
            .filter(|(_, v)| include_admin || v.kind == KeyKind::Runtime)
            .filter_map(|(name, v)| {
                let (provider, label) = validate_name(name).ok()?;
                Some(KeyEntry {
                    name: name.clone(),
                    provider,
                    label,
                    kind: v.kind,
                    masked_value: mask_value(&v.value),
                })
            })
            .collect();
        entries.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(entries)
    }

    fn exists(&self, name: &str) -> Result<bool> {
        validate_name(name)?;
        let keys = self.keys.lock().unwrap();
        Ok(keys.contains_key(name))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> MockStore {
        MockStore::new()
    }

    // -- Validation --

    #[test]
    fn test_validate_name_valid() {
        assert!(validate_name("openai:prod").is_ok());
        assert!(validate_name("anthropic:main").is_ok());
        assert!(validate_name("my-provider:my-key-1").is_ok());
    }

    #[test]
    fn test_validate_name_missing_colon() {
        let err = validate_name("openai").unwrap_err();
        assert!(matches!(err, Error::InvalidKeyName { .. }));
    }

    #[test]
    fn test_validate_name_empty_parts() {
        assert!(validate_name(":prod").is_err());
        assert!(validate_name("openai:").is_err());
        assert!(validate_name(":").is_err());
    }

    #[test]
    fn test_validate_name_uppercase_rejected() {
        assert!(validate_name("OpenAI:prod").is_err());
        assert!(validate_name("openai:Prod").is_err());
    }

    #[test]
    fn test_validate_name_special_chars_rejected() {
        assert!(validate_name("open_ai:prod").is_err());
        assert!(validate_name("openai:prod/test").is_err());
        assert!(validate_name("openai:prod test").is_err());
    }

    // -- Mask --

    #[test]
    fn test_mask_value() {
        assert_eq!(mask_value("sk-proj-abcdefghijklmnop"), "sk-p...mnop");
        assert_eq!(mask_value("short"), "*****");
        assert_eq!(mask_value("12345678"), "********");
        assert_eq!(mask_value("123456789"), "1234...6789");
    }

    #[test]
    fn test_mask_value_empty() {
        assert_eq!(mask_value(""), "");
    }

    #[test]
    fn test_mask_value_single_char() {
        assert_eq!(mask_value("x"), "*");
    }

    #[test]
    fn test_mask_value_unicode() {
        // 4-char Unicode string (≤8 chars → all masked)
        assert_eq!(mask_value("日本語テスト"), "******");
        // 9+ chars → prefix 4 + ... + suffix 4
        assert_eq!(mask_value("あいうえおかきくけ"), "あいうえ...かきくけ");
    }

    // -- Set / Get --

    #[test]
    fn test_set_and_get() {
        let s = store();
        s.set("openai:prod", "sk-abc123", KeyKind::Runtime, false)
            .unwrap();
        let (val, kind) = s.get("openai:prod").unwrap();
        assert_eq!(&*val, "sk-abc123");
        assert_eq!(kind, KeyKind::Runtime);
    }

    #[test]
    fn test_set_admin_key() {
        let s = store();
        s.set("openai:admin", "sk-admin-xyz", KeyKind::Admin, false)
            .unwrap();
        let (val, kind) = s.get("openai:admin").unwrap();
        assert_eq!(&*val, "sk-admin-xyz");
        assert_eq!(kind, KeyKind::Admin);
    }

    #[test]
    fn test_set_empty_value_rejected() {
        let s = store();
        let err = s
            .set("openai:prod", "", KeyKind::Runtime, false)
            .unwrap_err();
        assert!(matches!(err, Error::EmptyValue));
    }

    #[test]
    fn test_set_duplicate_rejected() {
        let s = store();
        s.set("openai:prod", "sk-abc", KeyKind::Runtime, false)
            .unwrap();
        let err = s
            .set("openai:prod", "sk-def", KeyKind::Runtime, false)
            .unwrap_err();
        assert!(matches!(err, Error::KeyAlreadyExists { .. }));
    }

    #[test]
    fn test_set_force_overwrite() {
        let s = store();
        s.set("openai:prod", "sk-abc", KeyKind::Runtime, false)
            .unwrap();
        s.set("openai:prod", "sk-def", KeyKind::Runtime, true)
            .unwrap();
        let (val, _) = s.get("openai:prod").unwrap();
        assert_eq!(&*val, "sk-def");
    }

    #[test]
    fn test_get_nonexistent() {
        let s = store();
        let err = s.get("openai:prod").unwrap_err();
        assert!(matches!(err, Error::KeyNotFound { .. }));
    }

    // -- Delete --

    #[test]
    fn test_delete() {
        let s = store();
        s.set("openai:prod", "sk-abc", KeyKind::Runtime, false)
            .unwrap();
        s.delete("openai:prod").unwrap();
        assert!(!s.exists("openai:prod").unwrap());
    }

    #[test]
    fn test_delete_nonexistent() {
        let s = store();
        let err = s.delete("openai:prod").unwrap_err();
        assert!(matches!(err, Error::KeyNotFound { .. }));
    }

    // -- List --

    #[test]
    fn test_list_empty() {
        let s = store();
        let entries = s.list(false).unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn test_list_excludes_admin_by_default() {
        let s = store();
        s.set("openai:prod", "sk-abc", KeyKind::Runtime, false)
            .unwrap();
        s.set("openai:admin", "sk-adm", KeyKind::Admin, false)
            .unwrap();

        let entries = s.list(false).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "openai:prod");
    }

    #[test]
    fn test_list_includes_admin_when_requested() {
        let s = store();
        s.set("openai:prod", "sk-abc", KeyKind::Runtime, false)
            .unwrap();
        s.set("openai:admin", "sk-adm", KeyKind::Admin, false)
            .unwrap();

        let entries = s.list(true).unwrap();
        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn test_list_sorted() {
        let s = store();
        s.set("zzz:last", "val", KeyKind::Runtime, false).unwrap();
        s.set("aaa:first", "val", KeyKind::Runtime, false).unwrap();

        let entries = s.list(false).unwrap();
        assert_eq!(entries[0].name, "aaa:first");
        assert_eq!(entries[1].name, "zzz:last");
    }

    // -- Exists --

    #[test]
    fn test_exists() {
        let s = store();
        assert!(!s.exists("openai:prod").unwrap());
        s.set("openai:prod", "sk-abc", KeyKind::Runtime, false)
            .unwrap();
        assert!(s.exists("openai:prod").unwrap());
    }
}
