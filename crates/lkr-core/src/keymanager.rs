use crate::error::{Error, Result};
use crate::SERVICE_NAME;
use core_foundation::base::TCFType;
use core_foundation::string::CFString;
use serde::{Deserialize, Serialize};
use security_framework::item::{ItemClass, ItemSearchOptions, Limit, SearchResult};
use security_framework_sys::item::kSecAttrAccount;
use std::collections::HashMap;
use std::sync::Mutex;
use zeroize::Zeroizing;

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

/// Metadata stored alongside each key in Keychain.
/// Serialized as JSON in the Keychain password field:
///   { "value": "<actual-api-key>", "kind": "runtime" }
#[derive(Debug, Serialize, Deserialize)]
struct StoredEntry {
    value: String,
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
            reason: format!(
                "Provider '{}' must match [a-z0-9][a-z0-9-]*",
                provider
            ),
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
/// Uses char-based slicing to avoid panics on non-ASCII input.
pub fn mask_value(value: &str) -> String {
    let chars: Vec<char> = value.chars().collect();
    let len = chars.len();
    if len <= 8 {
        return "*".repeat(len);
    }
    let prefix: String = chars[..4].iter().collect();
    let suffix: String = chars[len - 4..].iter().collect();
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
// KeychainStore — production implementation using macOS Keychain
// ---------------------------------------------------------------------------

pub struct KeychainStore {
    service: String,
}

impl KeychainStore {
    pub fn new() -> Self {
        Self {
            service: SERVICE_NAME.to_string(),
        }
    }

    fn entry(&self, name: &str) -> std::result::Result<keyring::Entry, Error> {
        keyring::Entry::new(&self.service, name).map_err(|e| Error::Keychain(e.to_string()))
    }

    /// Extract the account name (kSecAttrAccount) from a CFDictionary.
    /// Returns None if the attribute is missing or not a valid string.
    fn extract_account(dict: &core_foundation::dictionary::CFDictionary) -> Option<String> {
        let account_key = unsafe { CFString::wrap_under_get_rule(kSecAttrAccount) };
        let account_ref = dict.find(account_key.as_CFTypeRef())?;
        let account = unsafe { CFString::wrap_under_get_rule(*account_ref as _) }.to_string();
        Some(account)
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

        if !force && self.exists(name)? {
            return Err(Error::KeyAlreadyExists {
                name: name.to_string(),
            });
        }

        let stored = StoredEntry {
            value: value.to_string(),
            kind,
        };
        let json = serde_json::to_string(&stored)
            .map_err(|e| Error::Keychain(format!("Failed to serialize: {}", e)))?;

        let entry = self.entry(name)?;
        entry.set_password(&json).map_err(|e| match e {
            keyring::Error::PlatformFailure(_) => Error::KeychainLocked,
            _ => Error::Keychain(e.to_string()),
        })?;

        Ok(())
    }

    fn get(&self, name: &str) -> Result<(Zeroizing<String>, KeyKind)> {
        validate_name(name)?;
        let entry = self.entry(name)?;
        let json = Zeroizing::new(entry.get_password().map_err(|e| match e {
            keyring::Error::NoEntry => Error::KeyNotFound {
                name: name.to_string(),
            },
            keyring::Error::PlatformFailure(_) => Error::KeychainLocked,
            _ => Error::Keychain(e.to_string()),
        })?);

        let stored: StoredEntry = serde_json::from_str(&json)
            .map_err(|e| Error::Keychain(format!("Failed to deserialize: {}", e)))?;

        Ok((Zeroizing::new(stored.value), stored.kind))
    }

    fn delete(&self, name: &str) -> Result<()> {
        validate_name(name)?;
        let entry = self.entry(name)?;
        entry.delete_credential().map_err(|e| match e {
            keyring::Error::NoEntry => Error::KeyNotFound {
                name: name.to_string(),
            },
            keyring::Error::PlatformFailure(_) => Error::KeychainLocked,
            _ => Error::Keychain(e.to_string()),
        })?;
        Ok(())
    }

    fn list(&self, include_admin: bool) -> Result<Vec<KeyEntry>> {
        // Step 1: Enumerate account names via security-framework
        let results = ItemSearchOptions::new()
            .class(ItemClass::generic_password())
            .service(&self.service)
            .load_attributes(true)
            .limit(Limit::All)
            .search();

        let results = match results {
            Ok(r) => r,
            Err(e) if e.code() == -25300 => return Ok(vec![]), // errSecItemNotFound
            Err(e) => return Err(Error::Keychain(format!("Keychain search failed: {}", e))),
        };

        // Step 2: For each account, read full data via keyring crate
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
            .map(|(name, v)| {
                let (provider, label) = validate_name(name).unwrap();
                KeyEntry {
                    name: name.clone(),
                    provider,
                    label,
                    kind: v.kind,
                    masked_value: mask_value(&v.value),
                }
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
        s.set("aaa:first", "val", KeyKind::Runtime, false)
            .unwrap();

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
