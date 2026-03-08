#![warn(clippy::undocumented_unsafe_blocks)]

pub mod acl;
pub mod custom_keychain;
pub mod error;
pub mod keymanager;
pub mod template;
pub mod usage;

pub use error::{Error, Result};
pub use keymanager::{
    KeyEntry, KeyKind, KeyStatus, KeyStore, KeychainStore, MigrateKeyResult, MigrateResult,
    mask_value,
};
pub use template::{GenResult, Resolution, check_gitignore, generate, key_to_env_var};
pub use usage::{
    CostLineItem, CostReport, UsageCache, available_providers, fetch_cost, format_cost,
};
pub use zeroize::Zeroizing;

/// Keychain service name — shared across all frontends.
/// NEVER change this value once keys are stored.
pub const SERVICE_NAME: &str = "com.llm-key-ring";
