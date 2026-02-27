pub mod error;
pub mod keymanager;
pub mod template;
pub mod usage;

pub use error::{Error, Result};
pub use keymanager::{KeyEntry, KeyKind, KeyStore, KeychainStore, mask_value};
pub use template::{generate, check_gitignore, key_to_env_var, GenResult, Resolution};
pub use usage::{CostReport, CostLineItem, UsageCache, fetch_cost, available_providers, format_cost};
pub use zeroize::Zeroizing;

/// Keychain service name — shared between CLI and Tauri.
/// NEVER change this value once keys are stored.
pub const SERVICE_NAME: &str = "com.llm-key-ring";
