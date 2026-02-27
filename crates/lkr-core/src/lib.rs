pub mod error;
pub mod keymanager;
pub mod template;

pub use error::{Error, Result};
pub use keymanager::{KeyEntry, KeyKind, KeyStore, KeychainStore, mask_value};
pub use template::{generate, check_gitignore, GenResult, Resolution};
pub use zeroize::Zeroizing;

/// Keychain service name — shared between CLI and Tauri.
/// NEVER change this value once keys are stored.
pub const SERVICE_NAME: &str = "com.llm-key-ring";
