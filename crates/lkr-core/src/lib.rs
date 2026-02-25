pub mod error;
pub mod keymanager;

pub use error::{Error, Result};
pub use keymanager::{KeyEntry, KeyKind, KeyStore, KeychainStore};

/// Keychain service name — shared between CLI and Tauri.
/// NEVER change this value once keys are stored.
pub const SERVICE_NAME: &str = "com.llm-key-ring";
