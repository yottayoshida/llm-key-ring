use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Key not found: {name}")]
    KeyNotFound { name: String },

    #[error("Key already exists: {name}. Use --force to overwrite.")]
    KeyAlreadyExists { name: String },

    #[error("Invalid key name: {name}. {reason}")]
    InvalidKeyName { name: String, reason: String },

    #[error("Empty value is not allowed")]
    EmptyValue,

    #[error("Keychain error: {0}")]
    Keychain(String),

    #[error("Keychain is locked. Please unlock and try again.")]
    KeychainLocked,

    #[error("Template error: {0}")]
    Template(String),

    #[error("Usage API error: {0}")]
    Usage(String),

    #[error("Admin key required for {provider} usage tracking. Run `lkr set {provider}:admin --kind admin` to register.")]
    AdminKeyRequired { provider: String },

    #[error("HTTP {status}: {body}")]
    HttpError { status: u16, body: String },
}
