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

    #[error("Keychain is locked")]
    KeychainLocked,

    #[error("Template error: {0}")]
    Template(String),

    #[error("Usage API error: {0}")]
    Usage(String),

    #[error(
        "Admin key required for {provider} usage tracking. Run `lkr set {provider}:admin --kind admin` to register."
    )]
    AdminKeyRequired { provider: String },

    #[error("HTTP {status}: {body}")]
    HttpError { status: u16, body: String },

    #[error("{message}")]
    TtyGuard { message: String },

    #[error("LKR keychain is not initialized")]
    NotInitialized,

    #[error("Wrong keychain password")]
    PasswordWrong,

    #[error("ACL error: {0}")]
    Acl(String),

    #[error("Access denied — binary fingerprint may have changed")]
    AclMismatch,

    #[error("Keychain operation requires user interaction, which is disabled")]
    InteractionNotAllowed,
}

/// OSStatus codes from Security.framework.
pub mod os_status {
    pub const ERR_SEC_SUCCESS: i32 = 0;
    pub const ERR_SEC_ITEM_NOT_FOUND: i32 = -25300;
    pub const ERR_SEC_DUPLICATE_ITEM: i32 = -25299;
    pub const ERR_SEC_AUTH_FAILED: i32 = -25293;
    pub const ERR_SEC_INTERACTION_NOT_ALLOWED: i32 = -25308;
    pub const ERR_SEC_NO_SUCH_KEYCHAIN: i32 = -25294;
    pub const ERR_SEC_INVALID_KEYCHAIN: i32 = -25295;
    pub const ERR_SEC_DECODE_ERROR: i32 = -26275;
    pub const ERR_SEC_USER_CANCELED: i32 = -128;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_os_status_constants() {
        assert_eq!(os_status::ERR_SEC_SUCCESS, 0);
        assert_eq!(os_status::ERR_SEC_ITEM_NOT_FOUND, -25300);
        assert_eq!(os_status::ERR_SEC_DUPLICATE_ITEM, -25299);
        assert_eq!(os_status::ERR_SEC_AUTH_FAILED, -25293);
        assert_eq!(os_status::ERR_SEC_INTERACTION_NOT_ALLOWED, -25308);
        assert_eq!(os_status::ERR_SEC_NO_SUCH_KEYCHAIN, -25294);
        assert_eq!(os_status::ERR_SEC_USER_CANCELED, -128);
    }

    #[test]
    fn test_error_display_not_initialized() {
        let e = Error::NotInitialized;
        assert!(e.to_string().contains("not initialized"));
    }

    #[test]
    fn test_error_display_password_wrong() {
        let e = Error::PasswordWrong;
        assert!(e.to_string().contains("Wrong"));
    }

    #[test]
    fn test_error_display_acl_mismatch() {
        let e = Error::AclMismatch;
        let msg = e.to_string();
        assert!(msg.contains("binary fingerprint"));
        // I-cdhash: must NOT contain "cdhash"
        assert!(!msg.contains("cdhash"));
    }

    #[test]
    fn test_error_display_interaction_not_allowed() {
        let e = Error::InteractionNotAllowed;
        let msg = e.to_string();
        assert!(msg.contains("user interaction"));
        assert!(!msg.contains("cdhash"));
    }

    #[test]
    fn test_error_display_key_not_found() {
        let e = Error::KeyNotFound {
            name: "openai:prod".to_string(),
        };
        assert!(e.to_string().contains("openai:prod"));
    }

    #[test]
    fn test_error_display_key_already_exists() {
        let e = Error::KeyAlreadyExists {
            name: "openai:prod".to_string(),
        };
        let msg = e.to_string();
        assert!(msg.contains("openai:prod"));
        assert!(msg.contains("--force"));
    }
}
