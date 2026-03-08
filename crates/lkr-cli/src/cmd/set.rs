use lkr_core::{KeyKind, KeyStore};
use std::io::{self, Write};
use zeroize::Zeroizing;

pub(crate) fn cmd_set(
    store: &impl KeyStore,
    name: &str,
    kind_str: &str,
    force: bool,
) -> lkr_core::Result<()> {
    let kind: KeyKind = kind_str
        .parse()
        .map_err(|reason| lkr_core::Error::InvalidKeyName {
            name: name.to_string(),
            reason,
        })?;

    // Read value from prompt (not CLI args — prevents shell history exposure)
    // Wrapped in Zeroizing to zero memory on drop.
    eprint!("Enter API key for {}: ", name);
    io::stderr().flush().ok();
    let value = Zeroizing::new(
        rpassword::read_password()
            .map_err(|e| lkr_core::Error::Keychain(format!("Failed to read input: {}", e)))?,
    );

    store.set(name, value.trim(), kind, force)?;

    eprintln!("Stored {} (kind: {})", name, kind);
    Ok(())
}
