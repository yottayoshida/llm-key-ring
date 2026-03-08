use std::io::{self, Write};

/// Initialize the LKR secure keychain.
pub(crate) fn cmd_init() {
    if lkr_core::custom_keychain::is_initialized() {
        eprintln!("LKR keychain is already initialized.");
        if let Ok(path) = lkr_core::custom_keychain::keychain_path() {
            eprintln!("  Path: {}", path.display());
        }
        return;
    }

    eprintln!("Creating LKR secure keychain...");
    eprintln!("  This password protects your API keys at rest.\n");

    // Password with confirmation
    let password = loop {
        eprint!("Set keychain password: ");
        io::stderr().flush().ok();
        let pw1 = match rpassword::read_password() {
            Ok(p) if !p.is_empty() => p,
            Ok(_) => {
                eprintln!("Password cannot be empty.");
                continue;
            }
            Err(e) => {
                eprintln!("Error: Failed to read password: {}", e);
                std::process::exit(1);
            }
        };

        eprint!("Confirm password: ");
        io::stderr().flush().ok();
        let pw2 = match rpassword::read_password() {
            Ok(p) => p,
            Err(e) => {
                eprintln!("Error: Failed to read password: {}", e);
                std::process::exit(1);
            }
        };

        if pw1 != pw2 {
            eprintln!("Passwords do not match. Try again.\n");
            continue;
        }

        break pw1;
    };

    match lkr_core::custom_keychain::create(&password) {
        Ok(_kc) => {
            eprintln!("\nLKR keychain created successfully.");
            if let Ok(path) = lkr_core::custom_keychain::keychain_path() {
                eprintln!("  Path: {}", path.display());
            }
            eprintln!("  Auto-lock: 5 minutes / on sleep");
            eprintln!("\n  Next steps:");
            eprintln!("    lkr set openai:prod       # Store a key");
            eprintln!("    lkr migrate                # Move keys from login.keychain");
        }
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    }
}
