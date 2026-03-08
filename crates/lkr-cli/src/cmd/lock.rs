/// Lock the LKR keychain.
pub(crate) fn cmd_lock() {
    if !lkr_core::custom_keychain::is_initialized() {
        eprintln!("Error: LKR keychain is not initialized.");
        eprintln!("\n  Run `lkr init` to create the secure keychain.");
        std::process::exit(1);
    }

    match lkr_core::custom_keychain::open() {
        Ok(kc) => match lkr_core::custom_keychain::lock(&kc) {
            Ok(()) => eprintln!("LKR keychain locked."),
            Err(e) => {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        },
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    }
}
