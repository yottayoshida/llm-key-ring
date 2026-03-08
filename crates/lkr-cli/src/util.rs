use lkr_core::KeychainStore;
use std::io::{self, Write};

pub(crate) fn confirm(prompt: &str) -> bool {
    eprint!("{}", prompt);
    io::stderr().flush().ok();
    let mut input = String::new();
    io::stdin().read_line(&mut input).ok();
    input.trim().eq_ignore_ascii_case("y")
}

/// Spawn a detached background process that clears the clipboard after `seconds`.
///
/// Uses SHA-256 hash comparison to avoid clearing if the user copied something else.
/// The raw key value is never passed as a process argument (prevents `ps` exposure).
pub(crate) fn schedule_clipboard_clear(seconds: u32) {
    // Capture SHA-256 hash of current clipboard content
    let hash_output = std::process::Command::new("sh")
        .arg("-c")
        .arg("pbpaste 2>/dev/null | shasum -a 256 | cut -d' ' -f1")
        .output();

    let expected_hash = match hash_output {
        Ok(output) => String::from_utf8_lossy(&output.stdout).trim().to_string(),
        Err(_) => return, // Can't hash — skip auto-clear silently
    };

    if expected_hash.is_empty() {
        return;
    }

    // Spawn detached process: sleep → compare hash → clear if unchanged
    let script = format!(
        "sleep {} && current=$(pbpaste 2>/dev/null | shasum -a 256 | cut -d' ' -f1) && \
         [ \"$current\" = \"{}\" ] && printf '' | pbcopy",
        seconds, expected_hash
    );

    let _ = std::process::Command::new("sh")
        .arg("-c")
        .arg(&script)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn(); // Detach — orphaned child survives parent exit
}

/// Open and unlock the Custom Keychain with password retry.
///
/// Returns a v0.3.0 KeychainStore ready for operations.
/// Prompts for password up to 3 times.
pub(crate) fn open_and_unlock() -> lkr_core::Result<KeychainStore> {
    if !lkr_core::custom_keychain::is_initialized() {
        return Err(lkr_core::Error::NotInitialized);
    }

    let mut kc = lkr_core::custom_keychain::open()?;

    const MAX_RETRIES: u32 = 3;
    for attempt in 1..=MAX_RETRIES {
        eprint!("LKR keychain password: ");
        io::stderr().flush().ok();
        let password = rpassword::read_password()
            .map_err(|e| lkr_core::Error::Keychain(format!("Failed to read password: {e}")))?;

        match lkr_core::custom_keychain::unlock(&mut kc, &password) {
            Ok(()) => return Ok(KeychainStore::new_v3(kc)),
            Err(lkr_core::Error::PasswordWrong) => {
                if attempt < MAX_RETRIES {
                    eprintln!("Wrong password. ({}/{} attempts)", attempt, MAX_RETRIES);
                } else {
                    return Err(lkr_core::Error::PasswordWrong);
                }
            }
            Err(e) => return Err(e),
        }
    }

    Err(lkr_core::Error::PasswordWrong)
}
