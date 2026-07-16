use lkr_core::KeychainStore;
use std::io::{self, Write};

/// Blocks password prompts when stdin isn't an interactive terminal.
///
/// rpassword reads from `/dev/tty` (not stdin) as of v7, so piped input that
/// used to be readable in v5 now goes unread while the process waits on the
/// terminal. Checking this upfront turns that into an immediate, explicit
/// error instead of a hang or a silently-ignored pipe.
pub(crate) fn guard_stdin_tty(stdin_is_tty: bool) -> lkr_core::Result<()> {
    if stdin_is_tty {
        return Ok(());
    }
    Err(lkr_core::Error::TtyGuard {
        message: "Password prompt requires an interactive terminal.\n  \
            Piped/non-interactive input is not supported here (prevents silent \
            hangs and unintended empty-password retries against the Keychain).\n\n  \
            Run this command in an interactive terminal."
            .to_string(),
    })
}

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
pub(crate) fn open_and_unlock(stdin_is_tty: bool) -> lkr_core::Result<KeychainStore> {
    if !lkr_core::custom_keychain::is_initialized() {
        return Err(lkr_core::Error::NotInitialized);
    }

    guard_stdin_tty(stdin_is_tty)?;

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_guard_stdin_tty_passes_when_interactive() {
        assert!(guard_stdin_tty(true).is_ok());
    }

    #[test]
    fn test_guard_stdin_tty_blocks_when_non_interactive() {
        let result = guard_stdin_tty(false);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            lkr_core::Error::TtyGuard { .. }
        ));
    }
}
