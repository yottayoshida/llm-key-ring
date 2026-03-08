use lkr_core::{KeyKind, KeyStatus, KeyStore};

pub(crate) fn cmd_exec(
    store: &impl KeyStore,
    keys: &[String],
    command: &[String],
    stdout_is_tty: bool,
    verbose: bool,
) -> lkr_core::Result<()> {
    if command.is_empty() {
        return Err(lkr_core::Error::Usage(
            "No command specified. Usage: lkr exec -- <command> [args...]".to_string(),
        ));
    }

    // Collect keys to inject
    let entries: Vec<(String, lkr_core::Zeroizing<String>)> = if keys.is_empty() {
        // No -k flags: inject all runtime keys
        let listed = store.list(false)?;
        let mut blocked: Vec<String> = Vec::new();
        let mut pairs = Vec::new();
        for entry in &listed {
            if entry.status == KeyStatus::AclBlocked {
                blocked.push(entry.name.clone());
                continue;
            }
            // entry.status == Ok means data was already read by list(),
            // but we still need the raw value. Re-fetch via get().
            if let Ok((value, _kind)) = store.get(&entry.name) {
                pairs.push((lkr_core::key_to_env_var(&entry.name), value));
            }
        }
        if !blocked.is_empty() {
            eprintln!(
                "⚠ {} key(s) skipped (ACL mismatch): {}",
                blocked.len(),
                blocked.join(", ")
            );
            eprintln!("  Run `lkr harden` to fix ACL for these keys.");
        }
        pairs
    } else {
        // Specific keys requested — admin keys are rejected (SECURITY.md T7)
        let mut pairs = Vec::new();
        for key_name in keys {
            let (value, kind) = store.get(key_name)?;
            if kind == KeyKind::Admin {
                return Err(lkr_core::Error::Usage(format!(
                    "admin key \"{}\" cannot be used with exec. Use runtime keys only.",
                    key_name
                )));
            }
            pairs.push((lkr_core::key_to_env_var(key_name), value));
        }
        pairs
    };

    // v0.2.0 stderr output rules:
    //   TTY + no --verbose   → silent
    //   TTY + --verbose      → key count + env var names
    //   non-TTY + no verbose → fixed 1-line warning
    //   non-TTY + --verbose  → warning + env var names
    //   0 keys (any)         → always warn
    let print_env_vars = || {
        for (env_var, _) in &entries {
            eprintln!("  {}", env_var);
        }
    };

    if entries.is_empty() {
        eprintln!("Warning: no keys matched. Running command without injected env vars.");
    } else if !stdout_is_tty {
        eprintln!(
            "Warning: injecting {} key(s) in non-interactive environment.",
            entries.len()
        );
        if verbose {
            print_env_vars();
        }
    } else if verbose {
        eprintln!("Injecting {} key(s) as env vars:", entries.len());
        print_env_vars();
    }

    // Build and exec child process
    let mut child = std::process::Command::new(&command[0]);
    child.args(&command[1..]);

    // Inject keys as environment variables
    for (env_var, value) in &entries {
        child.env(env_var, &**value);
    }

    let status = child.status().map_err(|e| {
        lkr_core::Error::Usage(format!("Failed to execute '{}': {}", command[0], e))
    })?;

    // Propagate child exit code
    std::process::exit(status.code().unwrap_or(1));
}
