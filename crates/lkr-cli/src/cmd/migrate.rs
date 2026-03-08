use crate::util::confirm;
use lkr_core::{KeyStore, KeychainStore};

/// Migrate keys from login.keychain to LKR custom keychain (v0.3.0).
pub(crate) fn cmd_migrate(store: &KeychainStore, dry_run: bool, yes: bool) -> lkr_core::Result<()> {
    // Read keys from legacy login.keychain
    let legacy_store = KeychainStore::new();
    let legacy_entries = legacy_store.list(true)?;

    if legacy_entries.is_empty() {
        eprintln!("No keys found in login.keychain to migrate.");
        return Ok(());
    }

    // Check which keys already exist in Custom Keychain (skip those)
    let mut to_migrate = Vec::new();
    for entry in &legacy_entries {
        if store.exists(&entry.name).unwrap_or(false) {
            eprintln!("    {} — already in LKR keychain (skip)", entry.name);
        } else {
            to_migrate.push(entry);
        }
    }

    if to_migrate.is_empty() {
        eprintln!("All keys already migrated.");
        return Ok(());
    }

    if dry_run {
        eprintln!("  Would migrate {} key(s):", to_migrate.len());
        for entry in &to_migrate {
            eprintln!("    {} ({})", entry.name, entry.kind_display());
        }
        eprintln!("\n  Run `lkr migrate` (without --dry-run) to apply.");
        return Ok(());
    }

    // Confirmation
    if !yes {
        eprintln!(
            "  Will migrate {} key(s) to LKR keychain:",
            to_migrate.len()
        );
        for entry in &to_migrate {
            eprintln!("    {} ({})", entry.name, entry.kind_display());
        }
        if !confirm("\n  Proceed? [y/N] ") {
            eprintln!("Cancelled.");
            return Ok(());
        }
    }

    // Copy-first migration (SR6): read from legacy → write to custom → verify
    let mut success_count = 0;
    let mut fail_count = 0;

    for entry in &to_migrate {
        // Step 1: Read from legacy
        let (value, kind) = match legacy_store.get(&entry.name) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("    {} — FAILED to read: {}", entry.name, e);
                fail_count += 1;
                continue;
            }
        };

        // Step 2: Write to Custom Keychain (with ACL)
        if let Err(e) = store.set(&entry.name, &value, kind, false) {
            eprintln!("    {} — FAILED to write: {}", entry.name, e);
            fail_count += 1;
            continue;
        }

        // Step 3: Verify read-back
        match store.get(&entry.name) {
            Ok((readback, _)) if *readback == *value => {
                eprintln!("    {} ({}) — migrated", entry.name, kind);
                success_count += 1;
            }
            Ok(_) => {
                eprintln!("    {} — FAILED: verification mismatch", entry.name);
                fail_count += 1;
            }
            Err(e) => {
                eprintln!("    {} — FAILED to verify: {}", entry.name, e);
                fail_count += 1;
            }
        }
    }

    eprintln!(
        "\n  Result: {} migrated, {} failed",
        success_count, fail_count
    );

    if success_count > 0 {
        eprintln!("\n  Legacy keys are still in login.keychain. You can remove them with:");
        eprintln!("    security delete-generic-password -s com.llm-key-ring -a <name>");
    }

    Ok(())
}
