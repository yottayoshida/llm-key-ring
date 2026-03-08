use lkr_core::{KeyStore, KeychainStore};

/// Re-apply ACL to all keys (after binary update/reinstall).
pub(crate) fn cmd_harden(store: &KeychainStore, dry_run: bool) -> lkr_core::Result<()> {
    let binary_path = lkr_core::acl::current_binary_path()?;
    eprintln!("Binary path: {}", binary_path.display());

    let entries = store.list(true)?;
    if entries.is_empty() {
        eprintln!("No keys to harden.");
        return Ok(());
    }

    if dry_run {
        eprintln!("  Would re-apply ACL to {} key(s):", entries.len());
        for entry in &entries {
            eprintln!("    {} ({})", entry.name, entry.kind_display());
        }
        eprintln!("\n  Run `lkr harden` (without --dry-run) to apply.");
        return Ok(());
    }

    // Harden: delete + re-create with fresh ACL for each key
    let mut success_count = 0;
    let mut fail_count = 0;

    for entry in &entries {
        // Read current value
        let (value, kind) = match store.get(&entry.name) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("    {} — FAILED to read: {}", entry.name, e);
                fail_count += 1;
                continue;
            }
        };

        // Delete + re-create with force (which triggers CreateFromContent with fresh ACL)
        match store.set(&entry.name, &value, kind, true) {
            Ok(()) => {
                eprintln!("    {} — hardened", entry.name);
                success_count += 1;
            }
            Err(e) => {
                eprintln!("    {} — FAILED: {}", entry.name, e);
                fail_count += 1;
            }
        }
    }

    eprintln!(
        "\n  Result: {} hardened, {} failed",
        success_count, fail_count
    );
    Ok(())
}
