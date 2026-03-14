use lkr_core::error::Error;
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

    let total = entries.len();

    if dry_run {
        eprintln!("  Would re-apply ACL to {} key(s):", total);
        for entry in &entries {
            eprintln!("    {} ({})", entry.name, entry.kind_display());
        }
        eprintln!();
        eprintln!("  Note: Running without --dry-run will re-apply ACL to each key.");
        eprintln!("  macOS may show an authorization dialog if needed.");
        eprintln!("\n  Run `lkr harden` (without --dry-run) to apply.");
        return Ok(());
    }

    // --- Pre-flight briefing ---
    eprintln!("Hardening {} key(s)...", total);
    eprintln!();
    eprintln!("  Re-applying ACL for the current binary. macOS may show an");
    eprintln!("  authorization dialog if the keychain requires it.");
    eprintln!();

    // --- Harden loop: interactive-get → delete → set with fresh ACL ---
    let mut success_count: usize = 0;
    let mut skip_count: usize = 0;
    let mut fail_count: usize = 0;

    for (i, entry) in entries.iter().enumerate() {
        let idx = i + 1;
        eprint!("  [{}/{}] {} — ", idx, total, entry.name);

        // Step 1: Read current value via interactive dialog
        let (value, kind) = match store.get_interactive(&entry.name) {
            Ok(v) => v,
            Err(Error::UserCanceled) => {
                eprintln!("skipped (denied)");
                skip_count += 1;
                continue;
            }
            Err(Error::InteractionNotAllowed) => {
                eprintln!("FAILED");
                eprintln!("         `lkr harden` requires a GUI environment (macOS desktop).");
                eprintln!("         It cannot run over SSH, in CI, or as a launchd service.");
                fail_count += 1;
                continue;
            }
            Err(e) => {
                eprintln!("FAILED to read: {}", e);
                fail_count += 1;
                continue;
            }
        };

        // Step 2: Re-create with fresh ACL (interactive: allows macOS dialog
        // for delete/set when ACL cdhash no longer matches this binary)
        match store.set_interactive(&entry.name, &value, kind, true) {
            Ok(()) => {
                eprintln!("hardened");
                success_count += 1;
            }
            Err(e) => {
                eprintln!("FAILED to re-create: {}", e);
                eprintln!("         ⚠ The key may have been deleted during this operation.");
                eprintln!(
                    "         Recovery: `lkr set {} --kind {}` to re-register.",
                    entry.name, kind
                );
                fail_count += 1;
            }
        }
    }

    // --- Summary ---
    eprintln!();
    eprintln!(
        "  Result: {} hardened, {} skipped, {} failed",
        success_count, skip_count, fail_count
    );

    if skip_count > 0 {
        eprintln!();
        eprintln!("  Skipped keys can be hardened by running `lkr harden` again");
        eprintln!("  and clicking \"Allow\" or \"Always Allow\" in the dialog.");
    }

    if fail_count > 0 {
        eprintln!();
        eprintln!("  Failed keys may need manual recovery with `lkr set`.");
    }

    if success_count > 0 && skip_count == 0 && fail_count == 0 {
        eprintln!();
        eprintln!("  All keys hardened successfully.");
    }

    Ok(())
}
