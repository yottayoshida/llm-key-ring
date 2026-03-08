use lkr_core::{KeyStatus, KeyStore};

pub(crate) fn cmd_list(
    store: &impl KeyStore,
    include_admin: bool,
    json: bool,
) -> lkr_core::Result<()> {
    let entries = store.list(include_admin)?;

    if entries.is_empty() {
        if json {
            println!("[]");
        } else {
            eprintln!("No keys stored.\n");
            eprintln!("  Get started:");
            eprintln!("    lkr set openai:prod");
            eprintln!("    lkr set anthropic:main");
        }
        return Ok(());
    }

    if json {
        println!("{}", serde_json::to_string_pretty(&entries).unwrap());
        return Ok(());
    }

    // Table output
    let blocked_count = entries
        .iter()
        .filter(|e| e.status == KeyStatus::AclBlocked)
        .count();

    println!("  {:<14} {:<20} {:<10} Value", "Provider", "Name", "Kind");
    println!("  {}", "-".repeat(60));
    for entry in &entries {
        let kind_str = match (&entry.status, &entry.kind) {
            (KeyStatus::AclBlocked, _) => "⚠ blocked".to_string(),
            (_, Some(k)) => k.to_string(),
            (_, None) => "?".to_string(),
        };
        let value_str = if entry.status == KeyStatus::AclBlocked {
            "(ACL mismatch — run `lkr harden`)"
        } else {
            &entry.masked_value
        };
        println!(
            "  {:<14} {:<20} {:<10} {}",
            entry.provider, entry.name, kind_str, value_str
        );
    }
    println!("\n  {} key(s) stored in Keychain", entries.len());

    if blocked_count > 0 {
        eprintln!(
            "\n  ⚠ {} key(s) have ACL mismatch. Run `lkr harden` to fix.",
            blocked_count
        );
    }

    Ok(())
}
