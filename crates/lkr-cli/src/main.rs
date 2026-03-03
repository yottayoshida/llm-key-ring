use clap::{Parser, Subcommand};
use lkr_core::{KeyKind, KeyStore, KeychainStore, mask_value};
use std::io::{self, IsTerminal, Write};
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(
    name = "lkr",
    about = "LLM Key Ring — manage LLM API keys via macOS Keychain",
    version,
    after_help = "Examples:\n  lkr set openai:prod\n  lkr get openai:prod\n  lkr list\n  lkr rm openai:prod\n  lkr gen .env.example -o .env\n  lkr usage openai"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Output as JSON
    #[arg(long, global = true)]
    json: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Store an API key in Keychain
    Set {
        /// Key name in provider:label format (e.g. openai:prod)
        name: String,

        /// Key kind: runtime (default) or admin
        #[arg(long, default_value = "runtime")]
        kind: String,

        /// Overwrite existing key without confirmation
        #[arg(long)]
        force: bool,
    },

    /// Retrieve an API key (copies to clipboard)
    Get {
        /// Key name in provider:label format
        name: String,

        /// Show raw value in terminal (default: masked + clipboard)
        #[arg(long)]
        show: bool,

        /// Output raw value only (for piping). Blocked in non-interactive environments.
        #[arg(long)]
        plain: bool,

        /// Force raw output even in non-interactive environments (use with caution)
        #[arg(long)]
        force_plain: bool,
    },

    /// List stored keys
    #[command(alias = "ls")]
    List {
        /// Include admin keys
        #[arg(long)]
        all: bool,
    },

    /// Remove a key from Keychain
    Rm {
        /// Key name in provider:label format
        name: String,

        /// Skip confirmation prompt
        #[arg(long)]
        force: bool,
    },

    /// Show API usage costs for the current month
    Usage {
        /// Provider name (openai, anthropic). Omit to show all.
        provider: Option<String>,

        /// Force fresh API fetch (reserved for future file-based caching)
        #[arg(long)]
        refresh: bool,
    },

    /// Generate config from template (resolves Keychain keys)
    Gen {
        /// Template file path (e.g. .env.example, .mcp.json.template)
        template: String,

        /// Output file path (default: template name without .example/.template suffix)
        #[arg(short, long)]
        output: Option<String>,

        /// Overwrite output file without confirmation
        #[arg(long)]
        force: bool,
    },

    /// Migrate v0.1.0 keys to v0.2.0 format (adds sync protection + lock protection)
    Migrate {
        /// Preview changes without applying
        #[arg(long)]
        dry_run: bool,
    },

    /// Run a command with Keychain keys injected as environment variables.
    ///
    /// Keys never appear in stdout, files, or clipboard — the safest way
    /// to pass secrets to child processes.
    Exec {
        /// Key names to inject (e.g. -k openai:prod). Omit to inject all runtime keys.
        #[arg(short = 'k', long = "key")]
        keys: Vec<String>,

        /// Show injected key count and env var names on stderr
        #[arg(long)]
        verbose: bool,

        /// The command and arguments to run (after --)
        #[arg(trailing_var_arg = true, required = true)]
        command: Vec<String>,
    },
}

/// Prompt the user for y/N confirmation on stderr.
/// Returns true if the user typed "y" (case-insensitive).
fn confirm(prompt: &str) -> bool {
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
fn schedule_clipboard_clear(seconds: u32) {
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

fn main() {
    let cli = Cli::parse();
    let store = KeychainStore::new();

    // Determine TTY status once — injected into handlers for testability.
    // Only io::stdout().is_terminal() (isatty) is trusted; env vars like $TERM are not.
    let stdout_is_tty = io::stdout().is_terminal();

    let result = match cli.command {
        Commands::Set { name, kind, force } => cmd_set(&store, &name, &kind, force),
        Commands::Get {
            name,
            show,
            plain,
            force_plain,
        } => cmd_get(
            &store,
            &name,
            show,
            plain,
            force_plain,
            cli.json,
            stdout_is_tty,
        ),
        Commands::List { all } => cmd_list(&store, all, cli.json),
        Commands::Rm { name, force } => cmd_rm(&store, &name, force),
        Commands::Usage { provider, refresh } => {
            cmd_usage(&store, provider.as_deref(), refresh, cli.json)
        }
        Commands::Gen {
            template,
            output,
            force,
        } => cmd_gen(&store, &template, output.as_deref(), force, stdout_is_tty),
        Commands::Migrate { dry_run } => cmd_migrate(&store, dry_run),
        Commands::Exec {
            keys,
            verbose,
            command,
        } => cmd_exec(&store, &keys, &command, stdout_is_tty, verbose),
    };

    if let Err(e) = result {
        // TTY guard violations → exit code 2 (distinct from general errors)
        if let lkr_core::Error::TtyGuard { .. } = e {
            eprintln!("Error: {}", e);
            std::process::exit(2);
        }

        eprintln!("Error: {}", e);

        // Suggest similar keys for KeyNotFound errors
        if let lkr_core::Error::KeyNotFound { ref name } = e {
            if let Ok(entries) = store.list(true) {
                let suggestions: Vec<&str> = entries
                    .iter()
                    .filter(|entry| {
                        entry.name.contains(&name[..name.len().min(4)])
                            || entry.provider == name.split(':').next().unwrap_or("")
                    })
                    .map(|e| e.name.as_str())
                    .collect();
                if !suggestions.is_empty() {
                    eprintln!("\n  Did you mean?");
                    for s in suggestions {
                        eprintln!("    {}", s);
                    }
                }
            }
            eprintln!("\n  Run `lkr list` to see all stored keys.");
        }

        std::process::exit(1);
    }
}

fn cmd_set(store: &impl KeyStore, name: &str, kind_str: &str, force: bool) -> lkr_core::Result<()> {
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

fn cmd_get(
    store: &impl KeyStore,
    name: &str,
    show: bool,
    plain: bool,
    force_plain: bool,
    json: bool,
    stdout_is_tty: bool,
) -> lkr_core::Result<()> {
    // v0.2.0 TTY guard: comprehensive non-interactive protection.
    // Prevents AI agent / prompt-injection key exfiltration via pipe.
    //
    // Allowed in non-TTY:
    //   --force-plain  (explicit user override — warning emitted)
    //   --json         (masked values only, no --show)
    // Blocked in non-TTY:
    //   everything else (bare get, --show, --plain, --json --show)
    if !stdout_is_tty && !force_plain {
        let json_masked_only = json && !show;
        if !json_masked_only {
            return Err(lkr_core::Error::TtyGuard {
                message: "`lkr get` is blocked in non-interactive environments.\n  \
                    This prevents AI agents from extracting raw API keys via pipe.\n\n  \
                    Allowed alternatives:\n    \
                    lkr get <key> --json          (masked value only)\n    \
                    lkr get <key> --force-plain   (raw value, use with caution)\n    \
                    lkr exec -- <command>          (inject as env var)"
                    .to_string(),
            });
        }
    }

    if force_plain && !stdout_is_tty {
        eprintln!("Warning: outputting raw key value in non-interactive environment.");
    }

    let (value, kind) = store.get(name)?;

    if plain || force_plain {
        // Raw value only, no newline — for piping
        print!("{}", &*value);
        io::stdout().flush().ok();
        return Ok(());
    }

    // Copy to clipboard with 30s auto-clear.
    // Security: skip clipboard in non-interactive environments to prevent
    // agent bypass via `lkr get key && pbpaste`.
    let clipboard_ok = if !stdout_is_tty {
        eprintln!("Clipboard copy skipped (non-interactive environment).");
        false
    } else {
        match arboard::Clipboard::new().and_then(|mut cb| cb.set_text(&*value)) {
            Ok(()) => {
                schedule_clipboard_clear(30);
                eprintln!("Copied to clipboard (auto-clears in 30s)");
                true
            }
            Err(e) => {
                eprintln!("Warning: clipboard unavailable ({})", e);
                false
            }
        }
    };

    if json {
        let display_value = if show {
            (*value).clone()
        } else {
            mask_value(&value)
        };
        let obj = serde_json::json!({
            "name": name,
            "kind": kind.to_string(),
            "value": display_value,
            "clipboard": clipboard_ok,
        });
        println!("{}", serde_json::to_string_pretty(&obj).unwrap());
    } else if show {
        println!("{}", &*value);
    } else {
        println!("  {}  ({})", mask_value(&value), kind);
    }

    Ok(())
}

fn cmd_list(store: &impl KeyStore, include_admin: bool, json: bool) -> lkr_core::Result<()> {
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
    println!("  {:<14} {:<20} {:<10} Value", "Provider", "Name", "Kind");
    println!("  {}", "-".repeat(60));
    for entry in &entries {
        println!(
            "  {:<14} {:<20} {:<10} {}",
            entry.provider, entry.name, entry.kind, entry.masked_value
        );
    }
    println!("\n  {} key(s) stored in Keychain", entries.len());

    Ok(())
}

fn cmd_usage(
    store: &impl KeyStore,
    provider: Option<&str>,
    refresh: bool,
    json: bool,
) -> lkr_core::Result<()> {
    let cache = lkr_core::UsageCache::default();

    let rt = tokio::runtime::Runtime::new()
        .map_err(|e| lkr_core::Error::Usage(format!("Failed to start async runtime: {}", e)))?;

    let providers: Vec<String> = match provider {
        Some(p) => vec![p.to_lowercase()],
        None => {
            let avail = lkr_core::available_providers(store)?;
            if avail.is_empty() {
                eprintln!("No admin keys registered for usage tracking.\n");
                eprintln!("  Register an admin key first:");
                eprintln!("    lkr set openai:admin --kind admin");
                eprintln!("    lkr set anthropic:admin --kind admin");
                return Ok(());
            }
            avail
        }
    };

    let mut reports = Vec::new();
    let mut errors = Vec::new();
    for p in &providers {
        match rt.block_on(lkr_core::fetch_cost(store, p, &cache, refresh)) {
            Ok(report) => reports.push(report),
            Err(e) => {
                eprintln!("  {}: {}", p, e);
                errors.push(e);
            }
        }
    }

    if json {
        println!("{}", serde_json::to_string_pretty(&reports).unwrap());
        // Return error if ALL fetches failed (partial success is OK)
        if reports.is_empty() && !errors.is_empty() {
            return Err(errors.remove(0));
        }
        return Ok(());
    }

    if reports.is_empty() {
        if errors.is_empty() {
            eprintln!("No usage data available.");
            return Ok(());
        }
        // All fetches failed — propagate the first error for exit code 1
        return Err(errors.remove(0));
    }

    for report in &reports {
        println!(
            "\n  {} — {} to {}",
            report.provider, report.period_start, report.period_end
        );
        println!("  {}", "-".repeat(50));

        for item in &report.line_items {
            println!(
                "    {:<30} {}",
                item.description,
                lkr_core::format_cost(item.cost_cents)
            );
        }

        println!(
            "  {:<32} {}",
            "Total",
            lkr_core::format_cost(report.total_cost_cents)
        );
    }

    if reports.len() > 1 {
        let grand_total: f64 = reports.iter().map(|r| r.total_cost_cents).sum();
        println!(
            "\n  {:<32} {}",
            "Grand Total",
            lkr_core::format_cost(grand_total)
        );
    }

    println!();
    Ok(())
}

fn cmd_gen(
    store: &impl KeyStore,
    template: &str,
    output: Option<&str>,
    force: bool,
    stdout_is_tty: bool,
) -> lkr_core::Result<()> {
    use std::path::Path;

    // v0.2.0 TTY guard: block gen in non-interactive environments unless --force.
    // Generated files contain resolved secrets — risky in agent/CI contexts.
    if !stdout_is_tty && !force {
        return Err(lkr_core::Error::TtyGuard {
            message: "`lkr gen` is blocked in non-interactive environments.\n  \
                Use `lkr exec -- <command>` to inject keys as env vars instead.\n  \
                Or use `lkr gen --force` to override."
                .to_string(),
        });
    }

    let template_path = Path::new(template);
    if !template_path.exists() {
        return Err(lkr_core::Error::Template(format!(
            "Template file not found: {}",
            template
        )));
    }

    // Derive output path: .env.example → .env, foo.template → foo
    let output_path = match output {
        Some(o) => std::path::PathBuf::from(o),
        None => {
            let name = template_path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy();
            let derived = if name.ends_with(".example") {
                name.trim_end_matches(".example").to_string()
            } else if name.ends_with(".template") {
                name.trim_end_matches(".template").to_string()
            } else {
                return Err(lkr_core::Error::Template(
                    "Cannot derive output path. Use -o to specify output file.".to_string(),
                ));
            };
            template_path
                .parent()
                .unwrap_or(Path::new("."))
                .join(derived)
        }
    };

    // Check if output exists and not --force
    if output_path.exists()
        && !force
        && !confirm(&format!(
            "Output file '{}' already exists. Overwrite? [y/N] ",
            output_path.display()
        ))
    {
        eprintln!("Cancelled.");
        return Ok(());
    }

    // .gitignore check (skipped outside git repos)
    if let Some(false) = lkr_core::check_gitignore(&output_path) {
        eprintln!(
            "Warning: '{}' is NOT in .gitignore. Generated files may contain secrets!",
            output_path.display()
        );
        eprintln!("  Consider adding it to .gitignore before committing.");
    }

    // Generate
    let result = lkr_core::generate(store, template_path, &output_path)?;

    // Report
    let resolved: Vec<_> = result
        .resolutions
        .iter()
        .filter(|r| r.key_name.is_some())
        .collect();
    let unresolved: Vec<_> = result
        .resolutions
        .iter()
        .filter(|r| r.key_name.is_none())
        .collect();

    if !resolved.is_empty() {
        eprintln!("  Resolved from Keychain:");
        for r in &resolved {
            eprintln!(
                "    {:<24} <- {}",
                r.placeholder,
                r.key_name.as_deref().unwrap_or("?")
            );
            if r.alternatives.len() > 1 {
                let others: Vec<&str> = r
                    .alternatives
                    .iter()
                    .filter(|a| Some(a.as_str()) != r.key_name.as_deref())
                    .map(|a| a.as_str())
                    .collect();
                if !others.is_empty() {
                    eprintln!("      (also available: {})", others.join(", "));
                }
            }
        }
    }

    if !unresolved.is_empty() {
        eprintln!("  Kept as-is (no matching key):");
        for r in &unresolved {
            eprintln!("    {}", r.placeholder);
        }
    }

    eprintln!(
        "\n  Generated: {} ({} resolved, {} unresolved)",
        output_path.display(),
        resolved.len(),
        unresolved.len()
    );

    Ok(())
}

fn cmd_migrate(store: &KeychainStore, dry_run: bool) -> lkr_core::Result<()> {
    let result = store.migrate(dry_run)?;

    if result.keys.is_empty() {
        eprintln!("No keys to migrate.");
        return Ok(());
    }

    if dry_run {
        eprintln!("  Would migrate {} key(s):", result.keys.len());
        for key in &result.keys {
            eprintln!(
                "    {} ({}) — add sync protection + lock protection",
                key.name, key.kind
            );
        }
        eprintln!("\n  Run `lkr migrate` (without --dry-run) to apply.");
    } else {
        for key in &result.keys {
            if key.success {
                eprintln!("    {} ({}) — migrated", key.name, key.kind);
            } else {
                eprintln!(
                    "    {} ({}) — FAILED: {}",
                    key.name,
                    key.kind,
                    key.error.as_deref().unwrap_or("unknown error")
                );
            }
        }
        eprintln!(
            "\n  Result: {} migrated, {} failed",
            result.migrated_count(),
            result.failed_count()
        );
    }

    Ok(())
}

fn cmd_rm(store: &impl KeyStore, name: &str, force: bool) -> lkr_core::Result<()> {
    if !force && !confirm(&format!("Remove key '{}'? [y/N] ", name)) {
        eprintln!("Cancelled.");
        return Ok(());
    }

    store.delete(name)?;
    eprintln!("Removed {}", name);
    Ok(())
}

fn cmd_exec(
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
        let mut pairs = Vec::new();
        for entry in &listed {
            if let Ok((value, _kind)) = store.get(&entry.name) {
                pairs.push((lkr_core::key_to_env_var(&entry.name), value));
            }
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use lkr_core::keymanager::MockStore;

    // -- TTY guard tests (stdout_is_tty injection) --

    fn setup_store_with_key() -> MockStore {
        let store = MockStore::new();
        store
            .set(
                "openai:prod",
                "sk-test-key-12345678",
                KeyKind::Runtime,
                false,
            )
            .unwrap();
        store
    }

    fn is_tty_guard_error(err: &lkr_core::Error) -> bool {
        matches!(err, lkr_core::Error::TtyGuard { .. })
    }

    #[test]
    fn test_get_non_tty_bare_blocked() {
        let store = setup_store_with_key();
        // lkr get key (no flags, non-TTY) → blocked
        let result = cmd_get(&store, "openai:prod", false, false, false, false, false);
        assert!(result.is_err());
        assert!(is_tty_guard_error(&result.unwrap_err()));
    }

    #[test]
    fn test_get_non_tty_show_blocked() {
        let store = setup_store_with_key();
        // lkr get key --show (non-TTY) → blocked
        let result = cmd_get(&store, "openai:prod", true, false, false, false, false);
        assert!(result.is_err());
        assert!(is_tty_guard_error(&result.unwrap_err()));
    }

    #[test]
    fn test_get_non_tty_plain_blocked() {
        let store = setup_store_with_key();
        // lkr get key --plain (non-TTY) → blocked
        let result = cmd_get(&store, "openai:prod", false, true, false, false, false);
        assert!(result.is_err());
        assert!(is_tty_guard_error(&result.unwrap_err()));
    }

    #[test]
    fn test_get_non_tty_json_show_blocked() {
        let store = setup_store_with_key();
        // lkr get key --json --show (non-TTY) → blocked (raw value in JSON)
        let result = cmd_get(&store, "openai:prod", true, false, false, true, false);
        assert!(result.is_err());
        assert!(is_tty_guard_error(&result.unwrap_err()));
    }

    #[test]
    fn test_get_non_tty_json_masked_passes() {
        let store = setup_store_with_key();
        // lkr get key --json (non-TTY, no --show) → pass (masked value)
        let result = cmd_get(&store, "openai:prod", false, false, false, true, false);
        assert!(result.is_ok());
    }

    #[test]
    fn test_get_non_tty_force_plain_passes() {
        let store = setup_store_with_key();
        // lkr get key --force-plain (non-TTY) → pass (explicit override)
        let result = cmd_get(&store, "openai:prod", false, false, true, false, false);
        assert!(result.is_ok());
    }

    #[test]
    fn test_get_tty_bare_passes() {
        let store = setup_store_with_key();
        // lkr get key (TTY) → pass (clipboard copy + masked display)
        // Note: clipboard ops will fail in test env, but the function should succeed
        let result = cmd_get(&store, "openai:prod", false, false, false, false, true);
        assert!(result.is_ok());
    }

    // -- gen TTY guard tests --

    #[test]
    fn test_gen_non_tty_blocked() {
        let store = setup_store_with_key();
        // lkr gen (non-TTY, no --force) → blocked
        let result = cmd_gen(&store, "/nonexistent/template", None, false, false);
        assert!(result.is_err());
        assert!(is_tty_guard_error(&result.unwrap_err()));
    }

    #[test]
    fn test_gen_non_tty_force_passes() {
        let store = setup_store_with_key();
        // lkr gen --force (non-TTY) → passes TTY guard (may fail on file I/O, that's OK)
        let result = cmd_gen(&store, "/nonexistent/template", None, true, false);
        // Should NOT be a TtyGuard error — it will be a Template error (file not found)
        assert!(result.is_err());
        assert!(!is_tty_guard_error(&result.unwrap_err()));
    }

    // -- exec tests --

    #[test]
    fn test_cmd_exec_rejects_admin_key() {
        let store = MockStore::new();
        store
            .set("openai:admin", "sk-admin-secret", KeyKind::Admin, false)
            .unwrap();

        let result = cmd_exec(
            &store,
            &["openai:admin".to_string()],
            &["echo".to_string(), "hello".to_string()],
            false,
            false,
        );

        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("admin key"));
        assert!(err_msg.contains("openai:admin"));
    }

    #[test]
    fn test_cmd_exec_allows_runtime_key() {
        let store = MockStore::new();
        store
            .set(
                "openai:prod",
                "sk-test-key",
                lkr_core::KeyKind::Runtime,
                false,
            )
            .unwrap();

        // cmd_exec calls std::process::exit() on success — can't assert here.
        // Admin-guard rejection is covered by test_cmd_exec_rejects_admin_key.
    }

    #[test]
    fn test_cmd_exec_rejects_multiple_admin_keys() {
        let store = MockStore::new();
        store
            .set("openai:admin", "sk-admin-1", KeyKind::Admin, false)
            .unwrap();
        store
            .set("anthropic:admin", "sk-admin-2", KeyKind::Admin, false)
            .unwrap();

        // First admin key should be caught
        let result = cmd_exec(
            &store,
            &["openai:admin".to_string(), "anthropic:admin".to_string()],
            &["echo".to_string()],
            false,
            false,
        );

        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("admin key"));
    }

    #[test]
    fn test_cmd_exec_rejects_mixed_runtime_admin() {
        let store = MockStore::new();
        store
            .set("openai:prod", "sk-rt", KeyKind::Runtime, false)
            .unwrap();
        store
            .set("anthropic:admin", "sk-adm", KeyKind::Admin, false)
            .unwrap();

        let result = cmd_exec(
            &store,
            &["openai:prod".to_string(), "anthropic:admin".to_string()],
            &["echo".to_string()],
            false,
            false,
        );

        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("anthropic:admin"));
    }
}
