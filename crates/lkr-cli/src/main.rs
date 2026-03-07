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

    /// Initialize LKR secure keychain (run once after install)
    Init,

    /// Lock the LKR keychain
    Lock,

    /// Re-apply ACL to all keys (run after binary update/reinstall)
    Harden {
        /// Preview changes without applying
        #[arg(long)]
        dry_run: bool,
    },

    /// Migrate keys from login.keychain to LKR keychain
    Migrate {
        /// Preview changes without applying
        #[arg(long)]
        dry_run: bool,

        /// Skip confirmation prompt
        #[arg(long)]
        yes: bool,
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

/// Open and unlock the Custom Keychain with password retry.
///
/// Returns a v0.3.0 KeychainStore ready for operations.
/// Prompts for password up to 3 times.
fn open_and_unlock() -> lkr_core::Result<KeychainStore> {
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
                    eprintln!(
                        "Wrong password. ({}/{} attempts)",
                        attempt, MAX_RETRIES
                    );
                } else {
                    return Err(lkr_core::Error::PasswordWrong);
                }
            }
            Err(e) => return Err(e),
        }
    }

    Err(lkr_core::Error::PasswordWrong)
}

fn main() {
    let cli = Cli::parse();

    let stdout_is_tty = io::stdout().is_terminal();

    // Commands that don't need an unlocked Custom Keychain
    let result = match cli.command {
        Commands::Init => {
            cmd_init();
            return;
        }
        Commands::Lock => {
            cmd_lock();
            return;
        }
        _ => {
            // All other commands need an unlocked store
            let store = match open_and_unlock() {
                Ok(s) => s,
                Err(lkr_core::Error::NotInitialized) => {
                    eprintln!("Error: LKR keychain is not initialized.");
                    eprintln!("\n  Run `lkr init` to create the secure keychain.");
                    std::process::exit(1);
                }
                Err(lkr_core::Error::PasswordWrong) => {
                    eprintln!("Error: Wrong password. Maximum retries exceeded.");
                    std::process::exit(1);
                }
                Err(e) => {
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                }
            };

            match cli.command {
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
                Commands::Migrate { dry_run, yes } => {
                    cmd_migrate(&store, dry_run, yes)
                }
                Commands::Harden { dry_run } => cmd_harden(&store, dry_run),
                Commands::Exec {
                    keys,
                    verbose,
                    command,
                } => cmd_exec(&store, &keys, &command, stdout_is_tty, verbose),
                Commands::Init | Commands::Lock => unreachable!(),
            }
        }
    };

    if let Err(e) = result {
        // 3-layer error messages: WHAT happened / WHY / WHAT TO DO
        match &e {
            lkr_core::Error::TtyGuard { .. } => {
                eprintln!("Error: {}", e);
                std::process::exit(2);
            }

            lkr_core::Error::KeyNotFound { name } => {
                eprintln!("Error: Key '{}' not found.", name);
                // Check legacy login.keychain for migrate guidance
                let legacy_store = KeychainStore::new();
                if legacy_store.exists(name).unwrap_or(false) {
                    eprintln!("  Why: The key exists in login.keychain but not in the LKR keychain.");
                    eprintln!("  Fix: Run `lkr migrate` to move your keys.");
                } else {
                    eprintln!("  Fix: Run `lkr set {}` to store a new key.", name);
                    // Suggest similar keys
                    if let Ok(entries) = legacy_store.list(true) {
                        let suggestions: Vec<&str> = entries
                            .iter()
                            .filter(|entry| {
                                (name.len() >= 4
                                    && entry.name.contains(&name[..name.len().min(4)]))
                                    || entry.provider
                                        == name.split(':').next().unwrap_or("")
                            })
                            .map(|e| e.name.as_str())
                            .collect();
                        if !suggestions.is_empty() {
                            eprintln!("  Did you mean?");
                            for s in suggestions {
                                eprintln!("    {}", s);
                            }
                        }
                    }
                }
            }

            lkr_core::Error::KeyAlreadyExists { name } => {
                eprintln!("Error: Key '{}' already exists.", name);
                eprintln!("  Fix: Use `lkr set {} --force` to overwrite.", name);
            }

            lkr_core::Error::KeychainLocked => {
                eprintln!("Error: LKR keychain is locked.");
                eprintln!("  Why: The keychain auto-locks after 5 minutes or on sleep.");
                eprintln!("  Fix: Re-run the command — you'll be prompted for the password.");
            }

            lkr_core::Error::InteractionNotAllowed => {
                eprintln!("Error: Access denied to keychain item.");
                eprintln!("  Why: The binary fingerprint may have changed (e.g. after update or reinstall).");
                eprintln!("  Fix: Run `lkr harden` to re-apply access control for the current binary.");
            }

            lkr_core::Error::AclMismatch => {
                eprintln!("Error: Access denied — binary fingerprint has changed.");
                eprintln!("  Why: LKR was updated or reinstalled, and the access control no longer matches.");
                eprintln!("  Fix: Run `lkr harden` to refresh access control.");
            }

            lkr_core::Error::NotInitialized => {
                eprintln!("Error: LKR keychain is not initialized.");
                eprintln!("  Fix: Run `lkr init` to create the secure keychain.");
            }

            lkr_core::Error::PasswordWrong => {
                eprintln!("Error: Wrong keychain password.");
                eprintln!("  Fix: Try again with the correct password.");
            }

            lkr_core::Error::EmptyValue => {
                eprintln!("Error: Empty value is not allowed.");
                eprintln!("  Fix: Provide a non-empty API key value.");
            }

            _ => {
                eprintln!("Error: {}", e);
            }
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

/// Initialize the LKR secure keychain.
fn cmd_init() {
    if lkr_core::custom_keychain::is_initialized() {
        eprintln!("LKR keychain is already initialized.");
        eprintln!("  Path: {}", lkr_core::custom_keychain::keychain_path().display());
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
            eprintln!("  Path: {}", lkr_core::custom_keychain::keychain_path().display());
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

/// Lock the LKR keychain.
fn cmd_lock() {
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

/// Re-apply ACL to all keys (after binary update/reinstall).
fn cmd_harden(store: &KeychainStore, dry_run: bool) -> lkr_core::Result<()> {
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
            eprintln!("    {} ({})", entry.name, entry.kind);
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

/// Migrate keys from login.keychain to LKR custom keychain (v0.3.0).
fn cmd_migrate(store: &KeychainStore, dry_run: bool, yes: bool) -> lkr_core::Result<()> {
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
            eprintln!("    {} ({})", entry.name, entry.kind);
        }
        eprintln!("\n  Run `lkr migrate` (without --dry-run) to apply.");
        return Ok(());
    }

    // Confirmation
    if !yes {
        eprintln!("  Will migrate {} key(s) to LKR keychain:", to_migrate.len());
        for entry in &to_migrate {
            eprintln!("    {} ({})", entry.name, entry.kind);
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
        eprintln!(
            "\n  Legacy keys are still in login.keychain. You can remove them with:");
        eprintln!("    security delete-generic-password -s com.llm-key-ring -a <name>");
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
