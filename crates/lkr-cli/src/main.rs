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

    /// Run a command with Keychain keys injected as environment variables.
    ///
    /// Keys never appear in stdout, files, or clipboard — the safest way
    /// to pass secrets to child processes.
    Exec {
        /// Key names to inject (e.g. -k openai:prod). Omit to inject all runtime keys.
        #[arg(short = 'k', long = "key")]
        keys: Vec<String>,

        /// The command and arguments to run (after --)
        #[arg(trailing_var_arg = true, required = true)]
        command: Vec<String>,
    },
}

fn parse_kind(s: &str) -> Result<KeyKind, String> {
    match s {
        "runtime" => Ok(KeyKind::Runtime),
        "admin" => Ok(KeyKind::Admin),
        _ => Err(format!(
            "Invalid kind '{}'. Must be 'runtime' or 'admin'.",
            s
        )),
    }
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

    let result = match cli.command {
        Commands::Set { name, kind, force } => cmd_set(&store, &name, &kind, force),
        Commands::Get {
            name,
            show,
            plain,
            force_plain,
        } => cmd_get(&store, &name, show, plain, force_plain, cli.json),
        Commands::List { all } => cmd_list(&store, all, cli.json),
        Commands::Rm { name, force } => cmd_rm(&store, &name, force),
        Commands::Usage { provider, refresh } => cmd_usage(&store, provider.as_deref(), refresh, cli.json),
        Commands::Gen {
            template,
            output,
            force,
        } => cmd_gen(&store, &template, output.as_deref(), force),
        Commands::Exec { keys, command } => cmd_exec(&store, &keys, &command),
    };

    if let Err(e) = result {
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
    let kind = parse_kind(kind_str).map_err(|reason| lkr_core::Error::InvalidKeyName {
        name: name.to_string(),
        reason,
    })?;

    // Read value from prompt (not CLI args — prevents shell history exposure)
    // Wrapped in Zeroizing to zero memory on drop.
    eprint!("Enter API key for {}: ", name);
    io::stderr().flush().ok();
    let value = Zeroizing::new(rpassword::read_password().map_err(|e| {
        lkr_core::Error::Keychain(format!("Failed to read input: {}", e))
    })?);

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
) -> lkr_core::Result<()> {
    let is_tty = io::stdout().is_terminal();

    // TTY guard: block --plain and --show in non-interactive environments
    // to prevent agent IDE attacks (Antigravity-style prompt injection).
    if (plain || show) && !is_tty && !force_plain {
        eprintln!("Error: --plain and --show are blocked in non-interactive environments.");
        eprintln!("  This prevents AI agents from extracting raw API keys via pipe.");
        eprintln!("  Use --force-plain to override (at your own risk).");
        std::process::exit(2);
    }

    if force_plain && !is_tty {
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
    let clipboard_ok = if !is_tty {
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
    println!(
        "  {:<14} {:<20} {:<10} Value",
        "Provider", "Name", "Kind"
    );
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
        println!("\n  {:<32} {}", "Grand Total", lkr_core::format_cost(grand_total));
    }

    println!();
    Ok(())
}

fn cmd_gen(
    store: &impl KeyStore,
    template: &str,
    output: Option<&str>,
    force: bool,
) -> lkr_core::Result<()> {
    use std::path::Path;

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
    if output_path.exists() && !force {
        eprint!(
            "Output file '{}' already exists. Overwrite? [y/N] ",
            output_path.display()
        );
        io::stderr().flush().ok();
        let mut input = String::new();
        io::stdin().read_line(&mut input).ok();
        if !input.trim().eq_ignore_ascii_case("y") {
            eprintln!("Cancelled.");
            return Ok(());
        }
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
    let resolved: Vec<_> = result.resolutions.iter().filter(|r| r.key_name.is_some()).collect();
    let unresolved: Vec<_> = result.resolutions.iter().filter(|r| r.key_name.is_none()).collect();

    if !resolved.is_empty() {
        eprintln!("  Resolved from Keychain:");
        for r in &resolved {
            eprintln!(
                "    {:<24} <- {}",
                r.placeholder,
                r.key_name.as_deref().unwrap_or("?")
            );
            if r.alternatives.len() > 1 {
                let others: Vec<&str> = r.alternatives.iter()
                    .filter(|a| Some(a.as_str()) != r.key_name.as_deref())
                    .map(|a| a.as_str())
                    .collect();
                if !others.is_empty() {
                    eprintln!(
                        "      (also available: {})",
                        others.join(", ")
                    );
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

fn cmd_rm(store: &impl KeyStore, name: &str, force: bool) -> lkr_core::Result<()> {
    if !force {
        eprint!("Remove key '{}'? [y/N] ", name);
        io::stderr().flush().ok();
        let mut input = String::new();
        io::stdin().read_line(&mut input).ok();
        if !input.trim().eq_ignore_ascii_case("y") {
            eprintln!("Cancelled.");
            return Ok(());
        }
    }

    store.delete(name)?;
    eprintln!("Removed {}", name);
    Ok(())
}

fn cmd_exec(
    store: &impl KeyStore,
    keys: &[String],
    command: &[String],
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
                let env_var = lkr_core::key_to_env_var(&entry.name).unwrap_or_else(|| {
                    // Unknown provider → use key name as env var (uppercased, : → _)
                    entry.name.to_uppercase().replace(':', "_")
                });
                pairs.push((env_var, value));
            }
        }
        pairs
    } else {
        // Specific keys requested
        let mut pairs = Vec::new();
        for key_name in keys {
            let (value, _kind) = store.get(key_name)?;
            let env_var = lkr_core::key_to_env_var(key_name).unwrap_or_else(|| {
                // Unknown provider → use key name as env var (uppercased, : → _)
                key_name.to_uppercase().replace(':', "_")
            });
            pairs.push((env_var, value));
        }
        pairs
    };

    if entries.is_empty() {
        eprintln!("Warning: no keys matched. Running command without injected env vars.");
    } else {
        eprintln!("Injecting {} key(s) as env vars:", entries.len());
        for (env_var, _) in &entries {
            eprintln!("  {}", env_var);
        }
    }

    // Build and exec child process
    let mut child = std::process::Command::new(&command[0]);
    child.args(&command[1..]);

    // Inject keys as environment variables
    for (env_var, value) in &entries {
        child.env(env_var, &**value);
    }

    let status = child
        .status()
        .map_err(|e| lkr_core::Error::Usage(format!("Failed to execute '{}': {}", command[0], e)))?;

    // Propagate child exit code
    std::process::exit(status.code().unwrap_or(1));
}
