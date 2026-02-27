use clap::{Parser, Subcommand};
use lkr_core::{KeyKind, KeyStore, KeychainStore, mask_value};
use std::io::{self, IsTerminal, Write};

#[derive(Parser)]
#[command(
    name = "lkr",
    about = "LLM Key Ring — manage LLM API keys via macOS Keychain",
    version,
    after_help = "Examples:\n  lkr set openai:prod\n  lkr get openai:prod\n  lkr list\n  lkr rm openai:prod\n  lkr gen .env.example -o .env"
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
        Commands::Gen {
            template,
            output,
            force,
        } => cmd_gen(&store, &template, output.as_deref(), force),
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
    eprint!("Enter API key for {}: ", name);
    io::stderr().flush().ok();
    let value = rpassword::read_password().map_err(|e| {
        lkr_core::Error::Keychain(format!("Failed to read input: {}", e))
    })?;

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

    // Copy to clipboard
    // TODO: Implement 30s auto-clear (spawn background process)
    let clipboard_ok =
        match arboard::Clipboard::new().and_then(|mut cb| cb.set_text(&*value)) {
            Ok(()) => {
                eprintln!("Copied to clipboard");
                true
            }
            Err(e) => {
                eprintln!("Warning: clipboard unavailable ({})", e);
                false
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
