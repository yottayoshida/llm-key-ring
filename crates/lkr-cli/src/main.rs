use clap::{Parser, Subcommand};
use lkr_core::{KeyKind, KeyStore, KeychainStore};
use std::io::{self, Write};

#[derive(Parser)]
#[command(
    name = "lkr",
    about = "LLM Key Ring — manage LLM API keys via macOS Keychain",
    version,
    after_help = "Examples:\n  lkr set openai:prod\n  lkr get openai:prod\n  lkr list\n  lkr rm openai:prod"
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

        /// Output raw value only (for piping)
        #[arg(long)]
        plain: bool,
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

fn mask_value(value: &str) -> String {
    let chars: Vec<char> = value.chars().collect();
    let len = chars.len();
    if len <= 8 {
        return "*".repeat(len);
    }
    let prefix: String = chars[..4].iter().collect();
    let suffix: String = chars[len - 4..].iter().collect();
    format!("{}...{}", prefix, suffix)
}

fn main() {
    let cli = Cli::parse();
    let store = KeychainStore::new();

    let result = match cli.command {
        Commands::Set { name, kind, force } => cmd_set(&store, &name, &kind, force),
        Commands::Get { name, show, plain } => cmd_get(&store, &name, show, plain, cli.json),
        Commands::List { all } => cmd_list(&store, all, cli.json),
        Commands::Rm { name, force } => cmd_rm(&store, &name, force),
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
    json: bool,
) -> lkr_core::Result<()> {
    let (value, kind) = store.get(name)?;

    if plain {
        // Raw value only, no newline — for piping
        print!("{}", value);
        io::stdout().flush().ok();
        return Ok(());
    }

    // Copy to clipboard
    // TODO: Implement 30s auto-clear (spawn background process)
    let clipboard_ok =
        match arboard::Clipboard::new().and_then(|mut cb| cb.set_text(&value)) {
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
            value.clone()
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
        println!("{}", value);
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
            eprintln!("No keys listed.\n");
            eprintln!("  Note: 'list' does not yet enumerate Keychain entries.");
            eprintln!("  Use 'lkr get <name>' to retrieve a specific key.\n");
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
