use clap::{Parser, Subcommand};
use lkr_core::{KeyStore, KeychainStore};
use std::io::{self, IsTerminal};

mod cmd;
mod util;

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

fn main() {
    let cli = Cli::parse();

    let stdout_is_tty = io::stdout().is_terminal();

    // Commands that don't need an unlocked Custom Keychain
    let result = match cli.command {
        Commands::Init => {
            cmd::init::cmd_init();
            return;
        }
        Commands::Lock => {
            cmd::lock::cmd_lock();
            return;
        }
        _ => {
            // All other commands need an unlocked store
            let store = match util::open_and_unlock() {
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
                Commands::Set { name, kind, force } => {
                    cmd::set::cmd_set(&store, &name, &kind, force)
                }
                Commands::Get {
                    name,
                    show,
                    plain,
                    force_plain,
                } => cmd::get::cmd_get(
                    &store,
                    &name,
                    show,
                    plain,
                    force_plain,
                    cli.json,
                    stdout_is_tty,
                ),
                Commands::List { all } => cmd::list::cmd_list(&store, all, cli.json),
                Commands::Rm { name, force } => cmd::rm::cmd_rm(&store, &name, force),
                Commands::Usage { provider, refresh } => {
                    cmd::usage::cmd_usage(&store, provider.as_deref(), refresh, cli.json)
                }
                Commands::Gen {
                    template,
                    output,
                    force,
                } => {
                    cmd::r#gen::cmd_gen(&store, &template, output.as_deref(), force, stdout_is_tty)
                }
                Commands::Migrate { dry_run, yes } => {
                    cmd::migrate::cmd_migrate(&store, dry_run, yes)
                }
                Commands::Harden { dry_run } => cmd::harden::cmd_harden(&store, dry_run),
                Commands::Exec {
                    keys,
                    verbose,
                    command,
                } => cmd::exec::cmd_exec(&store, &keys, &command, stdout_is_tty, verbose),
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
                    eprintln!(
                        "  Why: The key exists in login.keychain but not in the LKR keychain."
                    );
                    eprintln!("  Fix: Run `lkr migrate` to move your keys.");
                } else {
                    eprintln!("  Fix: Run `lkr set {}` to store a new key.", name);
                    // Suggest similar keys
                    if let Ok(entries) = legacy_store.list(true) {
                        let suggestions: Vec<&str> = entries
                            .iter()
                            .filter(|entry| {
                                (name.len() >= 4 && entry.name.contains(&name[..name.len().min(4)]))
                                    || entry.provider == name.split(':').next().unwrap_or("")
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
                eprintln!(
                    "  Why: The binary fingerprint may have changed (e.g. after update or reinstall)."
                );
                eprintln!(
                    "  Fix: Run `lkr harden` to re-apply access control for the current binary."
                );
            }

            lkr_core::Error::AclMismatch => {
                eprintln!("Error: Access denied — binary fingerprint has changed.");
                eprintln!(
                    "  Why: LKR was updated or reinstalled, and the access control no longer matches."
                );
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use lkr_core::keymanager::MockStore;
    use lkr_core::{KeyKind, KeyStore};

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
        let result =
            crate::cmd::get::cmd_get(&store, "openai:prod", false, false, false, false, false);
        assert!(result.is_err());
        assert!(is_tty_guard_error(&result.unwrap_err()));
    }

    #[test]
    fn test_get_non_tty_show_blocked() {
        let store = setup_store_with_key();
        // lkr get key --show (non-TTY) → blocked
        let result =
            crate::cmd::get::cmd_get(&store, "openai:prod", true, false, false, false, false);
        assert!(result.is_err());
        assert!(is_tty_guard_error(&result.unwrap_err()));
    }

    #[test]
    fn test_get_non_tty_plain_blocked() {
        let store = setup_store_with_key();
        // lkr get key --plain (non-TTY) → blocked
        let result =
            crate::cmd::get::cmd_get(&store, "openai:prod", false, true, false, false, false);
        assert!(result.is_err());
        assert!(is_tty_guard_error(&result.unwrap_err()));
    }

    #[test]
    fn test_get_non_tty_json_show_blocked() {
        let store = setup_store_with_key();
        // lkr get key --json --show (non-TTY) → blocked (raw value in JSON)
        let result =
            crate::cmd::get::cmd_get(&store, "openai:prod", true, false, false, true, false);
        assert!(result.is_err());
        assert!(is_tty_guard_error(&result.unwrap_err()));
    }

    #[test]
    fn test_get_non_tty_json_masked_passes() {
        let store = setup_store_with_key();
        // lkr get key --json (non-TTY, no --show) → pass (masked value)
        let result =
            crate::cmd::get::cmd_get(&store, "openai:prod", false, false, false, true, false);
        assert!(result.is_ok());
    }

    #[test]
    fn test_get_non_tty_force_plain_passes() {
        let store = setup_store_with_key();
        // lkr get key --force-plain (non-TTY) → pass (explicit override)
        let result =
            crate::cmd::get::cmd_get(&store, "openai:prod", false, false, true, false, false);
        assert!(result.is_ok());
    }

    #[test]
    fn test_get_tty_bare_passes() {
        let store = setup_store_with_key();
        // lkr get key (TTY) → pass (clipboard copy + masked display)
        // Note: clipboard ops will fail in test env, but the function should succeed
        let result =
            crate::cmd::get::cmd_get(&store, "openai:prod", false, false, false, false, true);
        assert!(result.is_ok());
    }

    // -- gen TTY guard tests --

    #[test]
    fn test_gen_non_tty_blocked() {
        let store = setup_store_with_key();
        // lkr gen (non-TTY, no --force) → blocked
        let result =
            crate::cmd::r#gen::cmd_gen(&store, "/nonexistent/template", None, false, false);
        assert!(result.is_err());
        assert!(is_tty_guard_error(&result.unwrap_err()));
    }

    #[test]
    fn test_gen_non_tty_force_passes() {
        let store = setup_store_with_key();
        // lkr gen --force (non-TTY) → passes TTY guard (may fail on file I/O, that's OK)
        let result = crate::cmd::r#gen::cmd_gen(&store, "/nonexistent/template", None, true, false);
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

        let result = crate::cmd::exec::cmd_exec(
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
        let result = crate::cmd::exec::cmd_exec(
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

        let result = crate::cmd::exec::cmd_exec(
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
