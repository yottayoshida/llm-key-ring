use crate::util::schedule_clipboard_clear;
use lkr_core::{KeyStore, mask_value};
use std::io::{self, Write};

pub(crate) fn cmd_get(
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
