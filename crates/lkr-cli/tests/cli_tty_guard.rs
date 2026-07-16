//! CLI-level check that the non-TTY stdin guard actually maps to exit code 2
//! when the `lkr` binary runs end-to-end, not just at the `guard_stdin_tty()`
//! function level (covered by unit tests in `src/util.rs`).
//!
//! Uses an isolated `HOME` (never the real one — see
//! `.claude/rules/security.md` §実クレデンシャルストアへの操作禁止), so no
//! real Keychain is ever touched. Two entry points reach the guard:
//! - `cmd_init`, when no `lkr.keychain-db` exists yet at the isolated HOME
//! - `open_and_unlock` (used by `set`/`get`/`list`/...), which only checks
//!   `keychain_path().exists()` before the guard — an empty marker file at
//!   that path is enough to reach it, no valid/unlockable keychain needed.

use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};

static TEST_COUNTER: AtomicU32 = AtomicU32::new(0);

/// A throwaway `HOME` directory, isolated from the real one. Cleaned up on drop.
struct IsolatedHome(PathBuf);

impl IsolatedHome {
    fn new() -> Self {
        let id = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
        let pid = std::process::id();
        let path = PathBuf::from(format!("/tmp/lkr-cli-test-home-{pid}-{id}"));
        std::fs::create_dir_all(&path).expect("create isolated HOME");
        Self(path)
    }

    /// Drop an empty marker file at the resolved keychain path, so
    /// `custom_keychain::is_initialized()` (which only checks `.exists()`)
    /// reports `true` without a real, unlockable keychain.
    fn mark_initialized(&self) {
        let keychain_dir = self.0.join("Library").join("Keychains");
        std::fs::create_dir_all(&keychain_dir).expect("create Keychains dir");
        std::fs::write(keychain_dir.join("lkr.keychain-db"), b"").expect("write marker file");
    }
}

impl Drop for IsolatedHome {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn run_lkr(home: &IsolatedHome, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_lkr"))
        .args(args)
        .env("HOME", &home.0)
        .stdin(Stdio::null()) // no controlling terminal — not just an empty pipe
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap_or_else(|e| panic!("spawn `lkr {}`: {e}", args.join(" ")))
}

fn assert_exits_2_with_tty_guard_message(output: &Output) {
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(2), "stderr: {stderr}");
    assert!(
        stderr.contains("interactive terminal"),
        "stderr did not mention the TTY guard: {stderr}"
    );
}

#[test]
fn lkr_init_with_non_tty_stdin_exits_2() {
    let home = IsolatedHome::new();
    let output = run_lkr(&home, &["init"]);
    assert_exits_2_with_tty_guard_message(&output);
}

#[test]
fn lkr_set_with_non_tty_stdin_exits_2_before_keychain_open() {
    let home = IsolatedHome::new();
    home.mark_initialized();
    let output = run_lkr(&home, &["set", "openai:test"]);
    assert_exits_2_with_tty_guard_message(&output);
}
