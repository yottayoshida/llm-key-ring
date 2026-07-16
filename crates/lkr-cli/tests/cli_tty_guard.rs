//! CLI-level check that the non-TTY stdin guard actually maps to exit code 2
//! when the `lkr` binary runs end-to-end, not just at the `guard_stdin_tty()`
//! function level (covered by unit tests in `src/util.rs`).
//!
//! Uses an isolated `HOME` (never the real one — see
//! `.claude/rules/security.md` §実クレデンシャルストアへの操作禁止) so
//! `custom_keychain::is_initialized()` reports `false`, letting `lkr init`
//! reach the guard without any Keychain fixture.

use std::path::PathBuf;
use std::process::{Command, Stdio};
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
}

impl Drop for IsolatedHome {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn lkr_init_with_non_tty_stdin_exits_2() {
    let home = IsolatedHome::new();

    let output = Command::new(env!("CARGO_BIN_EXE_lkr"))
        .arg("init")
        .env("HOME", &home.0)
        .stdin(Stdio::null()) // no controlling terminal — not just an empty pipe
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn lkr init");

    assert_eq!(
        output.status.code(),
        Some(2),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("interactive terminal"),
        "stderr did not mention the TTY guard: {stderr}"
    );
}
