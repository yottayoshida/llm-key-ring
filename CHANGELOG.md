# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.4] - 2026-03-14

### Fixed

- **`lkr harden` ACL chicken-and-egg**: after `brew upgrade`, the binary's cdhash changes and all keys become ACL-blocked. `harden` now uses interactive Keychain access (macOS authorization dialog) to read key values before re-creating them with a fresh ACL. Previously, `harden` tried non-interactive reads, which failed immediately on every key
- **`-25293` misdiagnosed as wrong password**: `errSecAuthFailed` from `SecKeychainFindGenericPassword` is now checked for ACL cdhash mismatch (same as `-25308`), returning `AclMismatch` instead of `PasswordWrong`
- **`-128` error mapping**: `errSecUserCanceled` now maps to `Error::UserCanceled` (dedicated variant) instead of a generic `Error::Keychain` string

### Changed

- `lkr harden` UX overhaul:
  - Pre-flight briefing explains upcoming macOS dialogs and recommends "Always Allow"
  - Progress counter: `[1/5] key-name — hardened / skipped / FAILED`
  - Dialog deny → `skipped (denied)` with re-run guidance
  - Set failure → warns about potential key loss with `lkr set` recovery instructions
  - GUI-less environment (SSH, CI, launchd) → dedicated error message
  - `--dry-run` now warns about dialog prompts in live mode
- SECURITY.md roadmap: v0.3.4 = harden fix, v0.3.5 = doctor (shifted)

### Security

- `get_interactive()` is `pub` + `#[doc(hidden)]` on `KeychainStore` — not on the `KeyStore` trait. This prevents accidental use outside `lkr harden`. Normal reads remain non-interactive
- Note: macOS "Always Allow" granularity (per-cdhash vs per-app) is not fully verified. `set` rebuilds explicit ACL regardless, so the final security posture is correct

## [0.3.3] - 2026-03-13

### Fixed

- **`lkr migrate` circular error**: `exists()` delegated to `get()`, which returns a "run `lkr migrate`" error for keys in login.keychain — causing migrate itself to fail on every key. Now `exists()` checks the custom keychain directly, bypassing legacy detection

## [0.3.2] - 2026-03-13

Operational quality release: bug fixes, code structure improvements, and documentation.

### Fixed

- `list` command N+1 query: fetched key values unnecessarily for each entry; now uses metadata-only query
- `list` silently skipped keys when JSON deserialization failed; now returns an error

### Changed

- CLI refactored from single `main.rs` into per-command modules (`cmd/*.rs`) and `util.rs`
- Added `// SAFETY:` comments to all `unsafe` blocks in `lkr-core`

### Removed

- Unimplemented `lkr doctor` references removed from CHANGELOG and SECURITY.md (deferred to v0.3.3)

## [0.3.1] - 2026-03-07

Security hardening patch addressing code review feedback.

### Fixed

- **CRITICAL**: ACL fail-open → fail-closed. `build_access()` failure now returns an error instead of silently storing items without ACL protection
- **CRITICAL**: `keychain_path()` no longer silently falls back to `"."` when `$HOME` is unset. Returns `Error::Keychain` instead
- `-25308` (errSecInteractionNotAllowed) auto-diagnosis: when `item_ref` is available, `is_acl_blocked()` is called to distinguish ACL mismatch from keychain-locked, returning `AclMismatch` for better CLI guidance
- `--force` overwrite now builds ACL before deleting the old key. Previously, ACL failure after delete would cause key loss

### Changed

- `StoredEntry` now derives `Zeroize + ZeroizeOnDrop` — API key values are automatically zeroed from memory when the struct is dropped (removed redundant manual `zeroize()` call)

## [0.3.0] - 2026-03-07

Custom Keychain + Legacy ACL release. Pure FFI implementation (no CLI subprocess calls).

### Added

- `lkr init` — Create a dedicated `lkr.keychain-db` with password, auto-lock (5 min), lock-on-sleep
- `lkr lock` — Explicitly lock the custom keychain
- `lkr harden` — Re-apply Legacy ACL to all keys for the current binary path
- Custom Keychain (`lkr.keychain-db`) — isolated from login.keychain, never added to search list (I1/SR9)
- Legacy ACL (`SecAccessCreate` + `SecTrustedApplicationCreateFromPath`) — restricts key access to the LKR binary (Layer 2 defense)
- `disable_user_interaction` RAII guard — prevents macOS GUI dialogs during all keychain operations (SR12/I7)
- `crates/lkr-core/src/custom_keychain.rs` — keychain lifecycle management (create, open, unlock, lock, delete)
- `crates/lkr-core/src/acl.rs` — ACL construction and diagnostics (`build_access`, `is_acl_blocked`)
- `crates/lkr-core/src/error.rs` — expanded error types with OS status constants
- `crates/lkr-core/tests/keychain_integration.rs` — Tier 2 integration tests
- `docs/design-v030.md` — full design document for v0.3.0
- `docs/spike-report-v4.md` — CLI wrap spike report and lessons learned

### Changed

- **BREAKING**: All key storage now requires `lkr init` first. Keys are stored in `lkr.keychain-db` instead of login.keychain
- `KeyManager` now manages custom keychain lifecycle (open → unlock → operate → auto-lock)
- Password prompt uses `rpassword` with 3-retry loop
- All keychain FFI calls go through `keychain_raw` module (Pure FFI, no `security` CLI subprocess)

### Security

- Custom Keychain isolation: `lkr.keychain-db` is never in the default search list — other apps cannot discover LKR keys
- Legacy ACL: each key is bound to the LKR binary path via `SecTrustedApplicationCreateFromPath`
- Auto-lock: keychain locks after 5 minutes of inactivity and on sleep
- GUI dialog suppression: `SecKeychainSetUserInteractionAllowed(false)` prevents credential prompts from appearing

## [0.2.1] - 2026-03-03

Documentation-only patch. Updated threat model with Keychain ACL investigation results.

### Changed

- `docs/SECURITY.md`: Added "Keychain ACL Investigation" section documenting spike results (3 signing approaches tested, all failed without Apple Developer ID)
- `docs/SECURITY.md`: ACL-related items moved from "planned" to "known limitation" — Apple Developer Program ($99/year) required, not planned
- `docs/SECURITY.md`: Updated roadmap (removed Touch ID ACL from future versions)
- `README.md`: Updated roadmap — v0.3.0 is DX Improvement, v0.4.0 is MCP Server

## [0.2.0] - 2026-03-03

Security hardening release. Keychain attribute hardening + comprehensive TTY guard.

### Added

- `lkr migrate` — Migrate v0.1.0 keys to v0.2.0 format (adds iCloud sync protection + lock protection)
- `lkr migrate --dry-run` — Preview migration without applying changes
- `lkr exec --verbose` — Show injected env var names on stderr
- Keychain attributes on all new keys: `kSecAttrSynchronizable: false` + `kSecAttrAccessibleWhenUnlocked`
- `TtyGuard` error type with exit code 2 for non-interactive environment blocks
- 9 new tests for TTY guard matrix (7 for `get`, 2 for `gen`)
- `docs/SECURITY.md`: Attack surface comparison table (.env vs LKR), FFI memory gap documentation, v0.3.0 roadmap
- `README.md`: Upgrading from v0.1.x guide, exit code table, roadmap

### Changed

- **BREAKING**: `lkr get` is now blocked in non-interactive environments by default (exit code 2). Previously only `--plain`/`--show` were blocked. Use `--json` (masked values) or `--force-plain` to override.
- **BREAKING**: `lkr gen` is now blocked in non-interactive environments by default (exit code 2). Use `--force` to override.
- **BREAKING**: `lkr exec` stderr output is now silent by default in TTY mode. Use `--verbose` to see injected key names. Non-TTY mode emits a 1-line warning.
- Replaced `keyring` crate with direct `security-framework-sys` FFI calls for full Keychain attribute control
- All Keychain searches use `kSecAttrSynchronizableAny` for backward compatibility with v0.1.0 keys

### Removed

- `keyring` crate dependency (replaced by direct `security-framework-sys` FFI)

### Security

- iCloud Keychain sync disabled (`kSecAttrSynchronizable: false`) on all keys
- Locked device access blocked (`kSecAttrAccessibleWhenUnlocked`) on all keys
- Comprehensive TTY guard: `get` (all modes), `gen`, `exec` now covered
- `SECURITY.md` rewritten with honest threat model, attack surface comparison, and known limitations

## [0.1.0] - 2026-03-02

Initial release. Secure CLI for managing LLM API keys via macOS Keychain.

### Added

- `lkr set` — Store API keys interactively (never via CLI arguments)
- `lkr get` — Retrieve keys with masked display + clipboard auto-clear (30s)
- `lkr list` — List stored keys (runtime only by default)
- `lkr rm` — Delete keys with confirmation prompt
- `lkr exec` — Run commands with keys injected as env vars (safest method)
- `lkr gen` — Generate config files from templates (.env, JSON)
- `lkr usage` — Check API usage costs (OpenAI, Anthropic)
- TTY guard: `--plain` and `--show` blocked in non-interactive environments
- `zeroize` memory protection: keys zeroed on drop
- macOS Keychain backend via `security-framework`

### Changed

- **Behavior change**: `lkr exec -k` now rejects admin keys with an error. Previously, admin keys specified via `-k` were silently injected into child processes. This was inconsistent with the security model (admin keys are excluded from `exec` without `-k`). Use runtime keys only with `exec`.

### Security

- Admin key isolation: `lkr exec` only injects runtime keys; admin keys are never exposed to child processes
- `lkr gen` only resolves runtime keys in templates
- Generated files written with `0600` permissions
- `.gitignore` coverage check on generated files

[0.3.3]: https://github.com/yottayoshida/llm-key-ring/compare/v0.3.2...v0.3.3
[0.3.2]: https://github.com/yottayoshida/llm-key-ring/compare/v0.3.1...v0.3.2
[0.3.1]: https://github.com/yottayoshida/llm-key-ring/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/yottayoshida/llm-key-ring/compare/v0.2.1...v0.3.0
[0.2.1]: https://github.com/yottayoshida/llm-key-ring/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/yottayoshida/llm-key-ring/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/yottayoshida/llm-key-ring/releases/tag/v0.1.0
