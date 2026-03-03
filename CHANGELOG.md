# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

[0.2.1]: https://github.com/yottayoshida/llm-key-ring/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/yottayoshida/llm-key-ring/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/yottayoshida/llm-key-ring/releases/tag/v0.1.0
