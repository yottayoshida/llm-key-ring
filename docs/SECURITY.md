# Security & Threat Model

LLM Key Ring (LKR) is a local-first API key manager that stores secrets in macOS Keychain.
This document describes what LKR protects against, what it does NOT protect against,
and the design decisions behind each mitigation.

> **Honesty policy**: We document limitations alongside protections.
> Security through obscurity is not security.

## Attack Surface Comparison: `.env` vs LKR

| Attack Vector | `.env` plaintext | LKR v0.1.0 | LKR v0.2.0 | Notes |
|---------------|:---:|:---:|:---:|-------|
| `cat .env` / file read | Exposed | N/A | N/A | LKR eliminates persistent plaintext files |
| `grep -r API_KEY .` in project | Exposed | N/A | N/A | No files to grep |
| Git commit of secrets | Exposed | N/A | N/A | Nothing to commit |
| `security find-generic-password` (runtime) | N/A | Exposed | Exposed | Requires login Keychain access |
| `security find-generic-password` (admin) | N/A | Exposed | Exposed | ACL requires Apple Developer ID signing (see below) |
| Shell history exposure | Exposed (if `export KEY=...`) | Protected | Protected | `lkr set` uses hidden prompt |
| AI agent pipe exfiltration | Exposed (`cat .env`) | Partial | **Protected** | v0.2.0 blocks all non-TTY `get` access |
| iCloud Keychain sync to other devices | N/A | **Unprotected** | **Protected** | `kSecAttrSynchronizable: false` |
| Access while device is locked | N/A | **Unprotected** | **Protected** | `kSecAttrAccessibleWhenUnlocked` |
| Memory dump | Exposed (plaintext in memory) | Partial | Partial | `Zeroizing<String>` with FFI gap (see below) |

**Summary**: LKR v0.2.0 eliminates 3 of the 4 most common attack vectors (plaintext files,
git commits, shell history) and adds protection against iCloud sync, locked-device access,
and comprehensive AI agent exfiltration. The remaining gap (`security find-generic-password`)
requires Apple Developer ID code signing — see "Keychain ACL Investigation" below.

## Threat Overview

| # | Threat | Severity | Mitigation | Status |
|---|--------|----------|------------|--------|
| T1 | Plaintext keys in dotfiles (`.env`) | High | Keychain-encrypted storage; `.env` only generated on demand with `0600` permissions | Implemented |
| T2 | Shell history exposure | High | `lkr set` reads via hidden prompt (rpassword), never accepts key as CLI argument | Implemented |
| T3 | Clipboard residual | Medium | 30s auto-clear via detached background process; hash comparison prevents clearing user's own clipboard | Implemented |
| T4 | Terminal display leakage | Medium | Default masked output (`sk-p...wxyz`); `--show` required for plaintext | Implemented |
| T5 | Agent IDE key exfiltration | **Critical** | v0.2.0: All non-TTY `get` blocked (except `--json` masked, `--force-plain`); `gen` blocked; `exec` warns | **v0.2.0 hardened** |
| T6 | Memory dump / core dump | Medium | `zeroize::Zeroizing<String>` zeroes memory on drop (with FFI gap — see below) | Implemented |
| T7 | Admin key misuse via exec/templates | Medium | `lkr exec` and `lkr gen` only resolve `runtime` keys; `admin` keys are rejected | Implemented |
| T8 | Generated file committed to Git | Medium | `.gitignore` check warning on `lkr gen` output | Implemented |
| T9 | Log/error message key leakage | Low | Error messages never include key values; only key names | By design |
| T10 | iCloud Keychain sync | High | `kSecAttrSynchronizable: false` on all keys | **v0.2.0 new** |
| T11 | Locked device access | Medium | `kSecAttrAccessibleWhenUnlocked` on all keys | **v0.2.0 new** |

## Detailed Threat Analysis

### T5: Agent IDE Key Exfiltration (v0.2.0 hardened)

**Background**: AI-powered IDEs (Cursor, Copilot, Claude Code, etc.) can be manipulated via
prompt injection to execute commands that output secrets, exfiltrating API keys through the
AI agent's context window.

**v0.2.0 TTY guard matrix**:

| Command | TTY | Non-TTY | Notes |
|---------|:---:|:-------:|-------|
| `lkr get key` | Pass | **Block** (exit 2) | Default output leaks masked value + clipboard |
| `lkr get key --show` | Pass | **Block** (exit 2) | Raw value in terminal |
| `lkr get key --plain` | Pass | **Block** (exit 2) | Raw value for piping |
| `lkr get key --json` | Pass | **Pass** (masked only) | Safe: only masked value in output |
| `lkr get key --json --show` | Pass | **Block** (exit 2) | Raw value in JSON |
| `lkr get key --force-plain` | Pass | **Pass** (warning) | Explicit user override |
| `lkr gen template` | Pass | **Block** (exit 2) | Generated files contain secrets |
| `lkr gen template --force` | Pass | **Pass** | Explicit user override |
| `lkr exec -- cmd` | Pass (silent) | **Pass** (warning) | Safe: keys in env vars only |
| `lkr exec -- cmd` (0 keys) | **Warn** | **Warn** | Always warns when no keys matched |

**Detection method**: `std::io::IsTerminal` (wraps `isatty(2)` on stdout fd).
Environment variables (`TERM`, `CI`, etc.) are NOT checked — only the file descriptor.

**Exit code 2**: All TTY guard blocks use exit code 2, distinct from general errors (exit 1).

**Mitigations** (layered):

1. **TTY Guard — comprehensive non-TTY blocking**:
   - `get`: All access blocked unless `--json` (masked) or `--force-plain`
   - `gen`: Blocked unless `--force`
   - `exec`: Always allowed (keys stay in env vars, never in stdout)

2. **TTY Guard — clipboard blocked** (prevents `lkr get key && pbpaste` bypass):
   - In non-interactive environments, `lkr get` skips clipboard copy entirely

3. **`lkr exec` — safest automation path** (keys never leave the process boundary):
   - Injects Keychain keys as environment variables into a child process
   - Only `runtime` keys are injected — `admin` keys are excluded
   - Keys never appear in stdout, files, or clipboard
   - Non-TTY: 1-line warning on stderr (for audit trail), silent in TTY by default

4. **`lkr gen` as file-based alternative**:
   - Blocked in non-TTY by default (secrets written to files are risky in agent contexts)
   - `--force` overrides for CI/CD pipelines that explicitly need file-based secrets
   - Output files have `0600` permissions

### T10/T11: Keychain Attribute Hardening (v0.2.0 new)

**v0.2.0 adds two Keychain attributes to all keys**:

| Attribute | Value | Protection |
|-----------|-------|------------|
| `kSecAttrSynchronizable` | `false` | Prevents iCloud Keychain from syncing keys to other Apple devices |
| `kSecAttrAccessibleWhenUnlocked` | set | Keys are only accessible when the device is unlocked |

**Migration**: Run `lkr migrate` to apply these attributes to existing v0.1.0 keys.
Use `lkr migrate --dry-run` to preview changes without applying.

### What LKR Does NOT Protect Against

These are **known limitations** — users should be aware:

| Scenario | Why it's a limitation | Mitigation / Roadmap |
|----------|----------------------|---------------------|
| `security find-generic-password` reads runtime keys | Unsigned binary cannot set Keychain ACL (requires Apple Developer ID — see investigation below) | **Known limitation**: Use `lkr exec` instead of direct key retrieval |
| Root/admin access to the machine | macOS Keychain is unlocked when the user is logged in | Use FileVault; lock screen when away |
| Agent reads generated `.env` file via `cat` | File exists on disk after `lkr gen` | Use `lkr exec` instead; delete generated files after use |
| IDE with pseudo-TTY (pty) bypasses TTY guard | Some IDEs allocate a pty; `isatty` returns true | TTY guard is defense-in-depth; use `lkr exec` as primary |
| Child process logs env vars after `lkr exec` | LKR has no control over child behavior | Audit child programs; avoid untrusted commands |
| Clipboard manager capturing copied keys | Third-party clipboard managers may persist history | 30s auto-clear mitigates; disable clipboard managers for sensitive use |
| Unsigned binary path replacement | Attacker replaces `lkr` binary; Keychain allows access to same-service items | **Known limitation**: Verify binary integrity manually (`sha256sum`) |

### Keychain ACL Investigation (v0.2.1)

macOS Keychain ACL (`SecAccessControlCreateWithFlags`) could block `security find-generic-password`
from reading keys without biometric authentication. However, ACL requires code signing with a
valid Team ID from the Apple Developer Program ($99/year).

We tested three signing approaches — all failed:

| Signing Method | Result | Error |
|---------------|--------|-------|
| Ad-hoc (`codesign -s -`) | Failed | `errSecMissingEntitlement (-34018)` |
| Self-signed certificate (no entitlements) | Failed | `errSecMissingEntitlement (-34018)` |
| Self-signed certificate + `keychain-access-groups` entitlement | Failed | Process killed by `amfid` |

**Conclusion**: Keychain ACL is only available to binaries signed with an Apple Developer ID
(requires Apple Developer Program, $99/year). Binaries installed via `cargo install` or
Homebrew source-build cannot use ACL. This is a **permanent known limitation** of the
unsigned distribution model. The `security find-generic-password` attack vector remains
open — mitigated by `lkr exec` (keys never in stdout) and defense-in-depth layers above.

### FFI Memory Gap

`Zeroizing<String>` covers all Rust-side secret handling. However, when secrets pass through
the `security-framework-sys` FFI boundary, intermediate copies in `CFData`/`CFString` are
managed by Core Foundation's reference counting and are **not** zeroed on deallocation.

**Practical impact**: Low. The FFI copies are short-lived (function scope), and an attacker
with memory-dump capability likely has Keychain access already.

**Mitigation**: Secret data path is kept as short as possible (`Vec<u8>` based, minimal
string conversions).

## Security Design Principles

1. **Never accept secrets as CLI arguments** — prevents shell history and `/proc` exposure
2. **Masked by default** — raw values require explicit opt-in (`--show`)
3. **Non-interactive = restricted** — comprehensive TTY guard on `get`/`gen`; `exec` as safe path
4. **Admin keys are isolated** — higher-privilege keys excluded from `list`/`exec`/`gen` defaults
5. **No iCloud sync** — `kSecAttrSynchronizable: false` prevents cross-device leakage
6. **Locked = inaccessible** — `kSecAttrAccessibleWhenUnlocked` enforced
7. **Atomic file generation** — temp file + rename prevents partial secret files
8. **Minimal permissions** — generated files are `0600` (owner read/write only)
9. **Memory hygiene** — `Zeroizing<String>` for all secret values (with documented FFI gap)
10. **Honest threat model** — limitations are documented, not hidden

## Key Storage Format

Keys are stored in macOS Keychain as Generic Password items:

| Field | Value |
|-------|-------|
| Service | `com.llm-key-ring` (constant, never change) |
| Account | `{provider}:{label}` (e.g., `openai:prod`) |
| Password | JSON: `{"value":"<actual-key>","kind":"runtime"}` |
| Synchronizable | `false` (v0.2.0+) |
| Accessible | `WhenUnlocked` (v0.2.0+) |

The JSON envelope stores both the secret value and its kind (runtime/admin),
enabling kind-based access control without separate metadata storage.

## Roadmap

| Version | Security Focus |
|---------|---------------|
| **v0.2.0** (current) | Keychain attribute hardening + comprehensive TTY guard |
| **v0.3.0** | DX improvement (`lkr init`, shell completions, Homebrew tap) |
| v0.4.0 | MCP server with scoped access tokens |

## Reporting Security Issues

If you discover a security vulnerability, please report it via
[GitHub Security Advisories](https://github.com/yottayoshida/llm-key-ring/security/advisories/new)
rather than opening a public issue. We aim to respond within 48 hours.
