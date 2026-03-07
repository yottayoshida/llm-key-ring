# Security & Threat Model

LLM Key Ring (LKR) is a local-first API key manager that stores secrets in macOS Keychain.
This document describes what LKR protects against, what it does NOT protect against,
and the design decisions behind each mitigation.

> **Honesty policy**: We document limitations alongside protections.
> Security through obscurity is not security.

## Design Philosophy

LKR is **not** a vault that claims to make secrets absolutely safe.

LKR is a tool that **closes the leaky paths developers actually hit** — plaintext dotfiles,
shell history, clipboard residue, agent exfiltration, `security find-generic-password` —
and **funnels usage toward the safest execution path** (`lkr exec`).

The three tenets:

1. **Close leaky paths**: Eliminate common leakage vectors using OS-native mechanisms
   (Keychain encryption, Custom Keychain isolation, Legacy ACL authorization)
2. **Make the safe path the easy path**: `lkr exec` is the recommended and most convenient
   way to use API keys — and it is also the most secure (keys never appear in stdout,
   files, or clipboard)
3. **Draw the line honestly**: Same-user arbitrary code execution is outside LKR's protection
   scope. We document this, not hide it

### Scope and Non-goals

| | In scope (LKR protects) | Out of scope (LKR does not protect) |
|--|------------------------|-------------------------------------|
| **What** | Key storage and retrieval paths | Runtime behavior of child processes |
| **Against** | Casual/automated leakage (file read, CLI scraping, agent exfiltration) | Targeted same-user code execution by an attacker |
| **How** | OS-native mechanisms (Keychain, ACL, search list isolation) | Application-level encryption or HSM |

### Platform Dependency Risk

v0.3.0's defense relies on **Custom Keychains using the legacy CSSM format**, where Legacy ACL
trusted application lists are enforced because partition IDs do not exist. This works today
(macOS 14 Sonoma verified) and has worked since Custom Keychains were introduced.

However, Apple's direction favors Data Protection Keychains and modern APIs. If a future macOS
version changes Custom Keychain behavior (e.g., adding partition IDs to CSSM, deprecating
Custom Keychain creation APIs), Layer 2 (Authorization) could be weakened.

**Mitigations**:
- `lkr harden` re-registers ACL, serving as a migration point if the mechanism changes
- Layer 1 (Isolation via search list) is independent of ACL and provides baseline protection
- The architecture is designed to be **migrated, not permanent** — if Apple provides a
  better mechanism accessible to unsigned binaries, LKR will adopt it

## Attack Surface Comparison: `.env` vs LKR

| Attack Vector | `.env` plaintext | LKR v0.1.0 | LKR v0.2.0 | LKR v0.3.0 | Notes |
|---------------|:---:|:---:|:---:|:---:|-------|
| `cat .env` / file read | Exposed | N/A | N/A | N/A | LKR eliminates persistent plaintext files |
| `grep -r API_KEY .` in project | Exposed | N/A | N/A | N/A | No files to grep |
| Git commit of secrets | Exposed | N/A | N/A | N/A | Nothing to commit |
| `security find-generic-password` (default) | N/A | Exposed | Exposed | **Protected** | v0.3.0: Custom Keychain not in search list (Layer 1) |
| `security find-generic-password` (explicit path) | N/A | Exposed | Exposed | **Protected** | v0.3.0: Legacy ACL blocks non-lkr binaries (Layer 2) |
| Binary replacement at lkr path | N/A | N/A | N/A | **Protected** | v0.3.0: cdhash mismatch detected (Layer 3) |
| Shell history exposure | Exposed (if `export KEY=...`) | Protected | Protected | Protected | `lkr set` uses hidden prompt |
| AI agent pipe exfiltration | Exposed (`cat .env`) | Partial | **Protected** | **Protected** | v0.2.0 blocks all non-TTY `get` access |
| iCloud Keychain sync to other devices | N/A | **Unprotected** | **Protected** | **Protected** | `kSecAttrSynchronizable: false` |
| Access while device is locked | N/A | **Unprotected** | **Protected** | **Protected** | `kSecAttrAccessibleWhenUnlocked` |
| Memory dump | Exposed (plaintext in memory) | Partial | Partial | Partial | `Zeroizing<String>` with FFI gap (see below) |
| Same-user arbitrary code execution | Exposed | Exposed | Exposed | Exposed | **Out of scope** — see Design Philosophy |

**Summary**: LKR v0.3.0 closes the last "Exposed" vector from v0.2.0 — `security find-generic-password`
— via Custom Keychain isolation (Layer 1) and Legacy ACL cdhash authorization (Layer 2/3).
Combined with v0.2.0's TTY guard and attribute hardening, all common developer leakage paths
are now protected. The remaining "Exposed" row (same-user code execution) is an explicit
non-goal — see Design Philosophy above.

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
| T12 | `security find-generic-password` reads keys | **Critical** | Custom Keychain (isolation) + Legacy ACL (cdhash authorization) | **v0.3.0 new** |
| T13 | Binary replacement to bypass ACL | High | cdhash-based ACL requirement detects binary mismatch | **v0.3.0 new** |

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

These are **known limitations** — users should be aware.

LKR protects the **storage and retrieval paths** of API keys. It does NOT protect against
an attacker who has same-user code execution and chooses to attack the runtime (process
memory, environment variables, network traffic). This is a deliberate scope boundary,
not a gap waiting to be fixed.

| Scenario | Why it's a limitation | Mitigation |
|----------|----------------------|------------|
| Attacker knows keychain path + password | Custom Keychain password is the last line of defense | Use a strong, unique password; lock keychain when not in use |
| Attacker runs `lkr exec` directly | Same-user code execution = game over for any local tool | **Out of scope**; same limitation as aws-vault, 1Password CLI, etc. |
| Root/admin access to the machine | macOS Keychain is unlocked when the user is logged in | Use FileVault; lock screen when away |
| `security dump-keychain -d` with keychain password | Reads all items (requires password) | Password is the defense; same as aws-vault |
| Agent reads generated `.env` file via `cat` | File exists on disk after `lkr gen` | Use `lkr exec` instead; delete generated files after use |
| IDE with pseudo-TTY (pty) bypasses TTY guard | Some IDEs allocate a pty; `isatty` returns true | TTY guard is defense-in-depth; use `lkr exec` as primary |
| Child process logs env vars after `lkr exec` | LKR has no control over child behavior | Audit child programs; avoid untrusted commands |
| Clipboard manager capturing copied keys | Third-party clipboard managers may persist history | 30s auto-clear mitigates; disable clipboard managers for sensitive use |
| macOS deprecates Custom Keychain / CSSM format | Layer 2 (ACL) may stop working | Layer 1 (isolation) is independent; `lkr harden` serves as migration point; see Platform Dependency Risk |

### Keychain ACL Investigation (v0.2.1 — updated v0.3.0)

macOS Keychain has two distinct ACL mechanisms. We investigated both to determine
whether either can block `security find-generic-password` from reading keys.

#### Approach 1: Modern ACL (`SecAccessControlCreateWithFlags`)

Uses `kSecAttrAccessControl` with flags like Touch ID, device passcode, or application password.
Requires code signing with a valid Team ID from the Apple Developer Program ($99/year).

We tested three signing approaches — all failed:

| Signing Method | Result | Error |
|---------------|--------|-------|
| Ad-hoc (`codesign -s -`) | Failed | `errSecMissingEntitlement (-34018)` |
| Self-signed certificate (no entitlements) | Failed | `errSecMissingEntitlement (-34018)` |
| Self-signed certificate + `keychain-access-groups` entitlement | Failed | Process killed by `amfid` |

**Verdict**: NO-GO. Modern ACL requires Apple Developer ID ($99/year).

#### Approach 2: Legacy ACL (`SecAccessCreate` / `security -T`)

Uses `kSecAttrAccess` with trusted application lists (`SecTrustedApplicationCreateFromPath`).
Does not require code signing — predates the modern ACL system.

We tested via the `security` CLI's `-T` flag:

| Test | Command | Expected | Actual |
|------|---------|----------|--------|
| Empty trust list | `add-generic-password -T ""` | Prompt or block | **Plain text returned silently** |
| lkr-only trust | `add-generic-password -T /path/to/lkr` | Block `security` binary | **Plain text returned silently** |

**Root cause**: macOS 10.12+ introduced **partition IDs** (`apple-tool:,apple:`) that override
Legacy ACL trusted application lists. The `security` binary is an Apple system tool with
`apple-tool:` partition access, granting it unconditional read access regardless of the
trusted application list. This partition ID is set automatically when items are created
via the `security` CLI and cannot be removed by unsigned binaries.

**Verdict**: NO-GO. Legacy ACL cannot block `security find-generic-password`.

#### Approach 3: Custom Keychain (aws-vault approach) — v0.3.0

Instead of ACL, use a **separate keychain file** that is not in the default search list.
`security find-generic-password` only searches keychains in the search list.

We tested via the `security` CLI:

| Test | Expected | Actual |
|------|----------|--------|
| Create custom keychain | Success | **PASS** |
| Default search (`find-generic-password` without keychain arg) | Not found | **PASS** — `errSecItemNotFound` |
| Explicit path (`find-generic-password ... keychain.db`) | Found | **PASS** |
| Lock keychain → read | Blocked | **PASS** — exit code 128 |
| Unlock → read again | Found | **PASS** |
| Add to search list → default search | Found | **PASS** (confirms isolation mechanism) |
| Remove from search list → default search | Not found | **PASS** (isolation restored) |

**Verdict**: GO. Custom Keychain eliminates the `security find-generic-password` attack vector
by keeping the keychain file outside the default search list. The attacker would need to know
the keychain file path AND its password (or have it unlocked) to access items.

#### Approach 3+: Custom Keychain + Legacy ACL (combined defense)

A follow-up spike revealed that **Legacy ACL works on Custom Keychains** — because Custom
Keychains do not use partition IDs. This means the V1 FAIL (Legacy ACL on login.keychain)
does not apply here.

When items are created with `-T /path/to/lkr`, macOS automatically sets a **cdhash-based
requirement** in the ACL:

```
applications (1):
    0: /path/to/lkr (OK)
        requirement: cdhash H"<sha256-of-binary>"
```

We tested three ACL configurations on a Custom Keychain:

| ACL Setting | `security find-generic-password` | Notes |
|-------------|:---:|-------|
| Default (no `-T`) | **Silent read** | `security` binary auto-added as trusted app |
| `-T ""` (empty trust list) | **Blocked** (dialog → exit 128) | No trusted apps = always prompt |
| `-T /path/to/lkr` (lkr-only) | **Blocked** (dialog → exit 128) | Only lkr trusted; `security` not in list |
| `-T /path/to/lkr -T /usr/bin/security` | **Silent read** | Control: adding `security` restores silent access |

**Binary replacement resistance**: After replacing the signed binary at the same path (changing
its cdhash), the ACL entry changed from `(OK)` to `(status -2147415734)` — the cdhash
mismatch is detected even when the binary path remains identical.

**Key insight**: Custom Keychains use the legacy CSSM keychain format, which does NOT have
partition IDs (`apple-tool:`, `apple:`). Without partition IDs, Legacy ACL trusted application
lists are enforced as designed. This is why `-T` failed on login.keychain (V1) but works
on Custom Keychains.

**Trade-off**: The cdhash requirement means every binary rebuild (e.g., `cargo install --force`)
changes the hash, requiring ACL re-registration. This is addressable via `lkr harden` or
automatic re-registration on first access.

**Verdict**: GO. Custom Keychain + Legacy ACL provides **both isolation (not in search list)
and authorization (cdhash-based trusted app)**. This is the v0.3.0 target architecture.

#### ACL Enforcement Is Independent of Lock State

A critical property verified during spike testing: **Legacy ACL trusted application lists
are enforced whether the Custom Keychain is locked or unlocked.** An unlocked keychain does
NOT grant bypass of the `-T` trusted app list. This means:

- `security find-generic-password` is blocked by ACL regardless of lock state
- Lock state only gates access by the **trusted binary itself** (i.e., `lkr`)
- Since same-user code execution is out of scope (I4), lock state serves primarily as
  a physical-access defense (sleep lock) and user-preference option (timeout)

This property is why v0.3.0 uses a **session-maintained unlock** policy (lock on sleep,
no per-command locking) rather than aggressive per-operation locking.

#### Summary

| Approach | Blocks `security find-generic-password`? | Requires Apple Developer ID? | Status |
|----------|:---:|:---:|--------|
| Modern ACL (`SecAccessControlCreateWithFlags`) | Potentially | **Yes** ($99/year) | NO-GO |
| Legacy ACL on login.keychain (`-T`) | **No** (partition ID bypass) | No | NO-GO |
| Custom Keychain (isolation only) | **Yes** (default search) | No | GO |
| **Custom Keychain + Legacy ACL** | **Yes** (default search + explicit path) | No | **v0.3.0 target** |

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

### Design Invariants (v0.3.0)

These are **absolute rules** that must never be violated. Breaking any of these
collapses the security model.

| # | Invariant | What breaks if violated |
|---|-----------|------------------------|
| I1 | `lkr.keychain-db` must NEVER be in the default search list | Layer 1 (Isolation) — `security find-generic-password` finds keys without explicit path |
| I2 | `/usr/bin/security` must NEVER be in any item's trusted app list (`-T`) | Layer 2 (Authorization) — `security` reads keys silently even with explicit path |
| I3 | `lkr get` must NEVER be the recommended path for automation | Design Philosophy — `exec` is the safe path; promoting `get` invites leakage |
| I4 | LKR must NEVER claim to protect against same-user code execution | Honesty policy — overpromising destroys trust and leads to false sense of security |

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
| **v0.2.0** | Keychain attribute hardening + comprehensive TTY guard |
| **v0.3.0** | Custom Keychain + Legacy ACL via Pure FFI (3-layer defense: isolation + cdhash authorization + binary integrity) |
| **v0.3.1** (current) | Security hardening: ACL fail-closed, zeroize-on-drop, `-25308` auto-diagnosis |
| v0.3.2 | Operational quality: shell completions, Homebrew tap, `lkr config lock-timeout` |
| v0.4.0 | MCP server with scoped access tokens |

## Reporting Security Issues

If you discover a security vulnerability, please report it via
[GitHub Security Advisories](https://github.com/yottayoshida/llm-key-ring/security/advisories/new)
rather than opening a public issue. We aim to respond within 48 hours.
