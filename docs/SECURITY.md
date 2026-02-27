# Security & Threat Model

LLM Key Ring (LKR) is a local-first API key manager that stores secrets in macOS Keychain.
This document describes what LKR protects against, what it does NOT protect against,
and the design decisions behind each mitigation.

## Threat Overview

| # | Threat | Severity | Mitigation | Status |
|---|--------|----------|------------|--------|
| T1 | Plaintext keys in dotfiles (`.env`) | High | Keychain-encrypted storage; `.env` only generated on demand with `0600` permissions | Implemented |
| T2 | Shell history exposure | High | `lkr set` reads via hidden prompt (rpassword), never accepts key as CLI argument | Implemented |
| T3 | Clipboard residual | Medium | 30s auto-clear via detached background process; hash comparison prevents clearing user's own clipboard | Implemented |
| T4 | Terminal display leakage | Medium | Default masked output (`sk-p...wxyz`); `--show` required for plaintext | Implemented |
| T5 | Agent IDE key exfiltration | High | TTY guard blocks `--plain`/`--show` AND clipboard copy in non-interactive environments; `lkr exec` for safe automation | Implemented |
| T6 | Memory dump / core dump | Medium | `zeroize::Zeroizing<String>` zeroes memory on drop | Implemented |
| T7 | Admin key misuse via templates | Medium | `lkr gen` only resolves `runtime` keys; `admin` keys are rejected | Implemented |
| T8 | Generated file committed to Git | Medium | `.gitignore` check warning on `lkr gen` output | Implemented |
| T9 | Log/error message key leakage | Low | Error messages never include key values; only key names | By design |

## Detailed Threat Analysis

### T5: Agent IDE Key Exfiltration

**Background**: AI-powered IDEs (Cursor, Copilot, etc.) can be manipulated via prompt injection
to execute commands like `cat .env` or CLI tools that output secrets, exfiltrating API keys
through the AI agent's context window.

**Attack vector with LKR**:
```
Malicious prompt injection → AI agent executes → lkr get openai:prod --plain → key exfiltrated via agent context
```

**Mitigations** (three layers):

1. **TTY Guard — stdout blocked** (`--plain` / `--show` rejected in non-interactive environments):
   - `std::io::IsTerminal` checks whether stdout is a terminal
   - If not a TTY (pipe, agent subprocess), `--plain` and `--show` are rejected with exit code 2
   - `--force-plain` provides explicit override with warning (user accepts risk)

2. **TTY Guard — clipboard blocked** (prevents `lkr get key && pbpaste` bypass):
   - In non-interactive environments, `lkr get` skips clipboard copy entirely
   - This closes the attack vector where an agent runs `lkr get` then `pbpaste` to extract the key

3. **`lkr exec` — safest automation path** (keys never leave the process boundary):
   - Injects Keychain keys as environment variables into a child process
   - Keys never appear in stdout, files, or clipboard
   - `lkr exec -- python script.py` sets `OPENAI_API_KEY` etc. in the child's env only
   - The agent cannot observe the env vars of the child process

4. **`lkr gen` as file-based alternative**:
   - Agents can use `lkr gen .env.example -o .env` to set up environments
   - Keys are written to files (not stdout), with `0600` permissions
   - **Caveat**: an agent with file access can still `cat .env` — use `lkr exec` when possible

5. **`zeroize` for memory hygiene**:
   - `KeyStore::get()` returns `Zeroizing<String>` — memory is zeroed when the value goes out of scope
   - `Zeroizing<String>` intentionally does NOT implement `Display`, preventing accidental `println!("{}", value)` — you must explicitly dereference with `&*value`

### What LKR Does NOT Protect Against

These are **out of scope** — users should be aware of these limitations:

| Scenario | Why it's out of scope | Recommendation |
|----------|----------------------|----------------|
| Root/admin access to the machine | macOS Keychain is unlocked when the user is logged in; root can read it | Use FileVault full-disk encryption |
| Agent reads generated `.env` file via `cat` | File is on disk after `lkr gen`; any process with file access can read it | Rely on `0600` permissions; delete generated files after use |
| Keychain unlocked while machine unattended | macOS Keychain stays unlocked during a login session | Lock screen when away; configure Keychain auto-lock timeout |
| Key transmitted over network after retrieval | LKR is local-only; what happens after `lkr get` is up to the caller | Use TLS for API calls; rotate keys regularly |
| Clipboard manager capturing copied keys | Third-party clipboard managers may persist clipboard history | Disable clipboard managers for sensitive content; 30s auto-clear mitigates casual exposure |

## Security Design Principles

1. **Never accept secrets as CLI arguments** — prevents shell history and `/proc` exposure
2. **Masked by default** — raw values require explicit opt-in (`--show`)
3. **Non-interactive = restricted** — TTY guard prevents agent/pipe exploitation
4. **Admin keys are isolated** — higher-privilege keys excluded from `list`/`gen` defaults
5. **Atomic file generation** — temp file + rename prevents partial secret files
6. **Minimal permissions** — generated files are `0600` (owner read/write only)
7. **Memory hygiene** — `Zeroizing<String>` for all secret values in memory

## Key Storage Format

Keys are stored in macOS Keychain as Generic Password items:

| Field | Value |
|-------|-------|
| Service | `com.llm-key-ring` (constant, never change) |
| Account | `{provider}:{label}` (e.g., `openai:prod`) |
| Password | JSON: `{"value":"<actual-key>","kind":"runtime"}` |

The JSON envelope stores both the secret value and its kind (runtime/admin),
enabling kind-based access control without separate metadata storage.

## Reporting Security Issues

If you discover a security vulnerability, please report it via
[GitHub Security Advisories](https://github.com/yottayoshida/llm-key-ring/security/advisories/new)
rather than opening a public issue. We aim to respond within 48 hours.
