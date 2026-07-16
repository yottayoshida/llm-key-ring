# LLM Key Ring (`lkr`)

> **Status:** Working toward v1.0 — see [Epic #61](https://github.com/yottayoshida/llm-key-ring/issues/61) for the roadmap and current activity.

[![CI](https://github.com/yottayoshida/llm-key-ring/actions/workflows/ci.yml/badge.svg)](https://github.com/yottayoshida/llm-key-ring/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/lkr-cli.svg)](https://crates.io/crates/lkr-cli)
[![docs.rs](https://docs.rs/lkr-core/badge.svg)](https://docs.rs/lkr-core)

A secure CLI tool for managing LLM API keys via macOS Keychain. No more plaintext keys in `.env` files.

```
$ lkr set openai:prod
Enter API key for openai:prod: ****
Stored openai:prod (kind: runtime)

$ lkr get openai:prod
Copied to clipboard (auto-clears in 30s)
  sk-p...3xYz  (runtime)

$ lkr exec -- python script.py       # Keys injected as env vars (safest)
$ lkr gen .env.example -o .env       # Generate config from template
```

## Why?

| Problem | `lkr` Solution |
|---------|---------------|
| API keys sitting in `.env` files | Encrypted in macOS Keychain |
| Keys leaked via shell history | Interactive prompt input (never CLI args) |
| AI agents extracting keys via pipe | TTY guard blocks ALL non-TTY `get` access (v0.2.0) |
| Keys lingering in clipboard | Auto-clears after 30 seconds |
| Keys lingering in process memory | `zeroize` wipes memory on drop |

## Install

```bash
# Homebrew (recommended)
brew install yottayoshida/tap/lkr

# From source
git clone https://github.com/yottayoshida/llm-key-ring.git
cd llm-key-ring
cargo install --path crates/lkr-cli
```

Requires macOS (uses native Keychain) — see [*Why macOS-only?*](#why-macos-only) for the reason. Source build requires Rust 1.85+.

> **Note**: After upgrading (`brew upgrade lkr` or `cargo install --force`), run `lkr harden`
> to refresh Keychain ACL for the new binary.

## Usage

### Store a key

```bash
lkr set openai:prod          # Interactive prompt
```

Password prompts require an interactive terminal — piped input (e.g. `pbpaste | lkr set ...`)
is rejected with an explicit error rather than silently hanging or being read. This applies
to `lkr init`'s prompts and to the Keychain-unlock prompt every other command (`set`, `get`,
`list`, `rm`, `usage`, `gen`, `migrate`, `harden`, `exec`) shows on each invocation — there's
no persistent "unlocked session," so any of them run non-interactively (CI, background jobs)
will exit with this error too. This is intentional: it keeps secret entry on a path a script
or AI agent can't feed automatically.

Key names use `provider:label` format (e.g., `openai:prod`, `anthropic:main`).

### Retrieve a key

```bash
lkr get openai:prod            # Masked display + clipboard (30s auto-clear)
lkr get openai:prod --show     # Show raw value in terminal
lkr get openai:prod --json     # JSON output (masked value; safe in non-TTY)
lkr get openai:prod --plain    # Raw value only (blocked in non-interactive env)
lkr get openai:prod --force-plain  # Raw value even in non-interactive (use with caution)
```

> **v0.2.0**: In non-interactive environments (pipes, agent subprocesses), `lkr get` is blocked
> by default. Use `--json` (masked values) or `--force-plain` (raw, at your risk) to override.
> Prefer `lkr exec` for automation.

### List keys

```bash
lkr list                # Runtime keys only
lkr list --all          # Include admin keys
lkr list --json         # JSON output
```

### Run a command with keys as env vars (recommended)

```bash
lkr exec -- python script.py                # Inject all runtime keys
lkr exec -k openai:prod -- curl ...         # Inject specific keys only
lkr exec -k openai:prod -k anthropic:main -- node app.js
lkr exec --verbose -- python script.py      # Show injected env var names
```

Keys are mapped to conventional env var names (e.g., `openai:prod` → `OPENAI_API_KEY`) and injected into the child process. Only `runtime` keys are injected — `admin` keys are excluded by design. **Keys never appear in stdout, files, or clipboard** — this is the safest way to pass secrets to programs. Prefer `exec` over `gen` whenever possible.

### Generate config from template

Use `gen` when the target program requires a config file and cannot accept env vars.
In non-interactive environments, `--force` is required (v0.2.0):

```bash
lkr gen .env.example              # → .env (auto-derived output path)
lkr gen .env.example -o .env.local  # Explicit output path
lkr gen config.json.template      # Works with JSON templates too
```

**`.env.example` format** — keys are auto-resolved by exact env var name match:

```env
OPENAI_API_KEY=your-key-here    # ← resolved from openai:* in Keychain
ANTHROPIC_API_KEY=              # ← resolved from anthropic:*
```

**JSON template format** — use explicit `{{lkr:provider:label}}` placeholders:

```json
{
  "openai_key": "{{lkr:openai:prod}}",
  "anthropic_key": "{{lkr:anthropic:main}}"
}
```

Generated files are written with `0600` permissions. A warning is shown if the output file is not in `.gitignore`.

When multiple runtime keys exist for the same provider (e.g., `openai:prod` and `openai:stg`), the alphabetically first key is used. A warning lists alternatives. Use `{{lkr:provider:label}}` placeholders for explicit control.

### Migrate keys

```bash
lkr migrate --dry-run   # Preview what would be migrated
lkr migrate             # Copy keys from login.keychain → lkr.keychain-db (v0.3.0)
```

**v0.3.0**: Copies keys from login.keychain to the custom keychain with Legacy ACL applied.
Requires `lkr init` first. Safe to run multiple times (skips existing keys).

### Delete a key

```bash
lkr rm openai:prod         # With confirmation prompt
lkr rm openai:prod --force # Skip confirmation
```

### Check API usage costs

```bash
lkr usage openai        # Single provider
lkr usage               # All providers with admin keys
lkr usage --json        # JSON output
```

Requires an **Admin API key** registered with `--kind admin`:

```bash
lkr set openai:admin --kind admin
```

### Global flags

```bash
lkr <command> --json    # JSON output (all commands)
lkr --help
lkr --version
```

## Supported Providers

`lkr gen` auto-resolves keys for these providers:

| Provider | Env Variable | Key Name Example |
|----------|-------------|-----------------|
| OpenAI | `OPENAI_API_KEY` | `openai:prod` |
| Anthropic | `ANTHROPIC_API_KEY` | `anthropic:main` |
| Google | `GOOGLE_API_KEY` | `google:dev` |
| Mistral | `MISTRAL_API_KEY` | `mistral:api` |
| Cohere | `COHERE_API_KEY` | `cohere:prod` |
| Groq | `GROQ_API_KEY` | `groq:prod` |
| DeepSeek | `DEEPSEEK_API_KEY` | `deepseek:api` |
| xAI | `XAI_API_KEY` | `xai:prod` |
| And more... | | |

Any `provider:label` name works with `set`/`get`/`rm`. The provider list above is used for auto-resolution in `lkr gen`.

## Security

### Threat Model

See [docs/SECURITY.md](docs/SECURITY.md) for the full threat model. Key protections:

| Threat | Mitigation |
|--------|-----------|
| Plaintext key files | Keys stored in macOS Keychain (encrypted at rest) |
| Shell history exposure | `lkr set` reads from prompt, never from CLI arguments |
| Clipboard residual | 30s auto-clear via SHA-256 hash comparison |
| Terminal shoulder-surfing | Masked by default (`sk-p...3xYz`) |
| **AI agent exfiltration** | **TTY guard blocks ALL non-TTY `get`/`gen` access (v0.2.0)** |
| Memory forensics | `zeroize::Zeroizing<String>` zeroes memory on drop |
| Admin key in templates | `lkr gen` only resolves `runtime` keys |
| Accidental git commit | `.gitignore` coverage check on generated files |

### Agent IDE Attack Protection (v0.2.0)

AI coding assistants (Cursor, Copilot, Claude Code, etc.) can be tricked via prompt injection
into running commands that exfiltrate secrets. `lkr` v0.2.0 comprehensively blocks this:

```bash
# Non-TTY: ALL get access blocked by default (exit code 2)
echo | lkr get openai:prod          # ← Blocked
echo | lkr get openai:prod --show   # ← Blocked
echo | lkr get openai:prod --plain  # ← Blocked

# Allowed alternatives in non-TTY:
echo | lkr get openai:prod --json        # ← Pass (masked value only)
echo | lkr get openai:prod --force-plain # ← Pass (explicit override)

# gen is also blocked in non-TTY:
echo | lkr gen .env.example              # ← Blocked
echo | lkr gen .env.example --force      # ← Pass (explicit override)

# exec always works (safest path — keys never in stdout):
lkr exec -- python script.py
```

## Architecture

```
llm-key-ring/
├── crates/
│   ├── lkr-core/           # Library: KeyStore trait, Keychain, templates, usage API
│   │   ├── src/
│   │   │   ├── keymanager.rs       # KeychainStore + keychain_raw FFI (CRUD)
│   │   │   ├── custom_keychain.rs  # Keychain lifecycle (create/open/unlock/lock) [v0.3.0]
│   │   │   ├── acl.rs             # Legacy ACL builder (SecAccessCreate) [v0.3.0]
│   │   │   └── error.rs           # Error types + OSStatus constants
│   │   └── tests/
│   │       └── keychain_integration.rs  # Tier 2 contract tests [v0.3.0]
│   └── lkr-cli/            # Binary: clap CLI (init/set/get/list/rm/gen/usage/exec/migrate/harden/lock)
├── docs/
│   ├── SECURITY.md          # Threat model + attack surface
│   └── design-v030.md       # v0.3.0 design document
├── LICENSE-MIT
└── LICENSE-APACHE
```

All business logic lives in `lkr-core`. The CLI is a thin wrapper. v0.3.0 adds three key modules:
- **`custom_keychain`**: Dedicated keychain lifecycle management via Security.framework FFI
- **`acl`**: Legacy ACL builder using `SecAccessCreate` + `SecTrustedApplicationCreateFromPath`
- **`keychain_raw`**: Low-level item CRUD via `SecKeychainItemCreateFromContent` (with initial ACL)

### Why macOS-only?

v1.0 is macOS-only by design, not by lack of effort. `lkr`'s actual value — the 3-layer
defense (Custom Keychain isolation, Legacy ACL + cdhash binary integrity binding) — is
built on macOS's CSSM Keychain internals via `security-framework` / `security-framework-sys`
direct FFI. A Linux or Windows backend could store keys, but couldn't honor those specific
guarantees; shipping one under the same guarantees would be a false promise. See
[docs/SECURITY.md — Platform Dependency Risk](docs/SECURITY.md#platform-dependency-risk)
for how this architecture is designed to survive changes *within* macOS itself.

Want `lkr` on Linux or Windows anyway (with a reduced security model)? Add your use case to
[the tracking issue](https://github.com/yottayoshida/llm-key-ring/issues/65) — it's not planned
for v1.0, but demand shapes what comes after.

### Keychain Storage

| Field | Value |
|-------|-------|
| Keychain | `~/Library/Keychains/lkr.keychain-db` (v0.3.0+, NOT in search list) |
| Service | `com.llm-key-ring` |
| Account | `{provider}:{label}` |
| Password | `{"value":"sk-...","kind":"runtime"}` |
| ACL | `SecAccessRef` trusting only the lkr binary (cdhash-based, v0.3.0+) |
| Synchronizable | `false` (v0.2.0+, no iCloud sync) |
| Accessible | `WhenUnlocked` (v0.2.0+) |

## Upgrading from v0.1.x

### Breaking changes in v0.2.0

1. **`lkr get` is blocked in non-interactive environments** (exit code 2).
   - Previously only `--plain`/`--show` were blocked; now bare `get` is also blocked.
   - Use `--json` (masked values) or `--force-plain` (raw) to override.
   - Recommended: switch to `lkr exec` for automation.

2. **`lkr gen` is blocked in non-interactive environments** (exit code 2).
   - Add `--force` to CI/CD scripts that use `lkr gen`.

3. **`lkr exec` stderr output changed**:
   - TTY: silent by default (was verbose). Use `--verbose` to see injected keys.
   - Non-TTY: 1-line warning.

### Migration steps

```bash
# 1. Update lkr
cargo install --path crates/lkr-cli --force

# 2. Migrate existing keys (adds iCloud sync protection + lock protection)
lkr migrate --dry-run    # Preview
lkr migrate              # Apply

# 3. Update CI/CD scripts (if applicable)
# Before: lkr get openai:prod --plain | ...
# After:  lkr exec -- ...
# Or:     lkr get openai:prod --force-plain | ...
# Or:     lkr gen .env.example --force
```

## Upgrading to v0.3.0

> v0.3.0 is a **breaking change**. Keys are moved from login.keychain to a dedicated
> Custom Keychain with 3-layer defense against `security find-generic-password` attacks.

### What changes

| Before (v0.2.x) | After (v0.3.0) |
|-----------------|----------------|
| Keys in login.keychain (auto-unlocked at login) | Keys in `lkr.keychain-db` (separate password, auto-lock 5min) |
| `security find-generic-password` can read keys | **Blocked** — search list isolation + Legacy ACL |
| Binary replacement is undetected | **Detected** — cdhash-based integrity check |
| No setup step required | **`lkr init` required** before first use |
| All operations via `security-framework` crate | Pure FFI: `SecKeychainItemCreateFromContent` + `SecAccessCreate` |

### Upgrade steps

```bash
# 1. Update lkr
cargo install --path crates/lkr-cli --force

# 2. Create dedicated keychain (new in v0.3.0)
lkr init                # Set a keychain password (remember it!)

# 3. Move keys from login.keychain → lkr.keychain-db
lkr migrate --dry-run   # Preview what would be migrated
lkr migrate              # Apply (copy-first with verify readback, safe to re-run)

# 4. After future binary updates (cargo install --force):
lkr harden              # Refresh binary fingerprint (cdhash) for all keys
```

**Note**: `lkr migrate` copies keys (does not delete from login.keychain). Legacy keys
remain readable via v0.2.x fallback until you manually remove them.

### New commands in v0.3.0

| Command | Purpose |
|---------|---------|
| `lkr init` | Create `lkr.keychain-db`, set password, enable lock-on-sleep + 5min auto-lock |
| `lkr migrate` | Copy keys from login.keychain → custom keychain (with ACL) |
| `lkr harden` | Re-register binary fingerprint after `cargo install --force` |
| `lkr lock` | Explicitly lock `lkr.keychain-db` |

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | General error (key not found, Keychain error, etc.) |
| 2 | TTY guard violation (non-interactive environment blocked) |

## Roadmap

| Version | Theme | Key Changes |
|---------|-------|-------------|
| v0.2.2 | Docs & Roadmap | Roadmap update, v0.3.0 upgrade guide preview |
| **v0.3.0** | **Security: 3-Layer Defense** | Custom Keychain (`lkr.keychain-db`) + Legacy ACL via Pure FFI + cdhash. **Breaking change** — see below |
| **v0.3.1** | **Security Hardening** | ACL fail-closed, `keychain_path()` safety, `StoredEntry` zeroize-on-drop, `-25308` auto-diagnosis |
| **v0.3.2** | **Operational Quality** | List N+1 fix, CLI module split, unsafe SAFETY docs, Homebrew tap |
| **v0.3.3** | **Bug Fix** | `lkr migrate` circular error fix |
| **v0.3.4** (current) | **Bug Fix** | `lkr harden` ACL fix after binary update ([#13](https://github.com/yottayoshida/llm-key-ring/issues/13)) |
| v1.0 | Verifiable S/A-tier OSS | See [Epic #61](https://github.com/yottayoshida/llm-key-ring/issues/61) for the current roadmap and open issues |

## Development

```bash
# Build
cargo build

# Test
cargo test

# Clippy
cargo clippy -- -D warnings

# Run without installing
cargo run --bin lkr -- list
```

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option.

