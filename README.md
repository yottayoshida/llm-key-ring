# LLM Key Ring (`lkr`)

A secure CLI tool for managing LLM API keys via macOS Keychain. No more plaintext keys in `.env` files.

```
$ lkr set openai:prod
Enter API key for openai:prod: ****
Stored openai:prod (kind: runtime)

$ lkr get openai:prod
Copied to clipboard (auto-clears in 30s)
  sk-p...3xYz  (runtime)

$ lkr gen .env.example -o .env
  Resolved from Keychain:
    OPENAI_API_KEY           <- openai:prod
  Generated: .env (1 resolved, 0 unresolved)
```

## Why?

| Problem | `lkr` Solution |
|---------|---------------|
| API keys sitting in `.env` files | Encrypted in macOS Keychain |
| Keys leaked via shell history | Interactive prompt input (never CLI args) |
| AI agents extracting keys via pipe | TTY guard blocks `--plain` in non-interactive environments |
| Keys lingering in clipboard | Auto-clears after 30 seconds |
| Keys lingering in process memory | `zeroize` wipes memory on drop |

## Install

```bash
# From source
git clone https://github.com/yottayoshida/llm-key-ring.git
cd llm-key-ring
cargo install --path crates/lkr-cli
```

Requires Rust 1.85+ and macOS (uses native Keychain).

## Usage

### Store a key

```bash
lkr set openai:prod          # Interactive prompt (recommended)
pbpaste | lkr set openai:prod  # From clipboard (avoids hidden-input confusion)
```

Key names use `provider:label` format (e.g., `openai:prod`, `anthropic:main`).

### Retrieve a key

```bash
lkr get openai:prod            # Masked display + clipboard (30s auto-clear)
lkr get openai:prod --show     # Show raw value in terminal
lkr get openai:prod --json     # JSON output
lkr get openai:prod --plain    # Raw value only (blocked in non-interactive env)
```

### List keys

```bash
lkr list                # Runtime keys only
lkr list --all          # Include admin keys
lkr list --json         # JSON output
```

### Generate config from template

```bash
lkr gen .env.example              # → .env (auto-derived output path)
lkr gen .env.example -o .env.local  # Explicit output path
lkr gen config.json.template      # Works with JSON templates too
```

**`.env.example` format** — keys are auto-resolved by provider prefix:

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
| **AI agent exfiltration** | **TTY guard blocks `--plain`/`--show` in non-interactive environments** |
| Memory forensics | `zeroize::Zeroizing<String>` zeroes memory on drop |
| Admin key in templates | `lkr gen` only resolves `runtime` keys |
| Accidental git commit | `.gitignore` coverage check on generated files |

### Agent IDE Protection (Antigravity Attack)

AI coding assistants (Cursor, Copilot, etc.) can be tricked via prompt injection into running commands that exfiltrate secrets. `lkr` defends against this:

```bash
# In a pipe (non-interactive) — BLOCKED with exit code 2
echo | lkr get openai:prod --plain
# Error: --plain and --show are blocked in non-interactive environments.

# Safe alternative for automation:
lkr gen .env.example -o .env   # Keys go to file (0600), never stdout
```

## Architecture

```
llm-key-ring/
├── crates/
│   ├── lkr-core/     # Library: KeyStore trait, Keychain, templates, usage API
│   ├── lkr-cli/      # Binary: clap CLI (set/get/list/rm/gen/usage)
│   └── lkr-app/      # Binary: Tauri v2 menu bar app (skeleton)
├── docs/
│   └── SECURITY.md   # Threat model
├── LICENSE-MIT
└── LICENSE-APACHE
```

All business logic lives in `lkr-core`. The CLI and Tauri app are thin wrappers.

### Keychain Storage

| Field | Value |
|-------|-------|
| Service | `com.llm-key-ring` |
| Account | `{provider}:{label}` |
| Password | `{"value":"sk-...","kind":"runtime"}` |

## Development

```bash
# Build
cargo build

# Test (40 tests)
cargo test

# Clippy
cargo clippy -- -D warnings

# Run without installing
cargo run --bin lkr -- list
```

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option.
