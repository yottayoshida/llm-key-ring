# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

[0.1.0]: https://github.com/yottayoshida/llm-key-ring/releases/tag/v0.1.0
