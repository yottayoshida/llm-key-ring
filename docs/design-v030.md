# v0.3.0 Design: Custom Keychain + Legacy ACL

> Status: **Implemented** (2026-03-07) — Pure FFI approach

## Problem Statement

LKR stores secrets in macOS login.keychain. Any process running as the same user can
read them silently via `security find-generic-password`. This is the last remaining
"Exposed" vector in the attack surface table.

## Spike Results

We tested 4 approaches to close this vector. Only one combination worked.

### What failed

| Approach | Where | Why it failed |
|----------|-------|--------------|
| Modern ACL (`SecAccessControlCreateWithFlags`) | login.keychain | `errSecMissingEntitlement (-34018)` — requires Apple Developer ID |
| Legacy ACL (`-T` flag) | login.keychain | macOS 10.12+ partition IDs (`apple-tool:`) override trusted app list |
| `set-generic-password-partition-list` | Custom Keychain | Silently no-ops — Custom Keychains use CSSM format, no partition ID support |

### What worked: Custom Keychain + Legacy ACL

Custom Keychains (created via `security create-keychain`) use the legacy CSSM format,
which does **not** have partition IDs. Without partition IDs, Legacy ACL trusted
application lists are enforced as designed.

| Test | Result |
|------|--------|
| Custom KC, default `-T` (security auto-trusted) | `security` reads silently |
| Custom KC, `-T ""` (no trusted apps) | **Blocked** — dialog → exit 128 |
| Custom KC, `-T /path/to/lkr` (lkr-only) | **Blocked** — dialog → exit 128 |
| Custom KC, `-T /path/to/lkr -T /usr/bin/security` | `security` reads silently (control) |
| Binary replaced at same path (cdhash changed) | ACL status `(OK)` → `(status -2147415734)` |

**Key insight**: `-T /path/to/binary` automatically sets a `cdhash`-based requirement:

```
applications (1):
    0: /path/to/lkr (OK)
        requirement: cdhash H"5cbb7a1c4e87b7eff92f1119f4817c56c91edd43"
```

No manual `codesign` or partition list configuration needed — macOS extracts the cdhash
from the binary at item creation time.

## Architecture

### Defense Layers

```
Attack: security find-generic-password -s "com.llm-key-ring" -a "openai:prod" -w

Layer 1 — Isolation (search list)
  lkr.keychain-db is NOT in the default search list
  → "The specified item could not be found in the keychain" (exit 44)

Attack: security find-generic-password ... -w ~/Library/Keychains/lkr.keychain-db

Layer 2 — Authorization (Legacy ACL / cdhash)
  Only lkr binary (matching cdhash) is in the trusted app list
  → Dialog prompt → non-interactive: exit 128

Attack: Replace lkr binary at same path, then access

Layer 3 — Binary integrity (cdhash mismatch)
  ACL requirement stores original cdhash
  → Replaced binary has different cdhash → access denied
```

### Storage Model

```
~/Library/Keychains/lkr.keychain-db    ← NOT in search list
├── com.llm-key-ring / openai:prod     ← ACL: -T /path/to/lkr
├── com.llm-key-ring / anthropic:dev   ← ACL: -T /path/to/lkr
└── (password-protected, lockable)
```

### New Commands

| Command | Purpose | Version |
|---------|---------|---------|
| `lkr init` | Create `lkr.keychain-db`, set password, set lock-on-sleep | v0.3.0 |
| `lkr migrate` | Move items from login.keychain → custom keychain (with ACL) | v0.3.0 |
| `lkr harden` | Re-register ACL after binary update (cdhash refresh) | v0.3.0 |
| `lkr lock` | Explicitly lock `lkr.keychain-db` | v0.3.0 |
| `lkr doctor` | Diagnose: search list pollution, cdhash mismatch, signing status | v0.3.1 |
| `lkr config lock-timeout <min>` | Set optional inactivity timeout (minutes) | v0.3.1 |

### cdhash Lifecycle

```
cargo install lkr          → binary gets ad-hoc signature (or unsigned)
lkr init                   → creates keychain, checks signing status
lkr set openai:prod        → stores item with -T /path/to/lkr (captures cdhash)
                             ↓
cargo install lkr --force   → NEW binary, NEW cdhash
lkr get openai:prod        → dialog/failure (cdhash mismatch)
lkr harden                 → re-registers current binary cdhash on all items
lkr get openai:prod        → works again
```

## Trade-offs

### Accepted

| Trade-off | Why it's acceptable |
|-----------|-------------------|
| `lkr harden` needed after binary update | Explicit > implicit. User knows ACL was refreshed |
| Keychain password prompt on first use per session | Same UX as aws-vault. Keychain stays unlocked until sleep/timeout |
| Keychain unlocked for extended periods | Layer 2 (ACL/cdhash) enforces access control independently of lock state. Timeout available as opt-in |
| `codesign -s -` may be needed for unsigned builds | `lkr init` can detect and guide. Most `cargo install` binaries are already ad-hoc signed |

### Rejected

| Alternative | Why rejected |
|-------------|-------------|
| exec-immediate-lock (lock keychain right after `exec` reads keys) | Security theater — keys are already in child's env vars; Layer 2 is lock-independent; UX cost with no security benefit (I4) |
| Default inactivity timeout (e.g., 5 min) | Layer 2 is lock-independent, so timeout provides no current protection. Available as opt-in for users who want it |
| partition list (`set-generic-password-partition-list`) | No-ops on Custom Keychains (CSSM format) |
| Modern ACL (`SecAccessControlCreateWithFlags`) | Requires Apple Developer ID ($99/year) |
| Touch ID / biometric | Same Apple Developer ID requirement |
| Auto-`harden` on every access | Modifying ACL requires keychain password; too intrusive |

### Remaining Limitations

| Scenario | Status |
|----------|--------|
| Attacker knows keychain path + password | Not protected (same as aws-vault) |
| Attacker runs lkr binary directly (`lkr exec`) | Not protected (same-user code execution) |
| IDE with pty calls lkr | TTY guard still applies (defense-in-depth) |
| `security dump-keychain -d` with keychain password | Reads all items (requires password) |

## Prior Art

| Tool | Approach | Years in production |
|------|----------|-------------------|
| [aws-vault](https://github.com/99designs/aws-vault) | Custom Keychain (isolation only, no ACL) | 5+ years |
| LKR v0.3.0 | Custom Keychain + Legacy ACL (isolation + cdhash authorization) | — |

LKR goes beyond aws-vault by adding the cdhash authorization layer.

## Implementation Scope

### v0.3.0 — Custom Keychain core (breaking change)

3-layer defense が動く最小セット。Pure FFI で storage layer を全面差し替え。

- [x] `lkr init` — Custom Keychain creation + password + lock-on-sleep + auto-lock timeout
- [x] Item storage with Legacy ACL via Pure FFI (`SecKeychainItemCreateFromContent` + `SecAccessCreate`)
- [x] `lkr get` / `lkr exec` — Custom Keychain read + shared unlock lifecycle (3-retry password prompt)
- [x] `lkr migrate` — login.keychain → custom keychain (copy-first with verify readback)
- [x] `lkr harden` — cdhash re-registration for all items (get → set --force)
- [x] `lkr lock` — explicit keychain lock
- [x] SECURITY.md / design-v030.md update
- [x] Tier 1 unit tests + Tier 2 contract tests (temp keychain in /tmp/)

### v0.3.1 — Operational quality (non-breaking)

運用品質。壊れてないか確認 + 配布 + 設定。

- [ ] `lkr doctor` — diagnostic checks (see Doctor Checks below)
- [ ] `lkr config lock-timeout <minutes>` — optional inactivity timeout
- [ ] Shell completions (bash/zsh/fish)
- [ ] Homebrew tap (`brew install yottayoshida/tap/lkr`)

## Implementation Approach

### v0.3.0: Pure FFI

All keychain operations use direct FFI calls to Security.framework. No CLI wrapping.

| Operation | FFI Function |
|-----------|-------------|
| Create keychain | `security_framework::CreateOptions::create()` |
| Apply settings | `SecKeychain::set_settings()` (lock-on-sleep + auto-lock 5min) |
| Add item with ACL | `SecKeychainItemCreateFromContent` + `SecAccessCreate` + `SecTrustedApplicationCreateFromPath` |
| Read item | `SecKeychainFindGenericPassword` (scoped to custom keychain) |
| Delete item | `SecKeychainFindGenericPassword` → `SecKeychainItemDelete` |
| List items | `SecItemCopyMatching` + `kSecMatchSearchList` |
| Lock | `SecKeychainLock` |
| Unlock | `SecKeychain::unlock()` |
| Search list isolation | `SecKeychainCopySearchList` → filter → `SecKeychainSetSearchList` |
| ACL refresh (harden) | `get` → `set --force` (re-creates item with new `SecAccessRef`) |

**Why Pure FFI (not CLI wrap)**:
- PoC-2 revealed `security add-generic-password -w` cannot accept values via stdin (it interprets
  `-w` flag differently when piped). This makes CLI wrapping unreliable for `set` operations
- `SecKeychainItemCreateFromContent` is the only way to atomically create an item WITH an initial
  `SecAccessRef`, avoiding the `SecKeychainItemSetAccess` GUI dialog problem (-128 / user canceled)
- Direct control over `SecAccessRef` lifecycle (build → attach → release) without CLI escaping issues
- `kSecMatchSearchList` scopes `SecItemCopyMatching` to the custom keychain without modifying the
  system search list (required for `list` command)

**Key FFI modules**:
- `lkr-core/src/custom_keychain.rs` — Keychain lifecycle (create/open/unlock/lock/delete/search list)
- `lkr-core/src/acl.rs` — Legacy ACL builder (`build_access()` / `is_acl_blocked()`)
- `lkr-core/src/keymanager.rs::keychain_raw` — Item CRUD via `SecKeychainItemCreateFromContent` etc.

**ACL best-effort policy**: If `build_access()` fails (e.g., binary path unresolvable), the item
is stored WITHOUT ACL rather than failing entirely. The user can fix later with `lkr harden`.

**Invariant**: `/usr/bin/security` must NEVER be in any item's trusted app list.
If it is, Layer 2 (Authorization) is completely bypassed.

### Keychain Session Lifecycle

Keychain password is entered once per session (3-retry prompt via `rpassword`).
The keychain stays unlocked until macOS sleep, auto-lock timeout (5 min), or manual lock.

```
lkr get / lkr exec / lkr set (shared unlock flow):
  ├─ Is lkr.keychain-db unlocked?
  │   ├─ Yes → proceed with operation
  │   └─ No  → prompt for keychain password (up to 3 retries)
  │           → custom_keychain::unlock(&mut kc, password)
  │           → proceed with operation
  │
  │  (keychain remains unlocked until sleep/timeout/manual lock)

lkr lock:
  └─ custom_keychain::lock(&kc) via SecKeychainLock FFI

lkr init:
  └─ custom_keychain::create(password)
     → CreateOptions::create() + KeychainSettings (lock-on-sleep + 300s auto-lock)
     → ensure_not_in_search_list() (I1 enforcement)

lkr config lock-timeout <minutes>:  (v0.3.1)
  └─ SecKeychain::set_settings() with custom interval
```

**Lock policy**: All commands (`get`, `set`, `exec`) share the same unlock flow.
No command locks the keychain after completion. This is intentional: **Layer 2
(ACL/cdhash) enforces access control independently of lock state** — an unlocked
keychain does not grant bypass of the trusted application list (verified in spike V4b).

Lock state is relevant only as a gate before the **trusted binary itself** accesses
items. Since same-user code execution is out of scope (I4), the lock serves primarily
as a physical-access defense (sleep lock) and user-preference option (timeout).

**Why `exec` does not lock after spawn**: Keys are already injected into the child
process's environment variables. Locking the keychain after this point provides no
incremental protection — the secrets are outside the vault. Locking would only
impose re-entry cost on the next `lkr` invocation, which is UX cost with no
security benefit (see Security Review 2026-03-04).

### Doctor Checks (v0.3.x)

`lkr doctor` performs the following diagnostic checks:

| Check | What it detects | Severity |
|-------|----------------|----------|
| Search list pollution | `lkr.keychain-db` found in `security list-keychains` | **Critical** — Layer 1 bypassed |
| `security` in trusted apps | `/usr/bin/security` in any item's ACL | **Critical** — Layer 2 bypassed |
| cdhash mismatch | ACL status ≠ `(OK)` for lkr binary | **Warning** — run `lkr harden` |
| Binary signing status | lkr binary is unsigned (no ad-hoc signature) | **Info** — ACL may not set cdhash |
| Keychain file exists | `lkr.keychain-db` not found at expected path | **Error** — run `lkr init` |
| Keychain locked | Keychain is locked when doctor runs | **Info** — normal state |

## References

- [macOS Keychain partition IDs (Stack Overflow)](https://stackoverflow.com/questions/39868578/)
- [OBTS v5: Keychain ACL internals (Chris Thomas)](https://objectivebythesea.org/v5/talks/OBTS_v5_cThomas.pdf)
- [Apple TN3126: Inside Code Signing — Hashes](https://developer.apple.com/documentation/technotes/tn3126-inside-code-signing-hashes)
- [aws-vault Keychain backend](https://github.com/99designs/aws-vault)
