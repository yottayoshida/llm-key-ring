# Legacy ACL + Custom Keychain スパイク検証レポート

> 2026-03-04 実機検証結果。GPT-5.3 Pro の提案に対するアンサー。

## 検証サマリー

| ID | 検証内容 | 対象 | 結果 |
|----|---------|------|------|
| V1 | Legacy ACL (`-T`) on login.keychain | `security` CLI | **FAIL** — partition ID bypass |
| V2 | Rust FFI spike | — | **SKIP** (V1 FAIL) |
| V3 | Custom Keychain isolation | `security` CLI | **PASS** |
| V4a | `set-generic-password-partition-list` on Custom Keychain | `security` CLI | **FAIL** — silent no-op |
| V4b | Legacy ACL (`-T`) on Custom Keychain | `security` CLI | **PASS** |

**最終結論: Custom Keychain + Legacy ACL（隔離 + cdhash認可）が v0.3.0 の採用アーキテクチャ。**

---

## GPT提案の検証結果

### Pattern A（Custom Keychain隔離）→ 採用。提案通り

V3で全テストPASS。search list非登録でデフォルト検索を完全回避。

### Pattern B（cdhash partition list）→ 不採用。Custom Keychainでは動かない

`set-generic-password-partition-list -S "cdhash:..."` はCustom Keychainに対してsilent no-op。

```
# 設定前後でACLダンプが完全に同一
entry 0:
    applications (1):
        0: /usr/bin/security (OK)
            requirement: identifier "com.apple.security" and anchor apple
```

**原因**: Custom Keychainは CSSM (legacy) 形式。partition ID自体が存在しない。`set-generic-password-partition-list` はlogin.keychain (Data Protection Keychain) 専用の機能。

### Pattern C（A + B合体）→ 形を変えて採用

GPTの想定した「隔離 + partition list認可」ではなく、**「隔離 + Legacy ACL認可」** として成立した。

### Pattern D（Modern ACL / Touch ID）→ 不採用。提案通り

---

## 核心の発見: Legacy ACLはCustom Keychainで生きている

### なぜV1で効かなかったのにV4で効くのか

| | login.keychain | Custom Keychain |
|--|---------------|----------------|
| 形式 | Data Protection Keychain | CSSM (legacy) |
| partition ID | **あり** (`apple-tool:`, `apple:`) | **なし** |
| Legacy ACL trusted app list | partition IDに上書きされる | **そのまま機能する** |
| `-T ""` の効果 | 無効（`security`が素通り） | **有効**（ダイアログ → exit 128） |
| `-T /path/to/lkr` の効果 | 無効 | **有効**（lkrのみ許可、`security`はブロック） |

### ACLダンプの実物（`-T /path/to/lkr` 設定時）

```
entry 1:
    authorizations (6): decrypt derive export_clear export_wrapped mac sign
    applications (1):
        0: /tmp/lkr-spike-signed (OK)
            requirement: cdhash H"5cbb7a1c4e87b7eff92f1119f4817c56c91edd43"
```

**`-T` を指定するだけで macOS が自動的に cdhash を requirement に設定する。** GPTが提案した「ad-hoc署名 → cdhash取得 → partition list手動設定」のフロー は不要だった。

### バイナリ差し替え耐性

同じパスのバイナリを差し替えた（cdhash変化）後:

```
0: /tmp/lkr-spike-signed (status -2147415734)   ← (OK) から変化
    requirement: cdhash H"5cbb7a1c4e87b7eff92f1119f4817c56c91edd43"
```

cdhash不一致が自動検出される。パス一致だけでは突破不可。

---

## 実測データ（全テスト結果）

### V1: Legacy ACL on login.keychain

```bash
security add-generic-password -s "com.lkr-spike-v1" -a "test" -w "secret" -T ""
security find-generic-password -s "com.lkr-spike-v1" -a "test" -w
# → "secret" (exit 0) ← 無音で平文が出る。FAIL
```

### V3: Custom Keychain isolation

| Test | Result |
|------|--------|
| Default search (no keychain arg) | `errSecItemNotFound` (exit 44) **PASS** |
| Explicit path | Found (exit 0) **PASS** |
| Lock → read | exit 128 **PASS** |
| Unlock → read | Found (exit 0) **PASS** |
| Add to search list → default search | Found **PASS** (confirms mechanism) |
| Remove from search list → default search | Not found **PASS** |

### V4a: partition list on Custom Keychain

```bash
security set-generic-password-partition-list \
  -S "cdhash:0000000000000000000000000000000000000000" \
  -k "keychain-pw" custom.keychain-db
# → exit 0 (silent success)

security find-generic-password ... -w custom.keychain-db
# → "secret" (exit 0) ← まだ読める。partition listが効いていない。FAIL
```

ACLダンプ: 設定前後で完全同一。no-op確定。

### V4b: Legacy ACL (`-T`) on Custom Keychain

| ACL Setting | `security find-generic-password` | Exit Code |
|-------------|--------------------------------|-----------|
| Default (no `-T`) | Silent read | 0 |
| `-T ""` | **Dialog → denied** | **128** |
| `-T /path/to/lkr` | **Dialog → denied** | **128** |
| `-T /path/to/lkr -T /usr/bin/security` | Silent read | 0 |

---

## v0.3.0 アーキテクチャ（確定）

```
Layer 1 — Isolation
  Custom Keychain (not in search list)
  → security find-generic-password のデフォルト検索から消える

Layer 2 — Authorization
  Legacy ACL (-T /path/to/lkr)
  → cdhash-based requirement が自動設定
  → security find-generic-password はパス指定してもブロック

Layer 3 — Binary Integrity
  cdhash mismatch detection
  → バイナリ差し替えで ACL ステータスが (OK) → (error) に変化
```

### GPT提案との差分

| GPTの提案 | 実際の採用 | 理由 |
|----------|----------|------|
| ad-hoc署名 (`codesign -s -`) 必須 | 不要（`-T` が自動でcdhash取得） | macOSが`-T`指定時にバイナリのcdhashを自動抽出する |
| `set-generic-password-partition-list` で認可 | `-T` フラグで認可 | partition listはCustom Keychainで非対応 |
| Step 3: 自己署名を必須前提 | 不要 | Legacy ACLはコード署名を前提としない |
| Step 4: cdhash更新の自動マイグレーション | `lkr harden` コマンド | ここはGPTの指摘通り。ビルド更新でcdhash変化 → 再登録必要 |

### 残る設計課題

| 課題 | 対策案 |
|------|--------|
| cdhashがビルドごとに変わる | `lkr harden` で全アイテムのACL再登録 |
| Keychain作成時のパスワード管理 | `lkr init` でユーザーに設定させる |
| Rust FFI実装 | `SecAccessCreate` + `SecTrustedApplicationCreateFromPath` (Legacy API) |

---

## GPT提案の評価

| 観点 | 評価 |
|------|------|
| 「隔離 vs 認可」の2軸整理 | **秀逸** — この切り口がなければV4に到達できなかった |
| partition list (cdhash) への着目 | **方向は正しいが手段が違った** — Custom KeychainではなくLogin Keychain向けの仕組み |
| ad-hoc署名の必要性 | **不要だった** — Legacy ACLの`-T`はコード署名を前提としない |
| cdhash更新問題の指摘 | **正確** — `lkr harden` の必要性はGPTの指摘通り |
| Pattern C (A+B合体) の発想 | **正しい** — 形は変わったが「隔離 + 認可」の合体が最終解になった |
