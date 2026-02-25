# 実装プラン: LLM Key Ring

## 概要

macOS Keychainを活用したLLM APIキーマネージャー。APIキーを暗号化保存し、CLI + Tauriメニューバーアプリから操作可能。`.env` / `.mcp.json` テンプレート生成、OpenAI/Anthropicの使用量トラッキングを統合した、個人開発者向けローカルファーストツール。

## 非機能要件（合意済み）

| 項目 | 要件 | 優先度 |
|------|------|--------|
| 性能 | Keychain操作は数ms、Usage API呼び出しは数秒以内 | 低 |
| セキュリティ | APIキーが平文でファイルに残らない。クリップボード30秒自動クリア。生成ファイルは0600 | 高 |
| 可用性 | オフラインでもキー管理は動作。Usage取得はオンライン必須 | 中 |
| 保守性 | CLI/Tauriでコアロジック共有。OSSコントリビュートしやすい構造 | 高 |
| コスト | 個人OSSプロジェクト。無料で完結 | 高 |

## 技術選定

| 技術/ライブラリ | 選定理由 | 代替案 |
|---------------|---------|--------|
| **Rust** | Tauri親和性、ネイティブ性能、シングルバイナリ配布 | TypeScript (Node.js), Go |
| **keyring crate** (3.6.3) | クロスプラットフォーム抽象化。`apple-native`フィーチャーでmacOS Keychain対応。将来の移植性あり | security-framework (macOS専用、低レベル) |
| **clap v4** | Rust CLI のデファクト。derive macro で型安全なCLI定義 | argh, structopt |
| **Tauri v2** | メニューバーアプリ。`tray-icon`フィーチャーでsystem tray対応。Rust backend + Web frontend | Electron (重い), SwiftUI (Rust共有困難) |
| **reqwest** | OpenAI/Anthropic API呼び出し用HTTPクライアント | ureq (同期のみ) |
| **serde + serde_json** | JSON パース（Usage API レスポンス、`.mcp.json` テンプレート） | — |
| **独自テンプレートエンジン** | `.env.example` 形式をそのまま入力。`.mcp.json` は `{{lkr:keyname}}` 記法。軽量で外部依存なし | tera, handlebars (過剰) |
| **MIT OR Apache 2.0** | Rustエコシステムの慣習。keyring/security-frameworkも同方式 | MIT単独 |

## 設計方針

### アーキテクチャ: Cargo Workspace モノレポ

```
llm-key-ring/
├── Cargo.toml              # [workspace] members = ["crates/*"]
├── crates/
│   ├── lkr-core/           # lib crate (KeyManager, TemplateGen, UsageTracker)
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── keymanager.rs    # Keychain CRUD (trait抽象化)
│   │       ├── template.rs      # テンプレート生成
│   │       ├── usage.rs         # Usage Tracking (OpenAI/Anthropic)
│   │       └── config.rs        # 設定管理
│   ├── lkr-cli/            # bin crate (clap CLI)
│   │   ├── Cargo.toml
│   │   └── src/main.rs
│   └── lkr-app/            # Tauri app
│       ├── Cargo.toml
│       ├── tauri.conf.json
│       └── src/
├── templates/               # サンプルテンプレート
│   ├── env.example
│   └── mcp.json.example
├── LICENSE-MIT
├── LICENSE-APACHE
└── README.md
```

### コアロジック共有

- `lkr-core` が全ビジネスロジックを持つ
- `lkr-cli` と `lkr-app` は `lkr-core` に依存するだけの薄いラッパー
- Keychainアクセスは `KeyStore` trait で抽象化 → テスト時にモック差し替え可能

```rust
// lkr-core の設計イメージ
pub trait KeyStore {
    fn set(&self, name: &str, value: &str) -> Result<()>;
    fn get(&self, name: &str) -> Result<String>;
    fn delete(&self, name: &str) -> Result<()>;
    fn list(&self) -> Result<Vec<KeyEntry>>;
}

// 本番: macOS Keychain実装
pub struct KeychainStore { service: String }

// テスト: インメモリ実装
pub struct MockStore { keys: HashMap<String, String> }
```

### Keychain命名規則（CLI/Tauri統一 — 最重要）

| 項目 | 値 | 例 |
|------|-----|-----|
| service | `com.llm-key-ring` | 固定値。全キーで共通 |
| account | `{provider}:{name}` | `openai:prod`, `anthropic:main` |

> **Codexレビュー反映**: 区切り文字を `/` → `:` に変更。`/` はファイルパスと混同しやすく、将来の正規化・移行時に問題が出る可能性あり。`:` はURN慣習に沿い安全。
> account名のバリデーション: `[a-z0-9][a-z0-9-]*:[a-z0-9][a-z0-9-]*` に制限。

この命名規則は絶対に変えない。CLIとTauriが同一のservice/accountを使うことで、どちらからもキーにアクセス可能。

### CLIコマンド体系（UX分析準拠、コアコマンド5個）

```
lkr set <name> [--provider openai]    # キー登録（値はプロンプト入力）
lkr get <name>                         # キー取得（クリップボード + マスク表示）
lkr list                               # 一覧表示
lkr rm <name>                          # 削除（確認プロンプトあり）
lkr gen <template> [-o output]         # テンプレートから生成

lkr usage [provider]                   # 使用量表示（オプション機能）
lkr import <file>                      # .envからインポート
lkr doctor                             # 設定診断
lkr config <key> <value>               # 設定変更
```

### テンプレート生成の設計

**`.env.example` 形式（学習コスト=0）:**

既存の `.env.example` をそのまま入力にする。変数名からプロバイダーを自動推定。

```bash
$ lkr gen .env.example -o .env
  Resolved from Keychain:
    OPENAI_API_KEY       <- openai:prod
    ANTHROPIC_API_KEY    <- anthropic:main
  Kept as-is (no matching key):
    DATABASE_URL
```

**`.mcp.json` 形式（明示的プレースホルダー）:**

JSON内は `{{lkr:keyname}}` 記法で明示指定。

```json
{
  "mcpServers": {
    "codex": {
      "env": {
        "OPENAI_API_KEY": "{{lkr:openai:prod}}"
      }
    }
  }
}
```

### Usage Tracking の制約と対応

| プロバイダー | API | 認証要件 | 個人アカウント |
|-------------|-----|---------|--------------|
| OpenAI | `/v1/organization/usage` | **Admin API Key必須** | 利用可（Admin Key発行可能） |
| Anthropic | `/v1/organizations/usage_report` | **Admin API Key必須** | **利用不可**（組織設定必要） |

**対応方針:**
- Usage Trackingは**オプション機能**として位置づけ
- Admin Key未設定時は「Usage未対応」と明示表示
- 将来的にレスポンスヘッダー（`x-ratelimit-*`）からの推定も検討
- READMEにAdmin Key要件を明記

### キーの種別管理（Codexレビュー反映）

> **Codexレビュー反映**: Admin API Key（Usage Tracking用）は通常の推論用キーより権限が強い。同一フローで扱うと被害半径が大きいため、種別を分離する。

| 種別 | 用途 | デフォルト表示 | テンプレートエクスポート |
|------|------|--------------|----------------------|
| `runtime` | 推論API呼び出し用（通常のAPIキー） | `lkr list` に表示 | 可能 |
| `admin` | Usage Tracking用（Admin API Key） | `lkr list` から除外（`--all`で表示） | 禁止 |

- `lkr set openai:prod` → デフォルトで `kind=runtime`
- `lkr set openai:admin --kind admin` → Admin Key として登録
- `lkr gen` はruntime キーのみ対象。admin キーはテンプレート生成に使えない

### セキュリティ設計

| 脅威 | 対策 |
|------|------|
| ファイル上の平文キー | Keychain暗号化保存。`.env`生成時はファイルパーミッション`0600` |
| クリップボード残留 | 30秒後に自動クリア。設定で変更可能 |
| シェル履歴への残留 | `lkr set` はキー値を引数に取らない。プロンプト入力（stdin）を使用 |
| ターミナル表示 | `lkr get` はデフォルトでマスク表示 + クリップボードコピー。`--show`で生値表示 |
| ログ出力への混入 | エラーメッセージにキー値を含めない設計原則（監査ログは操作イベントのみ） |
| `.gitignore` 漏れ | `lkr gen` 実行時に出力ファイルが`.gitignore`に含まれているか自動チェック |
| Admin Key露出 | `kind=admin` は `list`/`gen` のデフォルト対象外。マスキング強制 |
| Tauriフロント側侵害 | Tauri capabilities を最小権限で設定。remote API access は原則無効 |

### メニューバーアプリ設計

```
[🔑] ← メニューバーアイコン（状態: 通常/警告/超過）
  │
  ├── [検索フィールド]
  │
  ├── 最近使用 ─── 直近3件
  │   ├── openai:prod      [Copy]
  │   ├── anthropic:main   [Copy]
  │   └── gemini:dev       [Copy]
  │
  ├── OpenAI ──── プロバイダー別グループ
  │   ├── openai:prod      [Copy]
  │   └── openai:dev       [Copy]
  │
  ├── Usage This Month
  │   OpenAI    ████████░░  $38 / $50
  │   Anthropic ██░░░░░░░░  $8  / $50
  │
  ├── Settings...
  └── Quit
```

## 実装ステップ（概要レベル）

| Phase | 内容 | 成果物 |
|-------|------|--------|
| 1 | Cargo Workspace構築 + `lkr-core` KeyManager（set/get/rm/list）+ `lkr-cli` 基本コマンド + **Tauri最小スケルトン** | CLIでKeychain CRUD動作 + Tauriビルド通る |
| 2 | TemplateGenerator（`.env.example` → `.env` / `.mcp.json` 生成）+ `lkr import` | テンプレート生成動作 |
| 3 | UsageTracker（OpenAI/Anthropic API統合）+ `lkr usage` + キー種別管理（admin/runtime） | 使用量表示動作 |
| 4 | Tauriメニューバーアプリ本格実装（キー一覧、Quick Copy、使用量表示） | メニューバーアプリ動作 |
| 5 | Homebrew tap + GitHub Actions CI/CD + Universal Binary + SHA256検証 | `brew install` で配布可能 |

> **Codexレビュー反映**: Phase 1でTauri最小スケルトン（set/getだけのIPC）を並走させ、CLI↔Tauriの境界面を早期に固める。Phase 4まで寝かせるとIPC/権限モデル差分が後半で爆発するリスクを回避。

※詳細タスク分解は /develop Phase 2 で実施

## ファイル変更予定

| ファイル/ディレクトリ | 変更内容 |
|---------------------|---------|
| `llm-key-ring/` (新規リポジトリ) | プロジェクト全体 |
| `Cargo.toml` | Workspace定義 |
| `crates/lkr-core/` | コアライブラリ（KeyManager, TemplateGen, UsageTracker） |
| `crates/lkr-cli/` | CLIバイナリ（clap） |
| `crates/lkr-app/` | Tauriメニューバーアプリ |
| `templates/` | サンプルテンプレート |
| `.github/workflows/` | CI/CD（テスト + ビルド + Homebrew更新） |

## リスクと対策

| リスク | 影響度 | 対策 |
|--------|--------|------|
| Usage APIがAdmin Key必須（OpenAI/Anthropic両方） | 高 | オプション機能として位置づけ。READMEに制約明記。Admin Key未設定時の体験を丁寧に設計 |
| Anthropic Usage APIが個人アカウント非対応 | 高 | 組織設定必要と明記。対応不可なら「ダッシュボードURL表示」にフォールバック |
| Keychain service/account 命名不一致（CLI vs Tauri） | 高 | 命名規則を`lkr-core`で一元定義。統合テストで保証 |
| macOS Keychain初回アクセス許可ダイアログ | 中 | READMEとCLI初回起動ガイドで事前説明 |
| Tauri v2 system tray のmacOSバグ | 中 | Tauriバージョンをpin。Phase 4で対応（CLIが先に安定） |
| Rust学習コスト | 中 | Phase 1のKeyManager（最小構成）で学習。段階的に複雑度を上げる |
| OpenAI/Anthropic API仕様変更 | 中 | APIクライアントをtrait抽象化。プロバイダーごとに実装分離 |
| Apple Developer署名なし（Gatekeeper警告） | 低 | Homebrew tap経由なら署名不要。直接DLの場合は手順を記載 |
| Tauri capabilities過剰付与（Codex指摘） | 中 | 最小権限で開始。必要コマンドだけallow。remote API accessは原則無効 |

## 成功指標

- [ ] `lkr set openai:prod` → `lkr get openai:prod` でKeychain経由のCRUDが動作する
- [ ] `lkr gen .env.example -o .env` でKeychainからキーを解決した`.env`が生成される
- [ ] `lkr usage` でOpenAI/Anthropicの使用量が表示される（Admin Key設定時）
- [ ] Tauriメニューバーアプリでキー一覧・Quick Copyが動作する
- [ ] 初回セットアップが3分以内で完了する
- [ ] キー取得がCLIで3秒以内、メニューバーで2秒以内
- [ ] `brew install yottayoshida/tap/lkr` でインストール可能
- [ ] APIキーの平文露出が明示的オプション使用時のみに限定される

## QA Shift-left結果（/develop への申し送り）

### 重点検証ポイント

- [ ] CLI `lkr set` で登録したキーをTauriが正しく読み取れるか（service/account一致）
- [ ] Keychainロック状態（スリープ復帰直後等）での各コマンドのエラー挙動
- [ ] `.env`/`.mcp.json`生成後のファイルパーミッションが`0600`であること
- [ ] `lkr get`出力がシェル履歴・プロセスリスト経由で露出しないこと
- [ ] Usage API障害・タイムアウト時にハングせずエラー表示されること
- [ ] テンプレート構文エラー時に部分生成ファイルが残らないこと（アトミック生成）

### 想定エッジケース

- キー0件状態での`lkr list`（空リスト表示）
- 空文字キーの`lkr set`（バリデーションで拒否）
- 同一キーの二重登録（上書き確認プロンプト）
- 未登録キーの`lkr get`/`lkr rm`（サジェスト付きエラー）
- テンプレート内の未定義プレースホルダー（警告+手動設定促進）
- 出力先ファイルが既に存在する場合（上書き確認）
- ネットワークオフラインでの`lkr usage`（キャッシュ or エラー）

### テスト戦略

- KeychainアクセスはTrait抽象化 → テスト時はMockStore差し替え
- Usage APIはHTTPモック（wiremock等）で外部依存を排除
- セキュリティテストは機能テストとは別立てで網羅的に実施

## UX分析結果

### ユーザーゴール

- 主要ユーザー: 個人LLM開発者（macOS、ターミナル常用、複数LLMプロバイダー利用）
- 達成したいこと: APIキーを安全かつ楽に管理し、プロジェクトごとに素早く切り替える

### 認知科学的考慮

| 法則 | 適用ポイント |
|------|-------------|
| Hick's Law | コアコマンドを5個に絞る（set/get/list/rm/gen） |
| Miller's Law | メニューバー一画面のキー表示は7個以内。グループ折りたたみ |
| Jakob's Law | Unix CLI慣習に合わせる（rm, ls的な短い動詞） |
| Fitts's Law | メニューバーは画面端で到達コスト低。行全体をクリッカブルに |
| 認知負荷 | テンプレートは既存`.env.example`形式（学習コスト=0） |

### CLI UX設計原則

- デフォルトは人間に優しく、`--json`/`--plain`でマシンリーダブル
- エラーは3層構造（何が起きた / なぜ / どうする）+ タイポサジェスト
- `lkr get` 引数なしでインタラクティブ選択（Recognition > Recall）
- `lkr set` はキー値を引数に取らずプロンプト入力（シェル履歴対策）

### 情報アーキテクチャ（メニューバー）

- 最近使用キー（上部3件）→ プロバイダー別グループ → 使用量サマリー → Settings
- アイコン状態: 通常 / 警告（予算80%超） / 超過（予算100%超）

### UX成功指標

- [ ] 初回セットアップが3分以内
- [ ] キー取得がCLI 3秒以内、メニューバー 2秒以内
- [ ] テンプレート生成で新記法の学習不要
- [ ] エラーメッセージだけで自力回復可能

## Codexレビュー結果（Phase 4）

### 良い点
- Workspace 3分割、KeyStore trait抽象化、CLI/GUI分離は保守性が高い
- `lkr set` のプロンプト入力、0600、クリップボード自動クリアは実運用をちゃんと見ている
- OSS公開とデュアルライセンスも、採用障壁を下げる良い判断

### 指摘事項と対応

| # | 重要度 | 指摘 | 対応 |
|---|--------|------|------|
| 1 | High | Admin API Keyとruntime keyの分離が必要 | **採用** — `kind=admin\|runtime` を導入。adminはlist/genのデフォルト対象外 |
| 2 | High | Tauri capabilities を最小権限に | **採用** — 最小権限で開始、remote API access無効 |
| 3 | Medium | keyring一本化だと将来の細かい制御が詰まる可能性 | **対応済み** — KeyStore traitで抽象化済み。将来security-framework実装を追加可能 |
| 4 | Medium | account区切り文字 `/` → `:` に変更推奨 | **採用** — `provider:name` 形式に変更。バリデーション規則も追加 |
| 5 | Medium | Tauri検証を後ろに寄せすぎ | **採用** — Phase 1でTauri最小スケルトン並走に変更 |
| 6 | Low | テンプレートの内部表現一本化 | **採用** — 内部でTemplate ASTに正規化する方針 |

### 追加提案（将来検討）

| 提案 | 採否 | 理由 |
|------|------|------|
| 脅威モデリング1枚をPhase 0で定義 | 将来 | MVPではセキュリティ設計セクションで代替 |
| 監査ログ方針 | 採用 | 操作イベントのみ記録、秘密値は絶対ログしない原則を明記 |
| Homebrew配布時のSHA256検証 | 採用 | Phase 5に含める |
| 受け入れテストに権限ミス設定の失敗系追加 | 採用 | QA申し送りに追加 |
